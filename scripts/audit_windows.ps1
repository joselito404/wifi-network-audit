<#
.SYNOPSIS
    Read-only Wi-Fi and network diagnostic audit script for Windows.

.DESCRIPTION
    Collects strictly sequential baseline metrics (Wi-Fi link, RF congestion,
    USB 2.0/3.0 negotiation via IOCTL, USB Selective Suspend, WLAN AutoConfig
    events 8003/11004, VPN/tunnel detection, idle ICMP latency, uncached DNS
    latency) followed by sequential Download/Upload bufferbloat tests against
    speed.cloudflare.com with parallel ICMP probing ONLY during active load.

    Strictly read-only: makes no changes to Windows settings, registry,
    drivers, or network adapters.

.LICENSE
    MIT License
#>

[CmdletBinding()]
param(
    [ValidateSet('Markdown', 'Json')]
    [string]$Format = 'Markdown',

    [bool]$Anonymize = $true,

    [switch]$SkipLoadTest,

    [ValidateRange(1, 200)]
    [int]$PingCount = 20,

    [string]$OutFile = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# Anonymization Helpers
# ============================================================================

$script:MacMap = @{}
$script:MacCounter = 0
$script:PublicIpMap = @{}
$script:PublicIpCounter = 0
$script:NeighborSsidMap = @{}
$script:NeighborSsidCounter = 0
$script:OwnSsidRaw = $null

$script:PreservedPublicIps = @(
    '1.1.1.1', '1.0.0.1',
    '8.8.8.8', '8.8.4.4',
    '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220'
)

function Test-IsPrivateOrPreservedIp {
    param([string]$IpString)

    if ([string]::IsNullOrWhiteSpace($IpString)) { return $true }
    if ($script:PreservedPublicIps -contains $IpString) { return $true }

    [System.Net.IPAddress]$ipObj = $null
    if (-not [System.Net.IPAddress]::TryParse($IpString, [ref]$ipObj)) {
        return $true
    }

    if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $bytes = $ipObj.GetAddressBytes()
        # 10.0.0.0/8
        if ($bytes[0] -eq 10) { return $true }
        # 172.16.0.0/12
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true }
        # 192.168.0.0/16
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
        # 127.0.0.0/8 (loopback)
        if ($bytes[0] -eq 127) { return $true }
        # 169.254.0.0/16 (link-local)
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $true }
        # 100.64.0.0/10 (CGNAT)
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) { return $true }
        # 0.0.0.0
        if ($bytes[0] -eq 0) { return $true }
        return $false
    }

    # IPv6: preserve loopback (::1), link-local (fe80::/10), unique local (fc00::/7)
    if ($ipObj.IsIPv6LinkLocal -or $ipObj.IsIPv6SiteLocal -or [System.Net.IPAddress]::IsLoopback($ipObj)) {
        return $true
    }
    $v6Bytes = $ipObj.GetAddressBytes()
    if (($v6Bytes[0] -band 0xFE) -eq 0xFC) { return $true }

    return $false
}

function Protect-MacAddress {
    param([string]$Mac)
    if (-not $Anonymize -or [string]::IsNullOrWhiteSpace($Mac)) { return $Mac }
    $norm = $Mac.Trim().ToLowerInvariant() -replace '-', ':'
    if (-not $script:MacMap.ContainsKey($norm)) {
        $script:MacCounter++
        $suffix = '{0:x2}' -f ($script:MacCounter % 256)
        $script:MacMap[$norm] = "xx:xx:xx:xx:xx:$suffix"
    }
    return $script:MacMap[$norm]
}

function Protect-IpAddress {
    param([string]$Ip)
    if (-not $Anonymize -or [string]::IsNullOrWhiteSpace($Ip)) { return $Ip }
    $trimmed = $Ip.Trim()
    if (Test-IsPrivateOrPreservedIp -IpString $trimmed) { return $trimmed }
    if (-not $script:PublicIpMap.ContainsKey($trimmed)) {
        $script:PublicIpCounter++
        $script:PublicIpMap[$trimmed] = ('[PUBLIC_IP_{0:d2}]' -f $script:PublicIpCounter)
    }
    return $script:PublicIpMap[$trimmed]
}

function Protect-Ssid {
    param(
        [string]$Ssid,
        [switch]$IsOwn
    )
    if (-not $Anonymize -or [string]::IsNullOrWhiteSpace($Ssid)) { return $Ssid }
    if ($IsOwn) {
        $script:OwnSsidRaw = $Ssid
        return 'Own_WiFi'
    }
    if (-not $script:NeighborSsidMap.ContainsKey($Ssid)) {
        $script:NeighborSsidCounter++
        $script:NeighborSsidMap[$Ssid] = ('Neighbor_{0:d2}' -f $script:NeighborSsidCounter)
    }
    return $script:NeighborSsidMap[$Ssid]
}

function Protect-FreeText {
    param([string]$Text)
    if (-not $Anonymize -or [string]::IsNullOrWhiteSpace($Text)) { return $Text }

    # Mask MAC addresses
    $result = [regex]::Replace($Text, '(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b', {
        param($m)
        Protect-MacAddress -Mac $m.Value
    })

    # Mask public IPv4 addresses
    $result = [regex]::Replace($result, '\b(?:\d{1,3}\.){3}\d{1,3}\b', {
        param($m)
        Protect-IpAddress -Ip $m.Value
    })

    # Mask own SSID if known
    if (-not [string]::IsNullOrWhiteSpace($script:OwnSsidRaw)) {
        $result = [regex]::Replace($result, [regex]::Escape($script:OwnSsidRaw), 'Own_WiFi', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }

    # Mask any known neighbor SSIDs
    foreach ($kvp in $script:NeighborSsidMap.GetEnumerator()) {
        if (-not [string]::IsNullOrWhiteSpace($kvp.Key)) {
            $result = [regex]::Replace($result, [regex]::Escape($kvp.Key), $kvp.Value, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }

    # Mask WLAN event profile/network/SSID fields (English & Spanish Windows Event Logs)
    $result = [regex]::Replace($result, '(?i)((?:Nombre de perfil|Nombre de red|SSID de red|Network SSID|Profile Name|Network Name|SSID)\s*:\s*)([^\r\n,;]+)', '$1[REDACTED_SSID]')

    return $result
}

# ============================================================================
# Statistics & Math Helpers
# ============================================================================

function Get-Percentile {
    param(
        [double[]]$Values,
        [double]$Percentile = 95
    )
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $sorted = $Values | Sort-Object
    if ($sorted.Count -eq 1) { return [math]::Round($sorted[0], 2) }
    $rank = ($Percentile / 100.0) * ($sorted.Count - 1)
    $low = [math]::Floor($rank)
    $high = [math]::Ceiling($rank)
    if ($low -eq $high) {
        return [math]::Round($sorted[$low], 2)
    }
    $weight = $rank - $low
    $val = $sorted[$low] + ($sorted[$high] - $sorted[$low]) * $weight
    return [math]::Round($val, 2)
}

function ConvertTo-LatencyStats {
    param(
        [double[]]$RttSamples,
        [int]$SentCount
    )
    $received = if ($RttSamples) { $RttSamples.Count } else { 0 }
    $lossPct = if ($SentCount -gt 0) {
        [math]::Round((($SentCount - $received) / [double]$SentCount) * 100.0, 2)
    } else { 100.0 }

    if ($received -eq 0) {
        return [ordered]@{
            sent     = $SentCount
            received = 0
            loss_pct = $lossPct
            min_ms   = $null
            avg_ms   = $null
            p95_ms   = $null
            max_ms   = $null
        }
    }

    $measure = $RttSamples | Measure-Object -Minimum -Maximum -Average
    return [ordered]@{
        sent     = $SentCount
        received = $received
        loss_pct = $lossPct
        min_ms   = [math]::Round($measure.Minimum, 2)
        avg_ms   = [math]::Round($measure.Average, 2)
        p95_ms   = Get-Percentile -Values $RttSamples -Percentile 95
        max_ms   = [math]::Round($measure.Maximum, 2)
    }
}

function Test-IsDfsChannel {
    param([int]$Channel)
    return ($Channel -ge 52 -and $Channel -le 144)
}

function Get-BandFromChannel {
    param(
        [int]$Channel,
        [string]$RawBand = ''
    )
    if ($RawBand -match '6\s*GHz') { return '6 GHz' }
    if ($RawBand -match '5\s*GHz') { return '5 GHz' }
    if ($RawBand -match '2\.4\s*GHz') { return '2.4 GHz' }
    if ($Channel -ge 1 -and $Channel -le 14) { return '2.4 GHz' }
    if ($Channel -ge 32 -and $Channel -le 177) { return '5 GHz' }
    return 'Unknown'
}

# ============================================================================
# (a) Active Wi-Fi Link & Interface Error Statistics
# ============================================================================

function Get-WifiLinkAudit {
    $rawLines = @()
    try {
        $rawLines = & netsh wlan show interfaces 2>&1
    } catch {
        $rawLines = @()
    }

    $ifaceName = $null
    $description = $null
    $state = $null
    $ssid = $null
    $bssid = $null
    $rawBand = $null
    $channel = $null
    $radioType = $null
    $signalPct = $null
    $rxRate = $null
    $txRate = $null

    foreach ($line in $rawLines) {
        $s = [string]$line
        if ($s -match '^\s*(Name|Nombre)\s*:\s*(.+)$' -and -not $ifaceName) {
            $ifaceName = $Matches[2].Trim()
        } elseif ($s -match '^\s*(Description|Descripci[oó]n)\s*:\s*(.+)$' -and -not $description) {
            $description = $Matches[2].Trim()
        } elseif ($s -match '^\s*(State|Estado)\s*:\s*(.+)$' -and -not $state) {
            $state = $Matches[2].Trim()
        } elseif ($s -match '^\s*SSID\s*:\s*(.+)$' -and -not $ssid) {
            $ssid = $Matches[1].Trim()
        } elseif ($s -match '^\s*(AP\s+)?BSSID\s*:\s*([0-9a-fA-F:.-]+)$' -and -not $bssid) {
            $bssid = $Matches[2].Trim()
        } elseif ($s -match '^\s*(Band|Banda)\s*:\s*(.+)$' -and -not $rawBand) {
            $rawBand = $Matches[2].Trim()
        } elseif ($s -match '^\s*(Channel|Canal)\s*:\s*(\d+)' -and $null -eq $channel) {
            $channel = [int]$Matches[2]
        } elseif ($s -match '^\s*(Radio type|Tipo de radio)\s*:\s*(.+)$' -and -not $radioType) {
            $radioType = $Matches[2].Trim()
        } elseif ($s -match '^\s*(Signal|Se[nñ]al)\s*:\s*(\d+)\s*%' -and $null -eq $signalPct) {
            $signalPct = [int]$Matches[2]
        } elseif ($s -match '^\s*(Receive rate|Velocidad de recepci[oó]n).*:\s*([\d.,]+)' -and $null -eq $rxRate) {
            $rxRate = [double]($Matches[2] -replace ',', '.')
        } elseif ($s -match '^\s*(Transmit rate|Velocidad de transmisi[oó]n).*:\s*([\d.,]+)' -and $null -eq $txRate) {
            $txRate = [double]($Matches[2] -replace ',', '.')
        }
    }

    $band = if ($null -ne $channel) {
        Get-BandFromChannel -Channel $channel -RawBand ([string]$rawBand)
    } else {
        if ($rawBand) { $rawBand } else { 'Unknown' }
    }
    $isDfs = if ($null -ne $channel) { Test-IsDfsChannel -Channel $channel } else { $false }

    # Interface error statistics via WMI/CIM + netstat -e
    $rxErr = $null; $rxDisc = $null; $txErr = $null; $txDisc = $null
    try {
        $perfAll = Get-CimInstance -ClassName Win32_PerfRawData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue
        if ($perfAll -and $description) {
            # WMI replaces ()/# with []/_ in Name
            $normDesc = ($description -replace '[()/\\#]', '_')
            $matched = $perfAll | Where-Object {
                $_.Name -eq $description -or $_.Name -eq $normDesc -or $_.Name -like "*$($description.Substring(0, [math]::Min(16, $description.Length)))*"
            } | Select-Object -First 1
            if ($matched) {
                $rxErr = [int64]$matched.PacketsReceivedErrors
                $rxDisc = [int64]$matched.PacketsReceivedDiscarded
                $txErr = [int64]$matched.PacketsOutboundErrors
                $txDisc = [int64]$matched.PacketsOutboundDiscarded
            }
        }
    } catch { }

    $netstatRxErr = $null; $netstatTxErr = $null
    try {
        $nsLines = & netstat -e 2>&1
        foreach ($nl in $nsLines) {
            $ns = [string]$nl
            if ($ns -match '^\s*(Errors|Errores)\s+(\d+)\s+(\d+)') {
                $netstatRxErr = [int64]$Matches[2]
                $netstatTxErr = [int64]$Matches[3]
                break
            }
        }
    } catch { }

    return [ordered]@{
        interface_name     = $ifaceName
        description        = $description
        state              = $state
        raw_ssid           = $ssid
        raw_bssid          = $bssid
        ssid               = Protect-Ssid -Ssid $ssid -IsOwn
        bssid              = Protect-MacAddress -Mac $bssid
        band               = $band
        channel            = $channel
        is_dfs             = $isDfs
        radio_type         = $radioType
        signal_percent     = $signalPct
        receive_rate_mbps  = $rxRate
        transmit_rate_mbps = $txRate
        interface_errors   = [ordered]@{
            packets_received_errors    = $rxErr
            packets_received_discarded = $rxDisc
            packets_outbound_errors    = $txErr
            packets_outbound_discarded = $txDisc
            netstat_rx_errors          = $netstatRxErr
            netstat_tx_errors          = $netstatTxErr
        }
    }
}

# ============================================================================
# (b) RF Congestion Scan
# ============================================================================

function Get-RfScanAudit {
    param([string]$OwnSsid, [string]$OwnBssid)

    $rawLines = @()
    try {
        $rawLines = & netsh wlan show networks mode=bssid 2>&1
    } catch {
        $rawLines = @()
    }

    $networks = New-Object System.Collections.Generic.List[object]
    $currentSsid = ''
    $currentBssid = $null
    $currentSignal = $null
    $currentChannel = $null
    $currentBand = ''

    $flushEntry = {
        if ($currentBssid) {
            $ch = if ($null -ne $currentChannel) { [int]$currentChannel } else { 0 }
            $b = Get-BandFromChannel -Channel $ch -RawBand $currentBand
            $isOwn = ($OwnBssid -and ($currentBssid.ToLowerInvariant() -eq $OwnBssid.ToLowerInvariant()))
            $displaySsid = if ([string]::IsNullOrWhiteSpace($currentSsid)) {
                '<hidden>'
            } elseif ($isOwn -or ($OwnSsid -and $currentSsid -eq $OwnSsid)) {
                Protect-Ssid -Ssid $currentSsid -IsOwn
            } else {
                Protect-Ssid -Ssid $currentSsid
            }

            $networks.Add([ordered]@{
                ssid           = $displaySsid
                bssid          = Protect-MacAddress -Mac $currentBssid
                channel        = if ($ch -gt 0) { $ch } else { $null }
                band           = $b
                is_dfs         = if ($ch -gt 0) { Test-IsDfsChannel -Channel $ch } else { $false }
                signal_percent = $currentSignal
                is_own         = $isOwn
            })
        }
        $script:tmpReset = $true
    }

    foreach ($line in $rawLines) {
        $s = [string]$line
        if ($s -match '^\s*SSID\s+\d+\s*:\s*(.*)$') {
            & $flushEntry
            $currentBssid = $null; $currentSignal = $null; $currentChannel = $null; $currentBand = ''
            $currentSsid = $Matches[1].Trim()
        } elseif ($s -match '^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:.-]+)$') {
            & $flushEntry
            $currentBssid = $Matches[1].Trim()
            $currentSignal = $null; $currentChannel = $null; $currentBand = ''
        } elseif ($s -match '^\s*(Signal|Se[nñ]al)\s*:\s*(\d+)\s*%') {
            $currentSignal = [int]$Matches[2]
        } elseif ($s -match '^\s*(Channel|Canal)\s*:\s*(\d+)') {
            $currentChannel = [int]$Matches[2]
        } elseif ($s -match '^\s*(Band|Banda)\s*:\s*(.+)$') {
            $currentBand = $Matches[2].Trim()
        }
    }
    & $flushEntry

    $ch1 = 0; $ch6 = 0; $ch11 = 0; $ch24Other = 0
    $ch5NonDfs = 0; $ch5Dfs = 0; $ch5Upper = 0

    foreach ($n in $networks) {
        if ($n.is_own) { continue }
        $ch = $n.channel
        if ($null -eq $ch) { continue }
        if ($n.band -eq '2.4 GHz') {
            switch ($ch) {
                1  { $ch1++ }
                6  { $ch6++ }
                11 { $ch11++ }
                default { $ch24Other++ }
            }
        } elseif ($n.band -eq '5 GHz') {
            if ($ch -ge 36 -and $ch -le 48) { $ch5NonDfs++ }
            elseif ($ch -ge 52 -and $ch -le 144) { $ch5Dfs++ }
            elseif ($ch -ge 149) { $ch5Upper++ }
        }
    }

    return [ordered]@{
        total_bssids = $networks.Count
        band_2_4ghz  = [ordered]@{
            ch1   = $ch1
            ch6   = $ch6
            ch11  = $ch11
            other = $ch24Other
            total = ($ch1 + $ch6 + $ch11 + $ch24Other)
        }
        band_5ghz    = [ordered]@{
            non_dfs_36_48  = $ch5NonDfs
            dfs_52_144     = $ch5Dfs
            upper_149_plus = $ch5Upper
            total          = ($ch5NonDfs + $ch5Dfs + $ch5Upper)
        }
        networks     = $networks.ToArray()
    }
}

# ============================================================================
# (c) USB Negotiation Audit (IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX),
#     USB Selective Suspend & WLAN AutoConfig Events (8003 / 11004)
# ============================================================================

$script:UsbIoctlCode = @'
using System;
using System.Runtime.InteropServices;

public static class UsbHubInspector
{
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint IOCTL_USB_GET_NODE_INFORMATION = 0x00220408;
    private const uint IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX = 0x00220448;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct USB_DEVICE_DESCRIPTOR
    {
        public byte bLength;
        public byte bDescriptorType;
        public ushort bcdUSB;
        public byte bDeviceClass;
        public byte bDeviceSubClass;
        public byte bDeviceProtocol;
        public byte bMaxPacketSize0;
        public ushort idVendor;
        public ushort idProduct;
        public ushort bcdDevice;
        public byte iManufacturer;
        public byte iProduct;
        public byte iSerialNumber;
        public byte bNumConfigurations;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct USB_NODE_CONNECTION_INFORMATION_EX
    {
        public uint ConnectionIndex;
        public USB_DEVICE_DESCRIPTOR DeviceDescriptor;
        public byte CurrentConfigurationValue;
        public byte Speed;
        public byte DeviceIsHub;
        public ushort DeviceAddress;
        public uint NumberOfOpenPipeInfos;
        public uint ConnectionStatus;
    }

    public class UsbPortResult
    {
        public bool Found;
        public uint PortIndex;
        public ushort BcdUsb;
        public byte Speed;
        public ushort IdVendor;
        public ushort IdProduct;
        public string Error;
    }

    public static UsbPortResult QueryDeviceOnHub(string hubDevicePath, ushort targetVid, ushort targetPid, int maxPorts)
    {
        var result = new UsbPortResult { Found = false };
        IntPtr handle = CreateFile(hubDevicePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (handle == new IntPtr(-1))
        {
            handle = CreateFile(hubDevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        }
        if (handle == new IntPtr(-1))
        {
            result.Error = "CreateFile failed with Win32 error " + Marshal.GetLastWin32Error();
            return result;
        }

        try
        {
            int structSize = Marshal.SizeOf(typeof(USB_NODE_CONNECTION_INFORMATION_EX));
            int bufSize = structSize + 1024;
            IntPtr buffer = Marshal.AllocHGlobal(bufSize);
            try
            {
                for (uint port = 1; port <= (uint)maxPorts; port++)
                {
                    for (int i = 0; i < bufSize; i++) Marshal.WriteByte(buffer, i, 0);
                    Marshal.WriteInt32(buffer, 0, (int)port);

                    uint bytesReturned;
                    bool ok = DeviceIoControl(
                        handle,
                        IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX,
                        buffer,
                        (uint)bufSize,
                        buffer,
                        (uint)bufSize,
                        out bytesReturned,
                        IntPtr.Zero);

                    if (!ok) continue;

                    var info = (USB_NODE_CONNECTION_INFORMATION_EX)Marshal.PtrToStructure(buffer, typeof(USB_NODE_CONNECTION_INFORMATION_EX));
                    if (info.ConnectionStatus == 1 &&
                        info.DeviceDescriptor.idVendor == targetVid &&
                        info.DeviceDescriptor.idProduct == targetPid)
                    {
                        result.Found = true;
                        result.PortIndex = port;
                        result.BcdUsb = info.DeviceDescriptor.bcdUSB;
                        result.Speed = info.Speed;
                        result.IdVendor = info.DeviceDescriptor.idVendor;
                        result.IdProduct = info.DeviceDescriptor.idProduct;
                        return result;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseHandle(handle);
        }

        return result;
    }
}
'@

function Get-UsbSelectiveSuspendState {
    $acState = 'Unknown'
    $dcState = 'Unknown'
    try {
        $qOut = & powercfg /q SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 2>&1
        foreach ($line in $qOut) {
            $s = [string]$line
            if ($s -match '(Current AC Power Setting Index|Índice de configuración de energía de CA actual).*:\s*0x([0-9a-fA-F]+)') {
                $val = [Convert]::ToInt32($Matches[2], 16)
                $acState = if ($val -eq 1) { 'Enabled' } else { 'Disabled' }
            } elseif ($s -match '(Current DC Power Setting Index|Índice de configuración de energía de CC actual).*:\s*0x([0-9a-fA-F]+)') {
                $val = [Convert]::ToInt32($Matches[2], 16)
                $dcState = if ($val -eq 1) { 'Enabled' } else { 'Disabled' }
            }
        }
    } catch { }
    return [ordered]@{ ac = $acState; dc = $dcState }
}

function Get-WlanRecentEvents {
    $events = New-Object System.Collections.Generic.List[object]
    try {
        $raw = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
            Id      = 8003, 11004
        } -MaxEvents 10 -ErrorAction SilentlyContinue

        foreach ($ev in $raw) {
            $rawMsg = if ($ev.Message) { Protect-FreeText -Text $ev.Message } else { '' }
            $msg = ($rawMsg -replace '\s+', ' ').Trim()
            if ($msg.Length -gt 240) { $msg = $msg.Substring(0, 240) + '...' }
            $events.Add([ordered]@{
                time_created = $ev.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                id           = [int]$ev.Id
                message      = $msg
            })
        }
    } catch { }
    return ,$events.ToArray()
}

function Get-UsbWifiAudit {
    param(
        [string]$InterfaceName,
        [string]$AdapterDescription
    )

    $suspend = Get-UsbSelectiveSuspendState
    $wlanEvents = Get-WlanRecentEvents

    $result = [ordered]@{
        applicable                  = $false
        adapter_name                = $AdapterDescription
        pnp_instance_id             = $null
        root_hub_type               = $null
        bcd_usb                     = $null
        negotiated_speed_code       = $null
        negotiated_speed_label      = $null
        usb2_bottleneck_on_usb3_hub = $false
        selective_suspend_ac        = $suspend.ac
        selective_suspend_dc        = $suspend.dc
        wlan_events_recent          = $wlanEvents
        note                        = $null
    }

    try {
        $netAdapter = $null
        if ($InterfaceName) {
            $netAdapter = Get-NetAdapter -Name $InterfaceName -ErrorAction SilentlyContinue
        }
        if (-not $netAdapter -and $AdapterDescription) {
            $netAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -eq $AdapterDescription } | Select-Object -First 1
        }
        if (-not $netAdapter) {
            $result.note = 'Active Wi-Fi NetAdapter could not be resolved.'
            return $result
        }

        $pnpId = $netAdapter.PnPDeviceID
        $result.pnp_instance_id = $pnpId
        if ($pnpId -notlike 'USB\*') {
            $result.note = 'Wi-Fi adapter is not a USB device (likely PCIe/M.2/integrated).'
            return $result
        }

        $result.applicable = $true

        # Parse VID & PID from PnPDeviceID (e.g. USB\VID_0BDA&PID_B812\...)
        if ($pnpId -notmatch 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
            $result.note = 'Could not extract VID/PID from USB PnPDeviceID.'
            return $result
        }
        $vid = [Convert]::ToUInt16($Matches[1], 16)
        $pidVal = [Convert]::ToUInt16($Matches[2], 16)

        # Walk parent chain to find immediate USB hub and ROOT_HUB type
        $hubIds = New-Object System.Collections.Generic.List[string]
        $currId = $pnpId
        for ($depth = 0; $depth -lt 8; $depth++) {
            $prop = Get-PnpDeviceProperty -InstanceId $currId -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
            if (-not $prop -or [string]::IsNullOrWhiteSpace($prop.Data)) { break }
            $parentId = [string]$prop.Data
            if ($parentId -like 'USB\*') {
                $hubIds.Add($parentId)
                if ($parentId -match 'ROOT_HUB30') { $result.root_hub_type = 'ROOT_HUB30' }
                elseif ($parentId -match 'ROOT_HUB20' -and -not $result.root_hub_type) { $result.root_hub_type = 'ROOT_HUB20' }
            }
            $currId = $parentId
        }

        if (-not ([System.Management.Automation.PSTypeName]'UsbHubInspector').Type) {
            Add-Type -TypeDefinition $script:UsbIoctlCode -Language CSharp -ErrorAction Stop
        }

        $hubGuid = '{f18a0e88-c30c-11d0-8815-00a0c906bed8}'
        $speedMap = @{
            0 = 'LowSpeed (USB 1.0, 1.5 Mbps)'
            1 = 'FullSpeed (USB 1.1, 12 Mbps)'
            2 = 'HighSpeed (USB 2.0, 480 Mbps)'
            3 = 'SuperSpeed (USB 3.0+, 5+ Gbps)'
        }

        $found = $false
        $lastErr = $null
        foreach ($hId in $hubIds) {
            $devPath = '\\?\' + ($hId -replace '\\', '#') + '#' + $hubGuid
            $qRes = [UsbHubInspector]::QueryDeviceOnHub($devPath, $vid, $pidVal, 32)
            if ($qRes.Found) {
                $found = $true
                $bcdHex = ('{0:X4}' -f $qRes.BcdUsb)
                $result.bcd_usb = $bcdHex
                $result.negotiated_speed_code = [int]$qRes.Speed
                $result.negotiated_speed_label = if ($speedMap.ContainsKey([int]$qRes.Speed)) {
                    $speedMap[[int]$qRes.Speed]
                } else {
                    "Unknown ($($qRes.Speed))"
                }
                if ($result.root_hub_type -eq 'ROOT_HUB30' -and ($bcdHex -eq '0200' -or [int]$qRes.Speed -le 2)) {
                    $result.usb2_bottleneck_on_usb3_hub = $true
                }
                break
            } elseif ($qRes.Error) {
                $lastErr = $qRes.Error
            }
        }

        if (-not $found) {
            $result.note = if ($lastErr) {
                "USB hub IOCTL query did not locate device ($lastErr)."
            } else {
                'USB device detected, but hub port enumeration did not match VID/PID.'
            }
        }
    } catch {
        $result.note = "USB audit error: $($_.Exception.Message)"
    }

    return $result
}

# ============================================================================
# (d) VPN/Tunnel Detection & Sequential Idle Latency
# ============================================================================

function Get-VpnTunnelAudit {
    $tunnels = New-Object System.Collections.Generic.List[object]
    $vpnPattern = '(?i)(WARP|Cloudflare|WireGuard|OpenVPN|Wintun|TAP-Windows|Tailscale|ZeroTier|AnyConnect|NordLynx|Mullvad|ProtonVPN|PPP|VPN|Tunnel)'
    try {
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
        foreach ($a in $adapters) {
            if ($a.Name -match $vpnPattern -or $a.InterfaceDescription -match $vpnPattern) {
                $tunnels.Add([ordered]@{
                    name        = $a.Name
                    description = $a.InterfaceDescription
                    status      = [string]$a.Status
                })
            }
        }
    } catch { }

    return [ordered]@{
        detected       = ($tunnels.Count -gt 0)
        active_tunnels = $tunnels.ToArray()
    }
}

function Get-DefaultGatewayIpv4 {
    param([string]$InterfaceName)
    try {
        $routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Sort-Object -Property RouteMetric, InterfaceMetric
        if ($InterfaceName) {
            $ifMatch = $routes | Where-Object { $_.InterfaceAlias -eq $InterfaceName } | Select-Object -First 1
            if ($ifMatch -and $ifMatch.NextHop -ne '0.0.0.0') { return $ifMatch.NextHop }
        }
        $first = $routes | Where-Object { $_.NextHop -ne '0.0.0.0' } | Select-Object -First 1
        if ($first) { return $first.NextHop }
    } catch { }
    return $null
}

function Invoke-SequentialPing {
    param(
        [string]$Target,
        [int]$Count = 20,
        [int]$TimeoutMs = 1500,
        [int]$IntervalMs = 100
    )

    if ([string]::IsNullOrWhiteSpace($Target)) {
        return ConvertTo-LatencyStats -RttSamples @() -SentCount 0
    }

    $samples = New-Object System.Collections.Generic.List[double]
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            try {
                $reply = $ping.Send($Target, $TimeoutMs)
                if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    $samples.Add([double]$reply.RoundtripTime)
                }
            } catch { }
            if ($i -lt ($Count - 1) -and $IntervalMs -gt 0) {
                Start-Sleep -Milliseconds $IntervalMs
            }
        }
    } finally {
        $ping.Dispose()
    }

    return ConvertTo-LatencyStats -RttSamples $samples.ToArray() -SentCount $Count
}

# ============================================================================
# (e) Uncached DNS Latency
# ============================================================================

function Get-DnsLatencyAudit {
    param(
        [string]$InterfaceName,
        [string]$GatewayIp,
        [string]$TestDomain = 'cloudflare.com',
        [int]$QueriesPerServer = 3
    )

    $configured = @()
    try {
        if ($InterfaceName) {
            $dnsInfo = Get-DnsClientServerAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($dnsInfo -and $dnsInfo.ServerAddresses) {
                $configured = @($dnsInfo.ServerAddresses)
            }
        }
    } catch { }

    $targets = New-Object System.Collections.Generic.List[object]
    if ($configured.Count -gt 0) {
        $targets.Add([ordered]@{ label = 'Current DNS'; server = $configured[0] })
    }
    $targets.Add([ordered]@{ label = 'Cloudflare'; server = '1.1.1.1' })
    $targets.Add([ordered]@{ label = 'Google'; server = '8.8.8.8' })
    if ($GatewayIp) {
        $targets.Add([ordered]@{ label = 'Gateway'; server = $GatewayIp })
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($t in $targets) {
        $times = New-Object System.Collections.Generic.List[double]
        $status = 'ok'
        for ($q = 0; $q -lt $QueriesPerServer; $q++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $null = Resolve-DnsName -Name $TestDomain -Type A -DnsOnly -NoHostsFile -QuickTimeout -Server $t.server -ErrorAction Stop
                $sw.Stop()
                $times.Add([math]::Round($sw.Elapsed.TotalMilliseconds, 2))
            } catch {
                $sw.Stop()
                $status = 'error'
            }
            Start-Sleep -Milliseconds 100
        }

        if ($times.Count -gt 0) {
            $m = $times | Measure-Object -Minimum -Maximum -Average
            $results.Add([ordered]@{
                label  = $t.label
                server = Protect-IpAddress -Ip $t.server
                avg_ms = [math]::Round($m.Average, 2)
                min_ms = [math]::Round($m.Minimum, 2)
                max_ms = [math]::Round($m.Maximum, 2)
                status = if ($times.Count -eq $QueriesPerServer) { 'ok' } else { 'partial' }
            })
        } else {
            $results.Add([ordered]@{
                label  = $t.label
                server = Protect-IpAddress -Ip $t.server
                avg_ms = $null
                min_ms = $null
                max_ms = $null
                status = $status
            })
        }
    }

    $protectedConfigured = @($configured | ForEach-Object { Protect-IpAddress -Ip $_ })
    return [ordered]@{
        test_domain        = $TestDomain
        configured_servers = $protectedConfigured
        results            = $results.ToArray()
    }
}

# ============================================================================
# (f) Sequential Load Test (Download 100 MB -> 2s drain -> Upload 25 MB)
#     with Parallel ICMP Probing ONLY During Active Transfer
# ============================================================================

function Start-BackgroundPingProbe {
    param([string]$Target)

    $state = [hashtable]::Synchronized(@{
        Stop    = $false
        Sent    = 0
        Samples = New-Object System.Collections.Generic.List[double]
    })

    if ([string]::IsNullOrWhiteSpace($Target)) {
        return [ordered]@{ PowerShell = $null; Handle = $null; State = $state }
    }

    $ps = [powershell]::Create()
    $null = $ps.AddScript({
        param($TargetIp, $SyncState)
        $p = New-Object System.Net.NetworkInformation.Ping
        try {
            while (-not $SyncState.Stop) {
                $SyncState.Sent++
                try {
                    $r = $p.Send($TargetIp, 1000)
                    if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                        $SyncState.Samples.Add([double]$r.RoundtripTime)
                    }
                } catch { }
                Start-Sleep -Milliseconds 150
            }
        } finally {
            $p.Dispose()
        }
    }).AddArgument($Target).AddArgument($state)

    $handle = $ps.BeginInvoke()
    return [ordered]@{ PowerShell = $ps; Handle = $handle; State = $state }
}

function Stop-BackgroundPingProbe {
    param($Probe)
    if ($Probe -and $Probe.PowerShell) {
        $Probe.State.Stop = $true
        try { $Probe.PowerShell.EndInvoke($Probe.Handle) } catch { }
        $Probe.PowerShell.Dispose()
    }
    return ConvertTo-LatencyStats -RttSamples $Probe.State.Samples.ToArray() -SentCount $Probe.State.Sent
}

function Invoke-CloudflareDownload {
    param([int64]$Bytes = 104857600) # 100 MB

    $url = "https://speed.cloudflare.com/__down?bytes=$Bytes"
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
    $referer = 'https://speed.cloudflare.com/'

    # Prefer curl.exe when available
    $curlCmd = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
    if ($curlCmd) {
        try {
            $out = & curl.exe -sS -L -o NUL `
                -A $ua `
                -H "Referer: $referer" `
                --max-time 60 `
                -w '%{size_download}|%{time_total}|%{speed_download}' `
                $url 2>&1
            $parts = ([string]$out).Trim().Split('|')
            if ($parts.Length -eq 3 -and [double]$parts[0] -gt 0 -and [double]$parts[1] -gt 0) {
                $dlBytes = [int64][double]$parts[0]
                $sec = [double]$parts[1]
                $mbps = [math]::Round((($dlBytes * 8.0) / $sec) / 1000000.0, 2)
                return [ordered]@{
                    tool            = 'curl.exe'
                    bytes           = $dlBytes
                    duration_sec    = [math]::Round($sec, 3)
                    throughput_mbps = $mbps
                    error           = $null
                }
            }
        } catch { }
    }

    # Fallback: .NET HttpClient streaming in memory
    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds(60)
        $client.DefaultRequestHeaders.Add('User-Agent', $ua)
        $client.DefaultRequestHeaders.Add('Referer', $referer)
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $resp = $client.GetAsync($url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            $resp.EnsureSuccessStatusCode() | Out-Null
            $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $buffer = New-Object byte[] 65536
            [int64]$totalRead = 0
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $totalRead += $read
            }
            $sw.Stop()
            $stream.Dispose()
            $sec = [math]::Max($sw.Elapsed.TotalSeconds, 0.001)
            $mbps = [math]::Round((($totalRead * 8.0) / $sec) / 1000000.0, 2)
            return [ordered]@{
                tool            = '.NET HttpClient'
                bytes           = $totalRead
                duration_sec    = [math]::Round($sec, 3)
                throughput_mbps = $mbps
                error           = $null
            }
        } finally {
            $client.Dispose()
        }
    } catch {
        return [ordered]@{
            tool            = '.NET HttpClient'
            bytes           = 0
            duration_sec    = 0
            throughput_mbps = $null
            error           = $_.Exception.Message
        }
    }
}

function Invoke-CloudflareUpload {
    param([int]$Bytes = 26214400) # 25 MB in-memory payload

    $url = 'https://speed.cloudflare.com/__up'
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
    $referer = 'https://speed.cloudflare.com/'

    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
        $payload = New-Object byte[] $Bytes
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds(60)
        $client.DefaultRequestHeaders.Add('User-Agent', $ua)
        $client.DefaultRequestHeaders.Add('Referer', $referer)
        try {
            $content = New-Object System.Net.Http.ByteArrayContent -ArgumentList (,$payload)
            $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/octet-stream')
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $resp = $client.PostAsync($url, $content).GetAwaiter().GetResult()
            $resp.EnsureSuccessStatusCode() | Out-Null
            $sw.Stop()
            $sec = [math]::Max($sw.Elapsed.TotalSeconds, 0.001)
            $mbps = [math]::Round((($Bytes * 8.0) / $sec) / 1000000.0, 2)
            return [ordered]@{
                tool            = '.NET HttpClient'
                bytes           = [int64]$Bytes
                duration_sec    = [math]::Round($sec, 3)
                throughput_mbps = $mbps
                error           = $null
            }
        } finally {
            $client.Dispose()
        }
    } catch {
        return [ordered]@{
            tool            = '.NET HttpClient'
            bytes           = 0
            duration_sec    = 0
            throughput_mbps = $null
            error           = $_.Exception.Message
        }
    }
}

function Invoke-LoadAndBufferbloatAudit {
    param(
        [string]$GatewayIp,
        [string]$WanTarget,
        $BaselineGateway,
        $BaselineWan
    )

    # Phase 1: Download 100 MB + parallel ICMP probing
    $dlGwProbe = Start-BackgroundPingProbe -Target $GatewayIp
    $dlWanProbe = Start-BackgroundPingProbe -Target $WanTarget
    $dlTransfer = Invoke-CloudflareDownload -Bytes 104857600
    $dlGwStats = Stop-BackgroundPingProbe -Probe $dlGwProbe
    $dlWanStats = Stop-BackgroundPingProbe -Probe $dlWanProbe

    # 2-second drain pause between Download and Upload phases
    Start-Sleep -Seconds 2

    # Phase 2: Upload 25 MB in-memory + parallel ICMP probing
    $ulGwProbe = Start-BackgroundPingProbe -Target $GatewayIp
    $ulWanProbe = Start-BackgroundPingProbe -Target $WanTarget
    $ulTransfer = Invoke-CloudflareUpload -Bytes 26214400
    $ulGwStats = Stop-BackgroundPingProbe -Probe $ulGwProbe
    $ulWanStats = Stop-BackgroundPingProbe -Probe $ulWanProbe

    $calcDelta = {
        param($loaded, $idle)
        if ($null -ne $loaded -and $null -ne $idle) {
            return [math]::Round(($loaded - $idle), 2)
        }
        return $null
    }

    return [ordered]@{
        skipped  = $false
        tool     = "$($dlTransfer.tool) / $($ulTransfer.tool)"
        download = [ordered]@{
            bytes            = $dlTransfer.bytes
            duration_sec     = $dlTransfer.duration_sec
            throughput_mbps  = $dlTransfer.throughput_mbps
            error            = $dlTransfer.error
            gateway_latency  = $dlGwStats
            wan_latency      = $dlWanStats
            gateway_bloat_ms = (& $calcDelta $dlGwStats.avg_ms $BaselineGateway.avg_ms)
            wan_bloat_ms     = (& $calcDelta $dlWanStats.avg_ms $BaselineWan.avg_ms)
        }
        upload   = [ordered]@{
            bytes            = $ulTransfer.bytes
            duration_sec     = $ulTransfer.duration_sec
            throughput_mbps  = $ulTransfer.throughput_mbps
            error            = $ulTransfer.error
            gateway_latency  = $ulGwStats
            wan_latency      = $ulWanStats
            gateway_bloat_ms = (& $calcDelta $ulGwStats.avg_ms $BaselineGateway.avg_ms)
            wan_bloat_ms     = (& $calcDelta $ulWanStats.avg_ms $BaselineWan.avg_ms)
        }
    }
}

# ============================================================================
# Markdown Renderer
# ============================================================================

function Format-ReportMarkdown {
    param($Report)

    $sb = New-Object System.Text.StringBuilder
    $fmtVal = { param($v, $suffix = '') if ($null -eq $v -or "$v" -eq '') { 'N/A' } else { "$v$suffix" } }

    [void]$sb.AppendLine('# Wi-Fi & Network Audit Report (Windows)')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("- **Timestamp (UTC):** $($Report.timestamp_utc)")
    [void]$sb.AppendLine("- **Anonymized:** $($Report.anonymized)")
    [void]$sb.AppendLine('')

    # Wi-Fi Link
    $w = $Report.wifi_link
    [void]$sb.AppendLine('## 1. Active Wi-Fi Link')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Metric | Value |')
    [void]$sb.AppendLine('| :--- | :--- |')
    [void]$sb.AppendLine("| Interface | $(& $fmtVal $w.interface_name) |")
    [void]$sb.AppendLine("| Adapter | $(& $fmtVal $w.description) |")
    [void]$sb.AppendLine("| State | $(& $fmtVal $w.state) |")
    [void]$sb.AppendLine("| SSID / BSSID | $(& $fmtVal $w.ssid) / ``$(& $fmtVal $w.bssid)`` |")
    [void]$sb.AppendLine("| Band / Channel | $(& $fmtVal $w.band) / Ch $(& $fmtVal $w.channel) (DFS: $($w.is_dfs)) |")
    [void]$sb.AppendLine("| Radio / PHY | $(& $fmtVal $w.radio_type) |")
    [void]$sb.AppendLine("| Signal | $(& $fmtVal $w.signal_percent '%') |")
    [void]$sb.AppendLine("| Link Rate (RX / TX) | $(& $fmtVal $w.receive_rate_mbps ' Mbps') / $(& $fmtVal $w.transmit_rate_mbps ' Mbps') |")
    $err = $w.interface_errors
    [void]$sb.AppendLine("| Interface Errors (RX/TX) | $(& $fmtVal $err.packets_received_errors) / $(& $fmtVal $err.packets_outbound_errors) (Discards: $(& $fmtVal $err.packets_received_discarded)/$(& $fmtVal $err.packets_outbound_discarded)) |")
    [void]$sb.AppendLine("| Netstat Errors (RX/TX) | $(& $fmtVal $err.netstat_rx_errors) / $(& $fmtVal $err.netstat_tx_errors) |")
    [void]$sb.AppendLine('')

    # RF Congestion
    $rf = $Report.rf_scan
    [void]$sb.AppendLine('## 2. RF Spectrum & Neighbor Congestion')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("- **Total BSSIDs scanned:** $($rf.total_bssids)")
    [void]$sb.AppendLine("- **2.4 GHz competing APs:** Ch1=$($rf.band_2_4ghz.ch1), Ch6=$($rf.band_2_4ghz.ch6), Ch11=$($rf.band_2_4ghz.ch11), Other=$($rf.band_2_4ghz.other) (Total: $($rf.band_2_4ghz.total))")
    [void]$sb.AppendLine("- **5 GHz competing APs:** Non-DFS 36-48=$($rf.band_5ghz.non_dfs_36_48), DFS 52-144=$($rf.band_5ghz.dfs_52_144), Upper 149+=$($rf.band_5ghz.upper_149_plus) (Total: $($rf.band_5ghz.total))")
    [void]$sb.AppendLine('')

    # USB & Power / Events
    $u = $Report.usb_audit
    [void]$sb.AppendLine('## 3. USB Adapter, Power & WLAN Events')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("| Metric | Value |")
    [void]$sb.AppendLine("| :--- | :--- |")
    [void]$sb.AppendLine("| USB Adapter Applicable | $($u.applicable) |")
    [void]$sb.AppendLine("| Root Hub Type | $(& $fmtVal $u.root_hub_type) |")
    [void]$sb.AppendLine("| bcdUSB / Negotiated Speed | $(& $fmtVal $u.bcd_usb) / $(& $fmtVal $u.negotiated_speed_label) |")
    [void]$sb.AppendLine("| USB 2.0 Bottleneck on USB 3.0 Hub | $($u.usb2_bottleneck_on_usb3_hub) |")
    [void]$sb.AppendLine("| USB Selective Suspend (AC / DC) | $($u.selective_suspend_ac) / $($u.selective_suspend_dc) |")
    [void]$sb.AppendLine("| Recent WLAN Events (8003/11004) | $($u.wlan_events_recent.Count) |")
    if ($u.note) {
        [void]$sb.AppendLine("| Note | $($u.note) |")
    }
    [void]$sb.AppendLine('')

    # VPN & Idle Baseline Latency
    $v = $Report.vpn_and_tunnel
    $b = $Report.baseline_latency
    [void]$sb.AppendLine('## 4. VPN / Tunnels & Idle Baseline Latency (Sequential)')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("- **Active VPN / Tunnel detected:** $($v.detected)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Target | Sent / Recv | Loss % | Min (ms) | Avg (ms) | P95 (ms) | Max (ms) |')
    [void]$sb.AppendLine('| :--- | :---: | :---: | :---: | :---: | :---: | :---: |')
    [void]$sb.AppendLine("| Gateway (``$(& $fmtVal $b.gateway_ip)``) | $($b.gateway.sent)/$($b.gateway.received) | $($b.gateway.loss_pct)% | $(& $fmtVal $b.gateway.min_ms) | $(& $fmtVal $b.gateway.avg_ms) | $(& $fmtVal $b.gateway.p95_ms) | $(& $fmtVal $b.gateway.max_ms) |")
    [void]$sb.AppendLine("| WAN (``$($b.wan_target)``) | $($b.wan.sent)/$($b.wan.received) | $($b.wan.loss_pct)% | $(& $fmtVal $b.wan.min_ms) | $(& $fmtVal $b.wan.avg_ms) | $(& $fmtVal $b.wan.p95_ms) | $(& $fmtVal $b.wan.max_ms) |")
    [void]$sb.AppendLine('')

    # DNS Latency
    $d = $Report.dns_latency
    [void]$sb.AppendLine('## 5. Uncached DNS Latency')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Resolver | Server | Min (ms) | Avg (ms) | Max (ms) | Status |')
    [void]$sb.AppendLine('| :--- | :--- | :---: | :---: | :---: | :---: |')
    foreach ($r in $d.results) {
        [void]$sb.AppendLine("| $($r.label) | ``$($r.server)`` | $(& $fmtVal $r.min_ms) | $(& $fmtVal $r.avg_ms) | $(& $fmtVal $r.max_ms) | $($r.status) |")
    }
    [void]$sb.AppendLine('')

    # Load Test & Bufferbloat
    $lt = $Report.load_test
    [void]$sb.AppendLine('## 6. Load Test & Bufferbloat (Sequential DL -> 2s Drain -> UL)')
    [void]$sb.AppendLine('')
    if ($lt.skipped) {
        [void]$sb.AppendLine('_Skipped (`-SkipLoadTest`)._')
    } else {
        [void]$sb.AppendLine('| Phase | Throughput | Gateway Avg (Delta) | WAN Avg (Delta) | Gateway Loss | WAN Loss |')
        [void]$sb.AppendLine('| :--- | :---: | :---: | :---: | :---: | :---: |')
        $dl = $lt.download
        $ul = $lt.upload
        [void]$sb.AppendLine("| Download (100 MB) | $(& $fmtVal $dl.throughput_mbps ' Mbps') | $(& $fmtVal $dl.gateway_latency.avg_ms ' ms') (+$(& $fmtVal $dl.gateway_bloat_ms ' ms')) | $(& $fmtVal $dl.wan_latency.avg_ms ' ms') (+$(& $fmtVal $dl.wan_bloat_ms ' ms')) | $($dl.gateway_latency.loss_pct)% | $($dl.wan_latency.loss_pct)% |")
        [void]$sb.AppendLine("| Upload (25 MB) | $(& $fmtVal $ul.throughput_mbps ' Mbps') | $(& $fmtVal $ul.gateway_latency.avg_ms ' ms') (+$(& $fmtVal $ul.gateway_bloat_ms ' ms')) | $(& $fmtVal $ul.wan_latency.avg_ms ' ms') (+$(& $fmtVal $ul.wan_bloat_ms ' ms')) | $($ul.gateway_latency.loss_pct)% | $($ul.wan_latency.loss_pct)% |")
    }

    return $sb.ToString()
}

# ============================================================================
# Main Execution (STRICTLY SEQUENTIAL)
# ============================================================================

$wifiLink = Get-WifiLinkAudit
$rfScan = Get-RfScanAudit -OwnSsid $wifiLink.raw_ssid -OwnBssid $wifiLink.raw_bssid
$usbAudit = Get-UsbWifiAudit -InterfaceName $wifiLink.interface_name -AdapterDescription $wifiLink.description
$vpnAudit = Get-VpnTunnelAudit

$gatewayIp = Get-DefaultGatewayIpv4 -InterfaceName $wifiLink.interface_name
$wanTarget = '1.1.1.1'

# Strictly sequential idle baseline pings (never concurrent with load)
$gwBaseline = Invoke-SequentialPing -Target $gatewayIp -Count $PingCount
$wanBaseline = Invoke-SequentialPing -Target $wanTarget -Count $PingCount

$dnsAudit = Get-DnsLatencyAudit -InterfaceName $wifiLink.interface_name -GatewayIp $gatewayIp

if ($SkipLoadTest) {
    $loadTest = [ordered]@{
        skipped  = $true
        tool     = $null
        download = $null
        upload   = $null
    }
} else {
    $loadTest = Invoke-LoadAndBufferbloatAudit `
        -GatewayIp $gatewayIp `
        -WanTarget $wanTarget `
        -BaselineGateway $gwBaseline `
        -BaselineWan $wanBaseline
}

# Strip internal raw SSID/BSSID before output
$wifiLinkClean = [ordered]@{
    interface_name     = $wifiLink.interface_name
    description        = $wifiLink.description
    state              = $wifiLink.state
    ssid               = $wifiLink.ssid
    bssid              = $wifiLink.bssid
    band               = $wifiLink.band
    channel            = $wifiLink.channel
    is_dfs             = $wifiLink.is_dfs
    radio_type         = $wifiLink.radio_type
    signal_percent     = $wifiLink.signal_percent
    receive_rate_mbps  = $wifiLink.receive_rate_mbps
    transmit_rate_mbps = $wifiLink.transmit_rate_mbps
    interface_errors   = $wifiLink.interface_errors
}

$report = [ordered]@{
    schema_version   = '1.0.0'
    timestamp_utc    = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    platform         = 'windows'
    anonymized       = [bool]$Anonymize
    wifi_link        = $wifiLinkClean
    rf_scan          = $rfScan
    usb_audit        = $usbAudit
    vpn_and_tunnel   = $vpnAudit
    baseline_latency = [ordered]@{
        gateway_ip = Protect-IpAddress -Ip $gatewayIp
        gateway    = $gwBaseline
        wan_target = $wanTarget
        wan        = $wanBaseline
    }
    dns_latency      = $dnsAudit
    load_test        = $loadTest
}

$outputText = if ($Format -eq 'Json') {
    $report | ConvertTo-Json -Depth 8
} else {
    Format-ReportMarkdown -Report $report
}

if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
    $resolvedOutPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
    $parentDir = Split-Path -Parent $resolvedOutPath
    if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($resolvedOutPath, $outputText + "`n", $utf8NoBom)
} else {
    $outputText
}
