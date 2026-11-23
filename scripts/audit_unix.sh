#!/usr/bin/env bash
# ============================================================================
# wifi-network-audit: Read-only Wi-Fi & Network Diagnostic Script (macOS/Linux)
# License: MIT
# ============================================================================
# Strictly read-only: makes no modifications to OS settings, network adapters,
# or system configuration. Baseline checks run strictly sequentially; parallel
# ICMP probing runs ONLY during active Download/Upload load phases with a 2s
# drain pause between phases.
# ============================================================================

set -euo pipefail

FORMAT="markdown"
ANONYMIZE=1
SKIP_LOAD=0
PING_COUNT=20
OUT_FILE=""
WAN_TARGET="1.1.1.1"
DNS_TEST_DOMAIN="cloudflare.com"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
REFERER="https://speed.cloudflare.com/"

usage() {
    cat <<'EOF'
Usage: audit_unix.sh [OPTIONS]

Options:
  --format markdown|json   Output format (default: markdown)
  -o, --out FILE           Write report output to FILE instead of stdout
  --anonymize              Mask MACs/BSSIDs, neighbor SSIDs, and public IPs (default)
  --no-anonymize           Disable anonymization
  --skip-load              Skip Download/Upload load and bufferbloat tests
  --ping-count N           Number of sequential idle pings per target (default: 20)
  -h, --help               Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --format)
            FORMAT="$(printf '%s' "${2:-}" | tr '[:upper:]' '[:lower:]')"
            if [[ "$FORMAT" != "markdown" && "$FORMAT" != "json" ]]; then
                echo "Error: --format must be 'markdown' or 'json'." >&2
                exit 2
            fi
            shift 2
            ;;
        -o|--out)
            if [[ -z "${2:-}" ]]; then
                echo "Error: --out requires a file path." >&2
                exit 2
            fi
            OUT_FILE="$2"
            shift 2
            ;;
        --anonymize)
            ANONYMIZE=1
            shift
            ;;
        --no-anonymize)
            ANONYMIZE=0
            shift
            ;;
        --skip-load)
            SKIP_LOAD=1
            shift
            ;;
        --ping-count)
            PING_COUNT="${2:-20}"
            if ! [[ "$PING_COUNT" =~ ^[0-9]+$ ]] || (( PING_COUNT < 1 || PING_COUNT > 200 )); then
                echo "Error: --ping-count must be an integer between 1 and 200." >&2
                exit 2
            fi
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option '$1'." >&2
            usage >&2
            exit 2
            ;;
    esac
done

OS_NAME="$(uname -s)"
case "$OS_NAME" in
    Darwin) PLATFORM="macos" ;;
    Linux)  PLATFORM="linux" ;;
    *)
        echo "Error: Unsupported OS '$OS_NAME'. Use audit_windows.ps1 on Windows." >&2
        exit 1
        ;;
esac

TIMESTAMP_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wifi-audit.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

# ============================================================================
# Anonymization & JSON Helpers (Bash 3.2+ compatible for macOS default bash)
# ============================================================================

MAC_MAP_FILE="$TMP_DIR/mac_map.txt"
IP_MAP_FILE="$TMP_DIR/ip_map.txt"
SSID_MAP_FILE="$TMP_DIR/ssid_map.txt"
: > "$MAC_MAP_FILE"
: > "$IP_MAP_FILE"
: > "$SSID_MAP_FILE"

json_escape() {
    local s="${1:-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

json_str_or_null() {
    local v="${1:-}"
    if [[ -z "$v" || "$v" == "null" ]]; then
        printf 'null'
    else
        printf '"%s"' "$(json_escape "$v")"
    fi
}

json_num_or_null() {
    local v="${1:-}"
    if [[ -z "$v" || "$v" == "null" ]] || ! [[ "$v" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
        printf 'null'
    else
        printf '%s' "$v"
    fi
}

is_preserved_ip() {
    local ip="${1:-}"
    local ip_lc
    ip_lc="$(printf '%s' "$ip" | tr '[:upper:]' '[:lower:]')"
    ip_lc="${ip_lc%%%*}"
    case "$ip_lc" in
        1.1.1.1|1.0.0.1|8.8.8.8|8.8.4.4|9.9.9.9|149.112.112.112|208.67.222.222|208.67.220.220)
            return 0 ;;
        10.*|192.168.*|127.*|169.254.*|0.*)
            return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)
            return 0 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*)
            return 0 ;;
        ::|::1|0:0:0:0:0:0:0:1|0000:0000:0000:0000:0000:0000:0000:0001)
            return 0 ;;
        fe[89ab][0-9a-f]:*|fc[0-9a-f][0-9a-f]:*|fd[0-9a-f][0-9a-f]:*)
            return 0 ;;
    esac
    return 1
}

protect_mac() {
    local raw="${1:-}"
    if [[ -z "$raw" || "$ANONYMIZE" -eq 0 ]]; then
        printf '%s' "$raw"
        return
    fi
    local norm
    norm="$(printf '%s' "$raw" | tr '[:upper:]-' '[:lower:]:')"
    local existing
    existing="$(awk -F'\t' -v k="$norm" '$1==k {print $2; exit}' "$MAC_MAP_FILE")"
    if [[ -n "$existing" ]]; then
        printf '%s' "$existing"
        return
    fi
    local count
    count="$(wc -l < "$MAC_MAP_FILE" | tr -d ' ')"
    count=$((count + 1))
    local masked
    masked="$(printf 'xx:xx:xx:xx:xx:%02x' $((count % 256)))"
    printf '%s\t%s\n' "$norm" "$masked" >> "$MAC_MAP_FILE"
    printf '%s' "$masked"
}

protect_ip() {
    local raw="${1:-}"
    if [[ -z "$raw" || "$ANONYMIZE" -eq 0 ]]; then
        printf '%s' "$raw"
        return
    fi
    if is_preserved_ip "$raw"; then
        printf '%s' "$raw"
        return
    fi
    local existing
    existing="$(awk -F'\t' -v k="$raw" '$1==k {print $2; exit}' "$IP_MAP_FILE")"
    if [[ -n "$existing" ]]; then
        printf '%s' "$existing"
        return
    fi
    local count
    count="$(wc -l < "$IP_MAP_FILE" | tr -d ' ')"
    count=$((count + 1))
    local masked
    masked="$(printf '[PUBLIC_IP_%02d]' "$count")"
    printf '%s\t%s\n' "$raw" "$masked" >> "$IP_MAP_FILE"
    printf '%s' "$masked"
}

protect_ssid() {
    local raw="${1:-}"
    local is_own="${2:-0}"
    if [[ -z "$raw" ]]; then
        printf ''
        return
    fi
    if [[ "$ANONYMIZE" -eq 0 ]]; then
        printf '%s' "$raw"
        return
    fi
    if [[ "$is_own" -eq 1 ]]; then
        printf 'Own_WiFi'
        return
    fi
    local existing
    existing="$(awk -F'\t' -v k="$raw" '$1==k {print $2; exit}' "$SSID_MAP_FILE")"
    if [[ -n "$existing" ]]; then
        printf '%s' "$existing"
        return
    fi
    local count
    count="$(wc -l < "$SSID_MAP_FILE" | tr -d ' ')"
    count=$((count + 1))
    local masked
    masked="$(printf 'Neighbor_%02d' "$count")"
    printf '%s\t%s\n' "$raw" "$masked" >> "$SSID_MAP_FILE"
    printf '%s' "$masked"
}

is_dfs_channel() {
    local ch="${1:-0}"
    if [[ "$ch" =~ ^[0-9]+$ ]] && (( ch >= 52 && ch <= 144 )); then
        printf 'true'
    else
        printf 'false'
    fi
}

band_from_channel() {
    local ch="${1:-0}"
    if ! [[ "$ch" =~ ^[0-9]+$ ]]; then
        printf 'Unknown'
        return
    fi
    if (( ch >= 1 && ch <= 14 )); then
        printf '2.4 GHz'
    elif (( ch >= 32 && ch <= 177 )); then
        printf '5 GHz'
    else
        printf 'Unknown'
    fi
}

# ============================================================================
# Statistics Helper (awk-based min/avg/p95/max/loss)
# ============================================================================

compute_ping_stats_json() {
    local samples_file="$1"
    local sent_count="$2"
    awk -v sent="$sent_count" '
    BEGIN { n = 0; sum = 0; min = 1e9; max = 0 }
    /^[0-9]+(\.[0-9]+)?$/ {
        val = $1 + 0
        vals[n++] = val
        sum += val
        if (val < min) min = val
        if (val > max) max = val
    }
    END {
        if (sent <= 0) {
            printf "{\"sent\":0,\"received\":0,\"loss_pct\":100.0,\"min_ms\":null,\"avg_ms\":null,\"p95_ms\":null,\"max_ms\":null}"
            exit
        }
        loss = ((sent - n) / sent) * 100.0
        if (n == 0) {
            printf "{\"sent\":%d,\"received\":0,\"loss_pct\":%.2f,\"min_ms\":null,\"avg_ms\":null,\"p95_ms\":null,\"max_ms\":null}", sent, loss
            exit
        }
        # Insertion sort
        for (i = 1; i < n; i++) {
            key = vals[i]; j = i - 1
            while (j >= 0 && vals[j] > key) { vals[j+1] = vals[j]; j-- }
            vals[j+1] = key
        }
        rank = 0.95 * (n - 1)
        lo = int(rank)
        hi = (rank > lo) ? lo + 1 : lo
        if (hi >= n) hi = n - 1
        p95 = vals[lo] + (vals[hi] - vals[lo]) * (rank - lo)
        avg = sum / n
        printf "{\"sent\":%d,\"received\":%d,\"loss_pct\":%.2f,\"min_ms\":%.2f,\"avg_ms\":%.2f,\"p95_ms\":%.2f,\"max_ms\":%.2f}", sent, n, loss, min, avg, p95, max
    }' "$samples_file"
}

run_sequential_ping() {
    local target="$1"
    local count="$2"
    local out_file="$TMP_DIR/ping_samples.txt"
    : > "$out_file"

    if [[ -z "$target" ]]; then
        compute_ping_stats_json "$out_file" 0
        return
    fi

    local raw_out
    if [[ "$PLATFORM" == "macos" ]]; then
        raw_out="$(ping -c "$count" -i 0.2 -W 1500 "$target" 2>/dev/null || true)"
    else
        raw_out="$(ping -c "$count" -i 0.2 -W 2 "$target" 2>/dev/null || true)"
    fi

    printf '%s\n' "$raw_out" | sed -nE 's/.*time=([0-9]+(\.[0-9]+)?).*/\1/p' > "$out_file"
    compute_ping_stats_json "$out_file" "$count"
}

# ============================================================================
# Platform-Specific Collectors: Wi-Fi, RF Scan, USB, VPN, Gateway, DNS
# ============================================================================

WIFI_IFACE=""
WIFI_DESC=""
WIFI_STATE="unknown"
WIFI_RAW_SSID=""
WIFI_RAW_BSSID=""
WIFI_BAND="Unknown"
WIFI_CHANNEL=""
WIFI_IS_DFS="false"
WIFI_RADIO=""
WIFI_SIGNAL=""
WIFI_RX_RATE=""
WIFI_TX_RATE=""
ERR_RX="null"
ERR_RX_DISC="null"
ERR_TX="null"
ERR_TX_DISC="null"

RF_TOTAL=0
RF_24_CH1=0; RF_24_CH6=0; RF_24_CH11=0; RF_24_OTHER=0
RF_5_NONDFS=0; RF_5_DFS=0; RF_5_UPPER=0

USB_APPLICABLE="false"
USB_HUB_TYPE=""
USB_SPEED_LABEL=""
USB_BOTTLENECK="false"
USB_NOTE=""

VPN_DETECTED="false"
VPN_JSON="[]"
GATEWAY_IP=""
DNS_SERVERS=()

collect_macos() {
    WIFI_IFACE="$(networksetup -listallhardwareports 2>/dev/null | awk '/Wi-Fi|AirPort/{getline; print $2; exit}')"
    [[ -z "$WIFI_IFACE" ]] && WIFI_IFACE="en0"
    WIFI_DESC="macOS Wi-Fi ($WIFI_IFACE)"

    GATEWAY_IP="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')"

    local ap_out=""
    if command -v system_profiler >/dev/null 2>&1; then
        ap_out="$(system_profiler SPAirPortDataType 2>/dev/null || true)"
    fi

    if [[ -n "$ap_out" ]]; then
        WIFI_STATE="$(printf '%s\n' "$ap_out" | awk '/Status:/{print $2; exit}')"
        WIFI_RAW_SSID="$(printf '%s\n' "$ap_out" | awk '/Current Network Information:/{getline; gsub(/^[ \t]+|:$/,""); print; exit}')"
        WIFI_RADIO="$(printf '%s\n' "$ap_out" | awk -F': ' '/PHY Mode:/{print $2; exit}' | tr -d '\r')"
        WIFI_CHANNEL="$(printf '%s\n' "$ap_out" | awk -F': ' '/Channel:/{print $2; exit}' | grep -oE '^[0-9]+' || true)"
        WIFI_TX_RATE="$(printf '%s\n' "$ap_out" | awk -F': ' '/Transmit Rate:/{print $2; exit}' | grep -oE '[0-9]+(\.[0-9]+)?' || true)"
        local rssi
        rssi="$(printf '%s\n' "$ap_out" | awk -F': ' '/Signal \/ Noise:/{print $2; exit}' | grep -oE '^-?[0-9]+' || true)"
        if [[ -n "$rssi" ]]; then
            # Approximate RSSI (-90..-30 dBm) to 0..100%
            WIFI_SIGNAL="$(awk -v r="$rssi" 'BEGIN { p = int((r + 90) * 100 / 60); if (p < 0) p = 0; if (p > 100) p = 100; print p }')"
        fi

        # Count other networks from SPAirPortDataType
        local ch_list
        ch_list="$(printf '%s\n' "$ap_out" | awk '/Other Local Wi-Fi Networks:/{flag=1; next} flag && /Channel:/{print $2}' | grep -oE '^[0-9]+' || true)"
        while IFS= read -r c; do
            [[ -z "$c" ]] && continue
            RF_TOTAL=$((RF_TOTAL + 1))
            if (( c >= 1 && c <= 14 )); then
                case "$c" in
                    1) RF_24_CH1=$((RF_24_CH1 + 1)) ;;
                    6) RF_24_CH6=$((RF_24_CH6 + 1)) ;;
                    11) RF_24_CH11=$((RF_24_CH11 + 1)) ;;
                    *) RF_24_OTHER=$((RF_24_OTHER + 1)) ;;
                esac
            elif (( c >= 36 && c <= 48 )); then
                RF_5_NONDFS=$((RF_5_NONDFS + 1))
            elif (( c >= 52 && c <= 144 )); then
                RF_5_DFS=$((RF_5_DFS + 1))
            elif (( c >= 149 )); then
                RF_5_UPPER=$((RF_5_UPPER + 1))
            fi
        done <<< "$ch_list"
    fi

    # Optional wdutil fallback for BSSID/channel if permitted without sudo
    if command -v wdutil >/dev/null 2>&1; then
        local wd_out
        wd_out="$(wdutil info 2>/dev/null || true)"
        if [[ -n "$wd_out" ]]; then
            local b
            b="$(printf '%s\n' "$wd_out" | awk -F': ' '/BSSID/{print $2; exit}' | tr -d ' \r')"
            [[ -n "$b" && "$b" != "<redacted>" ]] && WIFI_RAW_BSSID="$b"
        fi
    fi

    WIFI_BAND="$(band_from_channel "${WIFI_CHANNEL:-0}")"
    WIFI_IS_DFS="$(is_dfs_channel "${WIFI_CHANNEL:-0}")"

    # Interface errors via netstat -I
    if command -v netstat >/dev/null 2>&1; then
        local ns_line
        ns_line="$(netstat -I "$WIFI_IFACE" -b 2>/dev/null | awk 'NR==2{print $6, $9}')"
        if [[ -n "$ns_line" ]]; then
            ERR_RX="$(printf '%s' "$ns_line" | awk '{print $1}')"
            ERR_TX="$(printf '%s' "$ns_line" | awk '{print $2}')"
        fi
    fi

    # USB check (macOS integrated Wi-Fi is PCIe; check SPUSBDataType only for external dongles)
    USB_NOTE="macOS built-in Wi-Fi is typically PCIe; USB audit only applies to external USB dongles."

    # VPN / Tunnel detection
    local vpn_items=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        vpn_items+=("{\"name\":\"$(json_escape "$line")\",\"description\":\"Active VPN/tunnel\",\"status\":\"Up\"}")
    done < <(scutil --nc list 2>/dev/null | awk '/Connected/{print $0}' || true)
    if [[ ${#vpn_items[@]} -gt 0 ]]; then
        VPN_DETECTED="true"
        VPN_JSON="[$(IFS=,; printf '%s' "${vpn_items[*]}")]"
    fi

    # DNS servers via scutil --dns
    while IFS= read -r ns; do
        [[ -z "$ns" ]] && continue
        DNS_SERVERS+=("$ns")
    done < <(scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/{print $3}' | awk '!seen[$0]++' | head -n 4 || true)
}

collect_linux() {
    # Locate active wireless interface (prioritize associated/UP interface when multiple exist)
    local wifi_candidates=()
    local cand=""
    if command -v iw >/dev/null 2>&1; then
        while IFS= read -r cand; do
            [[ -n "$cand" ]] && wifi_candidates+=("$cand")
        done < <(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}' || true)
    fi
    if [[ "${#wifi_candidates[@]}" -eq 0 && -d /sys/class/net ]]; then
        for d in /sys/class/net/*; do
            if [[ -d "$d/wireless" ]]; then
                wifi_candidates+=("$(basename "$d")")
            fi
        done
    fi

    if [[ "${#wifi_candidates[@]}" -gt 0 ]]; then
        # Priority 1: interface actively associated via iw link
        if command -v iw >/dev/null 2>&1; then
            for cand in "${wifi_candidates[@]}"; do
                if iw dev "$cand" link 2>/dev/null | grep -q '^Connected to'; then
                    WIFI_IFACE="$cand"
                    break
                fi
            done
        fi
        # Priority 2: interface marked connected by nmcli
        if [[ -z "$WIFI_IFACE" ]] && command -v nmcli >/dev/null 2>&1; then
            local nm_iface
            nm_iface="$(nmcli -t -f DEVICE,TYPE,STATE dev status 2>/dev/null | awk -F: '$2=="wifi" && $3=="connected"{print $1; exit}' || true)"
            if [[ -n "$nm_iface" ]]; then
                WIFI_IFACE="$nm_iface"
            fi
        fi
        # Priority 3: interface with operstate up / state UP
        if [[ -z "$WIFI_IFACE" ]]; then
            for cand in "${wifi_candidates[@]}"; do
                if [[ -r "/sys/class/net/$cand/operstate" && "$(cat "/sys/class/net/$cand/operstate" 2>/dev/null || true)" == "up" ]]; then
                    WIFI_IFACE="$cand"
                    break
                elif command -v ip >/dev/null 2>&1 && ip link show "$cand" 2>/dev/null | grep -q 'state UP'; then
                    WIFI_IFACE="$cand"
                    break
                fi
            done
        fi
        # Priority 4: fallback to first detected wireless interface
        if [[ -z "$WIFI_IFACE" ]]; then
            WIFI_IFACE="${wifi_candidates[0]}"
        fi
    fi
    WIFI_DESC="Linux Wi-Fi (${WIFI_IFACE:-none})"

    if command -v ip >/dev/null 2>&1; then
        GATEWAY_IP="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
    fi

    if [[ -n "$WIFI_IFACE" ]]; then
        # Interface link stats
        if command -v iw >/dev/null 2>&1; then
            local link_out
            link_out="$(iw dev "$WIFI_IFACE" link 2>/dev/null || true)"
            if printf '%s\n' "$link_out" | grep -q '^Connected to'; then
                WIFI_STATE="connected"
                WIFI_RAW_BSSID="$(printf '%s\n' "$link_out" | awk '/^Connected to/{print $3; exit}')"
                WIFI_RAW_SSID="$(printf '%s\n' "$link_out" | sed -nE 's/^[[:space:]]*SSID:[[:space:]]*(.*)$/\1/p' | head -n 1)"
                local freq
                freq="$(printf '%s\n' "$link_out" | awk '/freq:/{print int($2); exit}')"
                if [[ -n "$freq" ]]; then
                    if (( freq >= 2412 && freq <= 2484 )); then
                        WIFI_CHANNEL=$(( (freq - 2407) / 5 ))
                        [[ "$freq" -eq 2484 ]] && WIFI_CHANNEL=14
                    elif (( freq >= 5180 && freq <= 5885 )); then
                        WIFI_CHANNEL=$(( (freq - 5000) / 5 ))
                    fi
                fi
                local sig_dbm
                sig_dbm="$(printf '%s\n' "$link_out" | awk '/signal:/{print int($2); exit}')"
                if [[ -n "$sig_dbm" ]]; then
                    WIFI_SIGNAL="$(awk -v r="$sig_dbm" 'BEGIN { p = int((r + 90) * 100 / 60); if (p < 0) p = 0; if (p > 100) p = 100; print p }')"
                fi
                WIFI_RX_RATE="$(printf '%s\n' "$link_out" | awk '/rx bitrate:/{print $3; exit}')"
                WIFI_TX_RATE="$(printf '%s\n' "$link_out" | awk '/tx bitrate:/{print $3; exit}')"
            else
                WIFI_STATE="disconnected"
            fi
        fi

        # sysfs error counters
        local stat_dir="/sys/class/net/$WIFI_IFACE/statistics"
        if [[ -d "$stat_dir" ]]; then
            ERR_RX="$(cat "$stat_dir/rx_errors" 2>/dev/null || echo null)"
            ERR_RX_DISC="$(cat "$stat_dir/rx_dropped" 2>/dev/null || echo null)"
            ERR_TX="$(cat "$stat_dir/tx_errors" 2>/dev/null || echo null)"
            ERR_TX_DISC="$(cat "$stat_dir/tx_dropped" 2>/dev/null || echo null)"
        fi

        # RF scan via nmcli (non-root friendly) or iw scan
        if command -v nmcli >/dev/null 2>&1; then
            while IFS=: read -r in_use chan; do
                [[ -z "$chan" || ! "$chan" =~ ^[0-9]+$ ]] && continue
                RF_TOTAL=$((RF_TOTAL + 1))
                [[ "$in_use" == "*" ]] && continue
                if (( chan >= 1 && chan <= 14 )); then
                    case "$chan" in
                        1) RF_24_CH1=$((RF_24_CH1 + 1)) ;;
                        6) RF_24_CH6=$((RF_24_CH6 + 1)) ;;
                        11) RF_24_CH11=$((RF_24_CH11 + 1)) ;;
                        *) RF_24_OTHER=$((RF_24_OTHER + 1)) ;;
                    esac
                elif (( chan >= 36 && chan <= 48 )); then
                    RF_5_NONDFS=$((RF_5_NONDFS + 1))
                elif (( chan >= 52 && chan <= 144 )); then
                    RF_5_DFS=$((RF_5_DFS + 1))
                elif (( chan >= 149 )); then
                    RF_5_UPPER=$((RF_5_UPPER + 1))
                fi
            done < <(nmcli -t -f IN-USE,CHAN dev wifi list 2>/dev/null || true)
        fi

        # USB check via sysfs + lsusb -t
        local dev_path
        dev_path="$(readlink -f "/sys/class/net/$WIFI_IFACE/device" 2>/dev/null || true)"
        if [[ "$dev_path" == *"/usb"* ]]; then
            USB_APPLICABLE="true"
            if command -v lsusb >/dev/null 2>&1; then
                local usb_tree
                usb_tree="$(lsusb -t 2>/dev/null || true)"
                if printf '%s\n' "$usb_tree" | grep -qiE 'xhci_hcd'; then
                    USB_HUB_TYPE="xHCI (USB 3.0+)"
                fi
                local drv
                drv="$(basename "$(readlink -f "/sys/class/net/$WIFI_IFACE/device/driver" 2>/dev/null || echo unknown)")"
                local speed_line
                speed_line="$(printf '%s\n' "$usb_tree" | grep -i "Driver=$drv" | head -n 1 || true)"
                if printf '%s\n' "$speed_line" | grep -q '5000M\|10000M'; then
                    USB_SPEED_LABEL="SuperSpeed (USB 3.0+, 5+ Gbps)"
                elif printf '%s\n' "$speed_line" | grep -q '480M'; then
                    USB_SPEED_LABEL="HighSpeed (USB 2.0, 480 Mbps)"
                    [[ -n "$USB_HUB_TYPE" ]] && USB_BOTTLENECK="true"
                else
                    USB_NOTE="USB Wi-Fi detected (driver=$drv); speed could not be parsed from lsusb -t."
                fi
            else
                USB_NOTE="USB Wi-Fi detected, but lsusb is not installed."
            fi
        else
            USB_NOTE="Wi-Fi adapter is not a USB device."
        fi
    fi

    WIFI_BAND="$(band_from_channel "${WIFI_CHANNEL:-0}")"
    WIFI_IS_DFS="$(is_dfs_channel "${WIFI_CHANNEL:-0}")"

    # VPN / Tunnel detection
    if command -v ip >/dev/null 2>&1; then
        local vpn_items=()
        while IFS= read -r iface; do
            [[ -z "$iface" ]] && continue
            vpn_items+=("{\"name\":\"$(json_escape "$iface")\",\"description\":\"Active tunnel interface\",\"status\":\"Up\"}")
        done < <(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -iE '^(wg|tun|tap|warp|tailscale|zt|ppp)' || true)
        if [[ ${#vpn_items[@]} -gt 0 ]]; then
            VPN_DETECTED="true"
            VPN_JSON="[$(IFS=,; printf '%s' "${vpn_items[*]}")]"
        fi
    fi

    # DNS servers via resolvectl or /etc/resolv.conf
    if command -v resolvectl >/dev/null 2>&1; then
        while IFS= read -r ns; do
            [[ -z "$ns" ]] && continue
            DNS_SERVERS+=("$ns")
        done < <(resolvectl dns 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '!seen[$0]++' | head -n 4 || true)
    fi
    if [[ ${#DNS_SERVERS[@]} -eq 0 && -r /etc/resolv.conf ]]; then
        while IFS= read -r ns; do
            [[ -z "$ns" ]] && continue
            DNS_SERVERS+=("$ns")
        done < <(awk '/^nameserver[ \t]+/{print $2}' /etc/resolv.conf | head -n 4 || true)
    fi
}

if [[ "$PLATFORM" == "macos" ]]; then
    collect_macos
else
    collect_linux
fi

# ============================================================================
# Strictly Sequential Idle Baseline Latency
# ============================================================================

GW_BASELINE_JSON="$(run_sequential_ping "$GATEWAY_IP" "$PING_COUNT")"
WAN_BASELINE_JSON="$(run_sequential_ping "$WAN_TARGET" "$PING_COUNT")"

# ============================================================================
# Uncached DNS Latency
# ============================================================================

measure_dns_server_json() {
    local label="$1"
    local server="$2"
    local masked_server
    masked_server="$(protect_ip "$server")"

    if ! command -v dig >/dev/null 2>&1; then
        printf '{"label":"%s","server":"%s","avg_ms":null,"min_ms":null,"max_ms":null,"status":"dig_missing"}' \
            "$(json_escape "$label")" "$(json_escape "$masked_server")"
        return
    fi

    local times_file="$TMP_DIR/dns_times.txt"
    : > "$times_file"
    local q
    for q in 1 2 3; do
        local qt
        qt="$(dig +time=2 +tries=1 +stats "@$server" "$DNS_TEST_DOMAIN" A 2>/dev/null | awk '/Query time:/{print $4; exit}' || true)"
        if [[ "$qt" =~ ^[0-9]+$ ]]; then
            printf '%s\n' "$qt" >> "$times_file"
        fi
        sleep 0.1
    done

    awk -v lbl="$label" -v srv="$masked_server" '
    BEGIN { n = 0; sum = 0; min = 1e9; max = 0 }
    /^[0-9]+$/ {
        v = $1 + 0; sum += v; n++
        if (v < min) min = v
        if (v > max) max = v
    }
    END {
        if (n == 0) {
            printf "{\"label\":\"%s\",\"server\":\"%s\",\"avg_ms\":null,\"min_ms\":null,\"max_ms\":null,\"status\":\"error\"}", lbl, srv
        } else {
            st = (n == 3) ? "ok" : "partial"
            printf "{\"label\":\"%s\",\"server\":\"%s\",\"avg_ms\":%.2f,\"min_ms\":%.2f,\"max_ms\":%.2f,\"status\":\"%s\"}", lbl, srv, sum/n, min, max, st
        }
    }' "$times_file"
}

DNS_RESULTS_ARR=()
if [[ ${#DNS_SERVERS[@]} -gt 0 ]]; then
    DNS_RESULTS_ARR+=("$(measure_dns_server_json "Current DNS" "${DNS_SERVERS[0]}")")
fi
DNS_RESULTS_ARR+=("$(measure_dns_server_json "Cloudflare" "1.1.1.1")")
DNS_RESULTS_ARR+=("$(measure_dns_server_json "Google" "8.8.8.8")")
if [[ -n "$GATEWAY_IP" ]]; then
    DNS_RESULTS_ARR+=("$(measure_dns_server_json "Gateway" "$GATEWAY_IP")")
fi
DNS_RESULTS_JSON="[$(IFS=,; printf '%s' "${DNS_RESULTS_ARR[*]}")]"

DNS_CONF_ARR=()
for ds in "${DNS_SERVERS[@]:-}"; do
    [[ -z "$ds" ]] && continue
    DNS_CONF_ARR+=("\"$(json_escape "$(protect_ip "$ds")")\"")
done
DNS_CONF_JSON="[$(IFS=,; printf '%s' "${DNS_CONF_ARR[*]}")]"

# ============================================================================
# Sequential Load Test & Bufferbloat (DL -> 2s drain -> UL)
# ============================================================================

extract_avg_ms() {
    printf '%s' "$1" | sed -nE 's/.*"avg_ms":([0-9]+(\.[0-9]+)?).*/\1/p'
}

calc_delta_json() {
    local loaded="$1"
    local idle="$2"
    if [[ -n "$loaded" && -n "$idle" ]]; then
        awk -v a="$loaded" -v b="$idle" 'BEGIN { printf "%.2f", a - b }'
    else
        printf 'null'
    fi
}

run_bg_ping() {
    local target="$1"
    local out_file="$2"
    : > "$out_file"
    if [[ -z "$target" ]]; then
        echo ""
        return
    fi
    if [[ "$PLATFORM" == "macos" ]]; then
        ping -i 0.2 "$target" > "$out_file" 2>/dev/null &
    else
        ping -i 0.2 "$target" > "$out_file" 2>/dev/null &
    fi
    echo $!
}

stop_bg_ping_stats() {
    local pid="$1"
    local raw_file="$2"
    if [[ -n "$pid" ]]; then
        kill -INT "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    local samples_file="$TMP_DIR/bg_samples.txt"
    sed -nE 's/.*time=([0-9]+(\.[0-9]+)?).*/\1/p' "$raw_file" > "$samples_file" 2>/dev/null || true
    local sent
    sent="$(grep -cE 'icmp_seq=|seq=' "$raw_file" 2>/dev/null || true)"
    local rec
    rec="$(wc -l < "$samples_file" | tr -d ' ')"
    (( sent < rec )) && sent="$rec"
    compute_ping_stats_json "$samples_file" "$sent"
}

LOAD_ERROR=""
LOAD_TEST_JSON='{"skipped":true,"tool":null,"load_error":null,"download":null,"upload":null}'

if [[ "$SKIP_LOAD" -eq 0 ]]; then
    BASE_GW_AVG="$(extract_avg_ms "$GW_BASELINE_JSON")"
    BASE_WAN_AVG="$(extract_avg_ms "$WAN_BASELINE_JSON")"
    LOAD_TOOL="curl + ping"
    NQ_SUMMARY=""

    # macOS native networkQuality -v (if available)
    if [[ "$PLATFORM" == "macos" ]] && command -v networkQuality >/dev/null 2>&1; then
        NQ_SUMMARY="$(networkQuality -v 2>/dev/null | tr '\n' ' ' | cut -c1-240 || true)"
        LOAD_TOOL="networkQuality + curl + ping"
    fi

    USE_IPERF3=0
    if [[ "$PLATFORM" == "linux" && -n "${IPERF3_SERVER:-}" ]] && command -v iperf3 >/dev/null 2>&1; then
        USE_IPERF3=1
    fi
    HAS_CURL=0
    if command -v curl >/dev/null 2>&1; then
        HAS_CURL=1
    fi

    if [[ "$USE_IPERF3" -eq 0 && "$HAS_CURL" -eq 0 ]]; then
        LOAD_ERROR="curl not installed; throughput/bufferbloat skipped"
        if [[ -n "$NQ_SUMMARY" ]]; then
            LOAD_TOOL="networkQuality"
        else
            LOAD_TOOL=""
        fi
        DL_MBPS="null"; UL_MBPS="null"
        DL_GW_BLOAT="null"; DL_WAN_BLOAT="null"
        UL_GW_BLOAT="null"; UL_WAN_BLOAT="null"
        LOAD_TEST_JSON="$(cat <<EOF
{
    "skipped": true,
    "tool": $(json_str_or_null "$LOAD_TOOL"),
    "load_error": "$(json_escape "$LOAD_ERROR")",
    "network_quality_note": $(json_str_or_null "$NQ_SUMMARY"),
    "download": null,
    "upload": null
  }
EOF
)"
    else
        # Phase 1: Download 100 MB (or iperf3 on Linux if IPERF3_SERVER is set)
        DL_GW_RAW="$TMP_DIR/dl_gw.txt"
        DL_WAN_RAW="$TMP_DIR/dl_wan.txt"
        PID_GW="$(run_bg_ping "$GATEWAY_IP" "$DL_GW_RAW")"
        PID_WAN="$(run_bg_ping "$WAN_TARGET" "$DL_WAN_RAW")"

        DL_BYTES=0; DL_SEC=0; DL_MBPS="null"
        if [[ "$USE_IPERF3" -eq 1 ]]; then
            LOAD_TOOL="iperf3 + ping"
            iperf_dl="$(iperf3 -c "$IPERF3_SERVER" -R -t 6 -J 2>/dev/null || true)"
            DL_MBPS="$(printf '%s' "$iperf_dl" | awk '/"bits_per_second"/{val=$2} END{gsub(/,/,"",val); if (val+0>0) printf "%.2f", (val+0)/1e6; else print "null"}')"
        elif [[ "$HAS_CURL" -eq 1 ]]; then
            curl_dl="$(curl -sS -L -o /dev/null -A "$UA" -H "Referer: $REFERER" --max-time 60 \
                -w '%{size_download}|%{time_total}' 'https://speed.cloudflare.com/__down?bytes=104857600' 2>/dev/null || true)"
            DL_BYTES="$(printf '%s' "$curl_dl" | cut -d'|' -f1)"
            DL_SEC="$(printf '%s' "$curl_dl" | cut -d'|' -f2)"
            if [[ "$DL_BYTES" =~ ^[0-9]+$ && "$DL_SEC" =~ ^[0-9]+(\.[0-9]+)?$ ]] && (( DL_BYTES > 0 )); then
                DL_MBPS="$(awk -v b="$DL_BYTES" -v s="$DL_SEC" 'BEGIN { if (s > 0) printf "%.2f", (b * 8.0 / s) / 1000000.0; else print "null" }')"
            fi
        fi

        DL_GW_STATS="$(stop_bg_ping_stats "$PID_GW" "$DL_GW_RAW")"
        DL_WAN_STATS="$(stop_bg_ping_stats "$PID_WAN" "$DL_WAN_RAW")"
        DL_GW_BLOAT="$(calc_delta_json "$(extract_avg_ms "$DL_GW_STATS")" "$BASE_GW_AVG")"
        DL_WAN_BLOAT="$(calc_delta_json "$(extract_avg_ms "$DL_WAN_STATS")" "$BASE_WAN_AVG")"

        # 2-second drain pause between Download and Upload phases
        sleep 2

        # Phase 2: Upload 25 MB in-memory stream
        UL_GW_RAW="$TMP_DIR/ul_gw.txt"
        UL_WAN_RAW="$TMP_DIR/ul_wan.txt"
        PID_GW="$(run_bg_ping "$GATEWAY_IP" "$UL_GW_RAW")"
        PID_WAN="$(run_bg_ping "$WAN_TARGET" "$UL_WAN_RAW")"

        UL_BYTES=26214400; UL_SEC=0; UL_MBPS="null"
        if [[ "$USE_IPERF3" -eq 1 ]]; then
            iperf_ul="$(iperf3 -c "$IPERF3_SERVER" -t 6 -J 2>/dev/null || true)"
            UL_MBPS="$(printf '%s' "$iperf_ul" | awk '/"bits_per_second"/{val=$2} END{gsub(/,/,"",val); if (val+0>0) printf "%.2f", (val+0)/1e6; else print "null"}')"
        elif [[ "$HAS_CURL" -eq 1 ]]; then
            curl_ul="$(head -c 26214400 /dev/zero | curl -sS -X POST -o /dev/null \
                -A "$UA" -H "Referer: $REFERER" -H "Content-Type: application/octet-stream" \
                --data-binary @- --max-time 60 \
                -w '%{size_upload}|%{time_total}' 'https://speed.cloudflare.com/__up' 2>/dev/null || true)"
            UL_BYTES="$(printf '%s' "$curl_ul" | cut -d'|' -f1)"
            UL_SEC="$(printf '%s' "$curl_ul" | cut -d'|' -f2)"
            if [[ "$UL_BYTES" =~ ^[0-9]+$ && "$UL_SEC" =~ ^[0-9]+(\.[0-9]+)?$ ]] && (( UL_BYTES > 0 )); then
                UL_MBPS="$(awk -v b="$UL_BYTES" -v s="$UL_SEC" 'BEGIN { if (s > 0) printf "%.2f", (b * 8.0 / s) / 1000000.0; else print "null" }')"
            fi
        fi

        UL_GW_STATS="$(stop_bg_ping_stats "$PID_GW" "$UL_GW_RAW")"
        UL_WAN_STATS="$(stop_bg_ping_stats "$PID_WAN" "$UL_WAN_RAW")"
        UL_GW_BLOAT="$(calc_delta_json "$(extract_avg_ms "$UL_GW_STATS")" "$BASE_GW_AVG")"
        UL_WAN_BLOAT="$(calc_delta_json "$(extract_avg_ms "$UL_WAN_STATS")" "$BASE_WAN_AVG")"

        LOAD_TEST_JSON="$(cat <<EOF
{
    "skipped": false,
    "tool": "$(json_escape "$LOAD_TOOL")",
    "load_error": $(json_str_or_null "$LOAD_ERROR"),
    "network_quality_note": $(json_str_or_null "$NQ_SUMMARY"),
    "download": {
      "bytes": $(json_num_or_null "$DL_BYTES"),
      "duration_sec": $(json_num_or_null "$DL_SEC"),
      "throughput_mbps": $(json_num_or_null "$DL_MBPS"),
      "gateway_latency": $DL_GW_STATS,
      "wan_latency": $DL_WAN_STATS,
      "gateway_bloat_ms": $(json_num_or_null "$DL_GW_BLOAT"),
      "wan_bloat_ms": $(json_num_or_null "$DL_WAN_BLOAT")
    },
    "upload": {
      "bytes": $(json_num_or_null "$UL_BYTES"),
      "duration_sec": $(json_num_or_null "$UL_SEC"),
      "throughput_mbps": $(json_num_or_null "$UL_MBPS"),
      "gateway_latency": $UL_GW_STATS,
      "wan_latency": $UL_WAN_STATS,
      "gateway_bloat_ms": $(json_num_or_null "$UL_GW_BLOAT"),
      "wan_bloat_ms": $(json_num_or_null "$UL_WAN_BLOAT")
    }
  }
EOF
)"
    fi
fi

# ============================================================================
# Assemble Canonical JSON & Render Output
# ============================================================================

MASKED_SSID="$(protect_ssid "$WIFI_RAW_SSID" 1)"
MASKED_BSSID="$(protect_mac "$WIFI_RAW_BSSID")"
MASKED_GW="$(protect_ip "$GATEWAY_IP")"
ANON_BOOL="$( [[ "$ANONYMIZE" -eq 1 ]] && echo true || echo false )"
RF_24_TOTAL=$((RF_24_CH1 + RF_24_CH6 + RF_24_CH11 + RF_24_OTHER))
RF_5_TOTAL=$((RF_5_NONDFS + RF_5_DFS + RF_5_UPPER))

REPORT_JSON="$(cat <<EOF
{
  "schema_version": "1.0.0",
  "timestamp_utc": "$TIMESTAMP_UTC",
  "platform": "$PLATFORM",
  "anonymized": $ANON_BOOL,
  "wifi_link": {
    "interface_name": $(json_str_or_null "$WIFI_IFACE"),
    "description": $(json_str_or_null "$WIFI_DESC"),
    "state": $(json_str_or_null "$WIFI_STATE"),
    "ssid": $(json_str_or_null "$MASKED_SSID"),
    "bssid": $(json_str_or_null "$MASKED_BSSID"),
    "band": $(json_str_or_null "$WIFI_BAND"),
    "channel": $(json_num_or_null "$WIFI_CHANNEL"),
    "is_dfs": $WIFI_IS_DFS,
    "radio_type": $(json_str_or_null "$WIFI_RADIO"),
    "signal_percent": $(json_num_or_null "$WIFI_SIGNAL"),
    "receive_rate_mbps": $(json_num_or_null "$WIFI_RX_RATE"),
    "transmit_rate_mbps": $(json_num_or_null "$WIFI_TX_RATE"),
    "interface_errors": {
      "packets_received_errors": $(json_num_or_null "$ERR_RX"),
      "packets_received_discarded": $(json_num_or_null "$ERR_RX_DISC"),
      "packets_outbound_errors": $(json_num_or_null "$ERR_TX"),
      "packets_outbound_discarded": $(json_num_or_null "$ERR_TX_DISC")
    }
  },
  "rf_scan": {
    "total_bssids": $RF_TOTAL,
    "band_2_4ghz": {
      "ch1": $RF_24_CH1,
      "ch6": $RF_24_CH6,
      "ch11": $RF_24_CH11,
      "other": $RF_24_OTHER,
      "total": $RF_24_TOTAL
    },
    "band_5ghz": {
      "non_dfs_36_48": $RF_5_NONDFS,
      "dfs_52_144": $RF_5_DFS,
      "upper_149_plus": $RF_5_UPPER,
      "total": $RF_5_TOTAL
    }
  },
  "usb_audit": {
    "applicable": $USB_APPLICABLE,
    "root_hub_type": $(json_str_or_null "$USB_HUB_TYPE"),
    "negotiated_speed_label": $(json_str_or_null "$USB_SPEED_LABEL"),
    "usb2_bottleneck_on_usb3_hub": $USB_BOTTLENECK,
    "note": $(json_str_or_null "$USB_NOTE")
  },
  "vpn_and_tunnel": {
    "detected": $VPN_DETECTED,
    "active_tunnels": $VPN_JSON
  },
  "baseline_latency": {
    "gateway_ip": $(json_str_or_null "$MASKED_GW"),
    "gateway": $GW_BASELINE_JSON,
    "wan_target": "$WAN_TARGET",
    "wan": $WAN_BASELINE_JSON
  },
  "dns_latency": {
    "test_domain": "$DNS_TEST_DOMAIN",
    "configured_servers": $DNS_CONF_JSON,
    "results": $DNS_RESULTS_JSON
  },
  "load_test": $LOAD_TEST_JSON
}
EOF
)"

emit_report() {
if [[ "$FORMAT" == "json" ]]; then
    printf '%s\n' "$REPORT_JSON"
else
    # Render clean Markdown directly (zero external dependencies)
    cat <<EOF
# Wi-Fi & Network Audit Report ($PLATFORM)

- **Timestamp (UTC):** $TIMESTAMP_UTC
- **Anonymized:** $ANON_BOOL

## 1. Active Wi-Fi Link

| Metric | Value |
| :--- | :--- |
| Interface | ${WIFI_IFACE:-N/A} |
| State | ${WIFI_STATE:-N/A} |
| SSID / BSSID | ${MASKED_SSID:-N/A} / \`${MASKED_BSSID:-N/A}\` |
| Band / Channel | ${WIFI_BAND} / Ch ${WIFI_CHANNEL:-N/A} (DFS: ${WIFI_IS_DFS}) |
| Radio / PHY | ${WIFI_RADIO:-N/A} |
| Signal | ${WIFI_SIGNAL:-N/A}% |
| Link Rate (RX / TX) | ${WIFI_RX_RATE:-N/A} Mbps / ${WIFI_TX_RATE:-N/A} Mbps |
| Interface Errors (RX / TX) | ${ERR_RX} / ${ERR_TX} |

## 2. RF Spectrum & Neighbor Congestion

- **Total BSSIDs scanned:** $RF_TOTAL
- **2.4 GHz competing APs:** Ch1=$RF_24_CH1, Ch6=$RF_24_CH6, Ch11=$RF_24_CH11, Other=$RF_24_OTHER (Total: $RF_24_TOTAL)
- **5 GHz competing APs:** Non-DFS 36-48=$RF_5_NONDFS, DFS 52-144=$RF_5_DFS, Upper 149+=$RF_5_UPPER (Total: $RF_5_TOTAL)

## 3. USB Adapter Check

- **USB Wi-Fi Applicable:** $USB_APPLICABLE
- **Root Hub / Speed:** ${USB_HUB_TYPE:-N/A} / ${USB_SPEED_LABEL:-N/A}
- **USB 2.0 Bottleneck on USB 3.0 Hub:** $USB_BOTTLENECK
- **Note:** ${USB_NOTE:-None}

## 4. VPN / Tunnels & Idle Baseline Latency (Sequential)

- **Active VPN / Tunnel detected:** $VPN_DETECTED
- **Gateway (\`${MASKED_GW:-N/A}\`):** \`$GW_BASELINE_JSON\`
- **WAN (\`$WAN_TARGET\`):** \`$WAN_BASELINE_JSON\`

## 5. Uncached DNS Latency

- **Results:** \`$DNS_RESULTS_JSON\`

## 6. Load Test & Bufferbloat (Sequential DL -> 2s Drain -> UL)

EOF
    if [[ "$SKIP_LOAD" -eq 1 ]]; then
        echo "_Skipped (\`--skip-load\`)._"
    elif [[ -n "${LOAD_ERROR:-}" ]]; then
        echo "_Skipped (${LOAD_ERROR})._"
    else
        cat <<EOF
- **Tool:** $LOAD_TOOL
- **Download:** ${DL_MBPS} Mbps (Gateway bloat: +${DL_GW_BLOAT} ms, WAN bloat: +${DL_WAN_BLOAT} ms)
- **Upload:** ${UL_MBPS} Mbps (Gateway bloat: +${UL_GW_BLOAT} ms, WAN bloat: +${UL_WAN_BLOAT} ms)
EOF
    fi
fi
}

if [[ -n "$OUT_FILE" ]]; then
    mkdir -p "$(dirname "$OUT_FILE")"
    emit_report > "$OUT_FILE"
else
    emit_report
fi
