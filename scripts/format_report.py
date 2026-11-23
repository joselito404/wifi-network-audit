#!/usr/bin/env python3
"""
wifi-network-audit: Report Anonymizer, Markdown Renderer & Before/After Comparator.

Uses Python 3 standard library only (no third-party dependencies).
Strictly read-only with respect to OS configuration.

License: MIT
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PRESERVED_PUBLIC_IPS = frozenset({
    "1.1.1.1", "1.0.0.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
})

MAC_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_REGEX = re.compile(
    r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])"
)


_PRESERVED_IPV4_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
)

_PRESERVED_IPV6_NETS = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
)


def _is_preserved_ip(ip_str: str) -> bool:
    """Return True for RFC1918 private, loopback, link-local, CGNAT, or well-known public DNS IPs."""
    if ip_str in PRESERVED_PUBLIC_IPS:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    if isinstance(ip_obj, ipaddress.IPv4Address):
        return any(ip_obj in net for net in _PRESERVED_IPV4_NETS)

    return any(ip_obj in net for net in _PRESERVED_IPV6_NETS)


class _AnonymizerState:
    """Deterministic per-run mapping so identical MACs/IPs/SSIDs map consistently."""

    def __init__(self) -> None:
        self.mac_map: Dict[str, str] = {}
        self.ip_map: Dict[str, str] = {}
        self.ssid_map: Dict[str, str] = {}

    def mask_mac(self, mac: str) -> str:
        norm = mac.strip().lower().replace("-", ":")
        if not norm or norm.startswith("xx:xx:xx:"):
            return mac
        if norm not in self.mac_map:
            idx = len(self.mac_map) + 1
            self.mac_map[norm] = f"xx:xx:xx:xx:xx:{idx % 256:02x}"
        return self.mac_map[norm]

    def mask_ip(self, ip_str: str) -> str:
        cleaned = ip_str.strip()
        if not cleaned or cleaned.startswith("[PUBLIC_IP_"):
            return ip_str
        if _is_preserved_ip(cleaned):
            return cleaned
        if cleaned not in self.ip_map:
            idx = len(self.ip_map) + 1
            self.ip_map[cleaned] = f"[PUBLIC_IP_{idx:02d}]"
        return self.ip_map[cleaned]

    def mask_ssid(self, ssid: str, is_own: bool = False) -> str:
        if not ssid or ssid in ("<hidden>", "Own_WiFi") or re.match(r"^Neighbor_\d+$", ssid):
            return ssid
        if is_own:
            return "Own_WiFi"
        if ssid not in self.ssid_map:
            idx = len(self.ssid_map) + 1
            self.ssid_map[ssid] = f"Neighbor_{idx:02d}"
        return self.ssid_map[ssid]

    def mask_text(self, text: str) -> str:
        if not text:
            return text
        out = MAC_REGEX.sub(lambda m: self.mask_mac(m.group(0)), text)
        out = IPV4_REGEX.sub(lambda m: self.mask_ip(m.group(0)), out)
        out = IPV6_REGEX.sub(lambda m: self.mask_ip(m.group(0)), out)
        return out


def anonymize_text(text: str) -> str:
    """Mask MAC addresses and public IPs in raw text while preserving private/well-known DNS IPs."""
    state = _AnonymizerState()
    return state.mask_text(text)


def anonymize_report(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deep-copied, deterministically anonymized audit report dictionary."""
    report = copy.deepcopy(data)
    state = _AnonymizerState()

    wifi = report.get("wifi_link")
    own_ssid_raw: Optional[str] = None
    if isinstance(wifi, dict):
        if isinstance(wifi.get("ssid"), str):
            own_ssid_raw = wifi["ssid"]
            wifi["ssid"] = state.mask_ssid(wifi["ssid"], is_own=True)
        if isinstance(wifi.get("bssid"), str):
            wifi["bssid"] = state.mask_mac(wifi["bssid"])

    rf = report.get("rf_scan")
    if isinstance(rf, dict) and isinstance(rf.get("networks"), list):
        for net in rf["networks"]:
            if not isinstance(net, dict):
                continue
            is_own = bool(net.get("is_own")) or (
                own_ssid_raw is not None and net.get("ssid") == own_ssid_raw
            )
            if isinstance(net.get("ssid"), str):
                net["ssid"] = state.mask_ssid(net["ssid"], is_own=is_own)
            if isinstance(net.get("bssid"), str):
                net["bssid"] = state.mask_mac(net["bssid"])

    usb = report.get("usb_audit")
    if isinstance(usb, dict):
        ssid_field_re = re.compile(
            r"(?i)((?:Nombre de perfil|Nombre de red|SSID de red|Network SSID|Profile Name|Network Name|SSID)\s*:\s*)([^\r\n,;]+)"
        )

        def _mask_usb_text(val: str) -> str:
            masked = state.mask_text(val)
            if own_ssid_raw and own_ssid_raw not in ("<hidden>", "Own_WiFi"):
                masked = re.sub(re.escape(own_ssid_raw), "Own_WiFi", masked, flags=re.IGNORECASE)
            masked = ssid_field_re.sub(r"\1[REDACTED_SSID]", masked)
            return masked

        if isinstance(usb.get("note"), str):
            usb["note"] = _mask_usb_text(usb["note"])
        if isinstance(usb.get("wlan_events_recent"), list):
            for ev in usb["wlan_events_recent"]:
                if isinstance(ev, dict) and isinstance(ev.get("message"), str):
                    ev["message"] = _mask_usb_text(ev["message"])

    baseline = report.get("baseline_latency")
    if isinstance(baseline, dict):
        if isinstance(baseline.get("gateway_ip"), str):
            baseline["gateway_ip"] = state.mask_ip(baseline["gateway_ip"])
        if isinstance(baseline.get("wan_target"), str):
            baseline["wan_target"] = state.mask_ip(baseline["wan_target"])

    dns = report.get("dns_latency")
    if isinstance(dns, dict):
        if isinstance(dns.get("configured_servers"), list):
            dns["configured_servers"] = [
                state.mask_ip(s) if isinstance(s, str) else s
                for s in dns["configured_servers"]
            ]
        if isinstance(dns.get("results"), list):
            for row in dns["results"]:
                if isinstance(row, dict) and isinstance(row.get("server"), str):
                    row["server"] = state.mask_ip(row["server"])

    report["anonymized"] = True
    return report


def _fmt(val: Any, suffix: str = "") -> str:
    if val is None or val == "":
        return "N/A"
    return f"{val}{suffix}"


def _fmt_delta(val: Any, suffix: str = " ms") -> str:
    if val is None:
        return "N/A"
    try:
        num = float(val)
        sign = "+" if num >= 0 else ""
        return f"{sign}{num:.2f}{suffix}"
    except (TypeError, ValueError):
        return str(val)


def _extract_findings(data: Dict[str, Any]) -> List[str]:
    """Generate concise automated diagnostic flags from structured report metrics."""
    flags: List[str] = []
    wifi = data.get("wifi_link") or {}
    usb = data.get("usb_audit") or {}
    vpn = data.get("vpn_and_tunnel") or {}
    base = data.get("baseline_latency") or {}
    load = data.get("load_test") or {}

    if wifi.get("is_dfs"):
        flags.append(
            f"**DFS Channel Active (Ch {wifi.get('channel')}):** Potential radar-induced channel switches or brief disconnects."
        )
    if wifi.get("band") == "2.4 GHz":
        flags.append(
            "**Connected on 2.4 GHz:** Higher interference and lower throughput than 5 GHz / 6 GHz."
        )
    sig = wifi.get("signal_percent")
    if isinstance(sig, (int, float)) and sig < 60:
        flags.append(f"**Weak Wi-Fi Signal ({sig}%):** Consider repositioning AP/antennas or reducing obstacles.")

    if usb.get("usb2_bottleneck_on_usb3_hub"):
        flags.append(
            "**USB 2.0 Bottleneck on USB 3.0 Root Hub:** Dongle negotiated 480 Mbps on a USB 3.0 port (check cable/port seating or chipset limits)."
        )
    if usb.get("applicable") and usb.get("selective_suspend_ac") == "Enabled":
        flags.append(
            "**USB Selective Suspend Enabled (AC):** Can cause periodic Wi-Fi USB adapter stalls or disconnects."
        )
    events = usb.get("wlan_events_recent") or []
    if len(events) > 0:
        flags.append(
            f"**Recent WLAN AutoConfig Events (8003/11004):** {len(events)} disconnect/roam event(s) logged."
        )

    if vpn.get("detected"):
        flags.append(
            "**Active VPN/Tunnel Detected:** Latency and throughput reflect encrypted tunnel overhead."
        )

    gw_base = base.get("gateway") or {}
    if isinstance(gw_base.get("loss_pct"), (int, float)) and gw_base["loss_pct"] > 0:
        flags.append(
            f"**Idle Packet Loss to Gateway ({gw_base['loss_pct']}%):** Indicates local Wi-Fi link instability."
        )

    if not load.get("skipped"):
        for phase in ("download", "upload"):
            ph = load.get(phase) or {}
            gw_b = ph.get("gateway_bloat_ms")
            wan_b = ph.get("wan_bloat_ms")
            if isinstance(gw_b, (int, float)) and gw_b >= 30:
                flags.append(
                    f"**First-Hop ({phase.title()}) Bufferbloat (+{gw_b:.1f} ms to gateway):** Local Wi-Fi/router queuing under load."
                )
            elif isinstance(wan_b, (int, float)) and wan_b >= 50:
                flags.append(
                    f"**WAN ({phase.title()}) Bufferbloat (+{wan_b:.1f} ms to WAN):** ISP/router WAN queue buildup (SQM candidate)."
                )

    return flags


def render_markdown(data: Dict[str, Any]) -> str:
    """Render a canonical audit report dictionary as a clean Markdown document."""
    lines: List[str] = []
    platform = data.get("platform", "unknown")
    lines.append(f"# Wi-Fi & Network Audit Report ({platform})")
    lines.append("")
    lines.append(f"- **Timestamp (UTC):** {_fmt(data.get('timestamp_utc'))}")
    lines.append(f"- **Schema Version:** {_fmt(data.get('schema_version'))}")
    lines.append(f"- **Anonymized:** {bool(data.get('anonymized'))}")
    lines.append("")

    # Automated Findings
    findings = _extract_findings(data)
    if findings:
        lines.append("## Key Findings")
        lines.append("")
        for f in findings:
            lines.append(f"- {f}")
        lines.append("")

    # 1. Wi-Fi Link
    w = data.get("wifi_link") or {}
    err = w.get("interface_errors") or {}
    lines.append("## 1. Active Wi-Fi Link")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| Interface | {_fmt(w.get('interface_name'))} |")
    lines.append(f"| Adapter | {_fmt(w.get('description'))} |")
    lines.append(f"| State | {_fmt(w.get('state'))} |")
    lines.append(f"| SSID / BSSID | {_fmt(w.get('ssid'))} / `{_fmt(w.get('bssid'))}` |")
    lines.append(
        f"| Band / Channel | {_fmt(w.get('band'))} / Ch {_fmt(w.get('channel'))} (DFS: {bool(w.get('is_dfs'))}) |"
    )
    lines.append(f"| Radio / PHY | {_fmt(w.get('radio_type'))} |")
    lines.append(f"| Signal | {_fmt(w.get('signal_percent'), '%')} |")
    lines.append(
        f"| Link Rate (RX / TX) | {_fmt(w.get('receive_rate_mbps'), ' Mbps')} / {_fmt(w.get('transmit_rate_mbps'), ' Mbps')} |"
    )
    lines.append(
        f"| Interface Errors (RX / TX) | {_fmt(err.get('packets_received_errors'))} / {_fmt(err.get('packets_outbound_errors'))} "
        f"(Discards: {_fmt(err.get('packets_received_discarded'))}/{_fmt(err.get('packets_outbound_discarded'))}) |"
    )
    lines.append("")

    # 2. RF Scan
    rf = data.get("rf_scan") or {}
    b24 = rf.get("band_2_4ghz") or {}
    b5 = rf.get("band_5ghz") or {}
    lines.append("## 2. RF Spectrum & Neighbor Congestion")
    lines.append("")
    lines.append(f"- **Total BSSIDs scanned:** {_fmt(rf.get('total_bssids'))}")
    lines.append(
        f"- **2.4 GHz competing APs:** Ch1={_fmt(b24.get('ch1'))}, Ch6={_fmt(b24.get('ch6'))}, "
        f"Ch11={_fmt(b24.get('ch11'))}, Other={_fmt(b24.get('other'))} (Total: {_fmt(b24.get('total'))})"
    )
    lines.append(
        f"- **5 GHz competing APs:** Non-DFS 36-48={_fmt(b5.get('non_dfs_36_48'))}, "
        f"DFS 52-144={_fmt(b5.get('dfs_52_144'))}, Upper 149+={_fmt(b5.get('upper_149_plus'))} (Total: {_fmt(b5.get('total'))})"
    )
    lines.append("")

    # 3. USB & Power / Events
    u = data.get("usb_audit") or {}
    lines.append("## 3. USB Adapter, Power & WLAN Events")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| USB Adapter Applicable | {bool(u.get('applicable'))} |")
    lines.append(f"| Root Hub Type | {_fmt(u.get('root_hub_type'))} |")
    lines.append(
        f"| bcdUSB / Negotiated Speed | {_fmt(u.get('bcd_usb'))} / {_fmt(u.get('negotiated_speed_label'))} |"
    )
    lines.append(f"| USB 2.0 Bottleneck on USB 3.0 Hub | {bool(u.get('usb2_bottleneck_on_usb3_hub'))} |")
    if "selective_suspend_ac" in u or "selective_suspend_dc" in u:
        lines.append(
            f"| USB Selective Suspend (AC / DC) | {_fmt(u.get('selective_suspend_ac'))} / {_fmt(u.get('selective_suspend_dc'))} |"
        )
    if "wlan_events_recent" in u:
        lines.append(f"| Recent WLAN Events (8003/11004) | {len(u.get('wlan_events_recent') or [])} |")
    if u.get("note"):
        lines.append(f"| Note | {u['note']} |")
    lines.append("")

    # 4. VPN & Idle Baseline Latency
    v = data.get("vpn_and_tunnel") or {}
    b = data.get("baseline_latency") or {}
    gw = b.get("gateway") or {}
    wan = b.get("wan") or {}
    lines.append("## 4. VPN / Tunnels & Idle Baseline Latency (Sequential)")
    lines.append("")
    lines.append(f"- **Active VPN / Tunnel detected:** {bool(v.get('detected'))}")
    lines.append("")
    lines.append("| Target | Sent / Recv | Loss % | Min (ms) | Avg (ms) | P95 (ms) | Max (ms) |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
    lines.append(
        f"| Gateway (`{_fmt(b.get('gateway_ip'))}`) | {_fmt(gw.get('sent'))}/{_fmt(gw.get('received'))} | "
        f"{_fmt(gw.get('loss_pct'), '%')} | {_fmt(gw.get('min_ms'))} | {_fmt(gw.get('avg_ms'))} | "
        f"{_fmt(gw.get('p95_ms'))} | {_fmt(gw.get('max_ms'))} |"
    )
    lines.append(
        f"| WAN (`{_fmt(b.get('wan_target'))}`) | {_fmt(wan.get('sent'))}/{_fmt(wan.get('received'))} | "
        f"{_fmt(wan.get('loss_pct'), '%')} | {_fmt(wan.get('min_ms'))} | {_fmt(wan.get('avg_ms'))} | "
        f"{_fmt(wan.get('p95_ms'))} | {_fmt(wan.get('max_ms'))} |"
    )
    lines.append("")

    # 5. DNS Latency
    d = data.get("dns_latency") or {}
    lines.append("## 5. Uncached DNS Latency")
    lines.append("")
    lines.append("| Resolver | Server | Min (ms) | Avg (ms) | Max (ms) | Status |")
    lines.append("| :--- | :--- | :---: | :---: | :---: | :---: |")
    for r in d.get("results") or []:
        lines.append(
            f"| {_fmt(r.get('label'))} | `{_fmt(r.get('server'))}` | {_fmt(r.get('min_ms'))} | "
            f"{_fmt(r.get('avg_ms'))} | {_fmt(r.get('max_ms'))} | {_fmt(r.get('status'))} |"
        )
    lines.append("")

    # 6. Load Test & Bufferbloat
    lt = data.get("load_test") or {}
    lines.append("## 6. Load Test & Bufferbloat (Sequential DL -> 2s Drain -> UL)")
    lines.append("")
    if lt.get("skipped"):
        lines.append("_Skipped._")
    else:
        dl = lt.get("download") or {}
        ul = lt.get("upload") or {}
        dl_gw = dl.get("gateway_latency") or {}
        dl_wan = dl.get("wan_latency") or {}
        ul_gw = ul.get("gateway_latency") or {}
        ul_wan = ul.get("wan_latency") or {}
        lines.append("| Phase | Throughput | Gateway Avg (Bloat) | WAN Avg (Bloat) | Gateway Loss | WAN Loss |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: |")
        lines.append(
            f"| Download | {_fmt(dl.get('throughput_mbps'), ' Mbps')} | "
            f"{_fmt(dl_gw.get('avg_ms'), ' ms')} ({_fmt_delta(dl.get('gateway_bloat_ms'))}) | "
            f"{_fmt(dl_wan.get('avg_ms'), ' ms')} ({_fmt_delta(dl.get('wan_bloat_ms'))}) | "
            f"{_fmt(dl_gw.get('loss_pct'), '%')} | {_fmt(dl_wan.get('loss_pct'), '%')} |"
        )
        lines.append(
            f"| Upload | {_fmt(ul.get('throughput_mbps'), ' Mbps')} | "
            f"{_fmt(ul_gw.get('avg_ms'), ' ms')} ({_fmt_delta(ul.get('gateway_bloat_ms'))}) | "
            f"{_fmt(ul_wan.get('avg_ms'), ' ms')} ({_fmt_delta(ul.get('wan_bloat_ms'))}) | "
            f"{_fmt(ul_gw.get('loss_pct'), '%')} | {_fmt(ul_wan.get('loss_pct'), '%')} |"
        )
    lines.append("")
    return "\n".join(lines)


def _get_nested(data: Dict[str, Any], path: Tuple[str, ...]) -> Any:
    curr: Any = data
    for key in path:
        if not isinstance(curr, dict):
            return None
        curr = curr.get(key)
    return curr


def _dns_avg_by_label(data: Dict[str, Any], label: str) -> Optional[float]:
    results = _get_nested(data, ("dns_latency", "results")) or []
    for row in results:
        if isinstance(row, dict) and row.get("label") == label:
            val = row.get("avg_ms")
            if isinstance(val, (int, float)):
                return float(val)
    return None


def _format_diff_cell(before_val: Any, after_val: Any, unit: str, higher_is_better: Optional[bool]) -> str:
    if before_val is None or after_val is None:
        return "N/A"
    if (
        isinstance(before_val, (int, float))
        and isinstance(after_val, (int, float))
        and not isinstance(before_val, bool)
        and not isinstance(after_val, bool)
    ):
        delta = float(after_val) - float(before_val)
        if abs(delta) < 1e-6:
            return f"0{unit} (unchanged)"
        sign = "+" if delta > 0 else ""
        tag = ""
        if higher_is_better is True:
            tag = " (better)" if delta > 0 else " (worse)"
        elif higher_is_better is False:
            tag = " (better)" if delta < 0 else " (worse)"
        return f"{sign}{delta:.2f}{unit}{tag}"
    if before_val == after_val:
        return "unchanged"
    return "changed"


def compare_reports(before: Dict[str, Any], after: Dict[str, Any]) -> str:
    """Generate a Before vs After Markdown comparison table from two audit report dicts."""
    rows: List[Tuple[str, Any, Any, str, Optional[bool]]] = [
        (
            "Wi-Fi Band / Channel",
            f"{_fmt(_get_nested(before, ('wifi_link', 'band')))} / Ch {_fmt(_get_nested(before, ('wifi_link', 'channel')))}",
            f"{_fmt(_get_nested(after, ('wifi_link', 'band')))} / Ch {_fmt(_get_nested(after, ('wifi_link', 'channel')))}",
            "",
            None,
        ),
        (
            "DFS Channel",
            _get_nested(before, ("wifi_link", "is_dfs")),
            _get_nested(after, ("wifi_link", "is_dfs")),
            "",
            None,
        ),
        (
            "Wi-Fi Signal",
            _get_nested(before, ("wifi_link", "signal_percent")),
            _get_nested(after, ("wifi_link", "signal_percent")),
            "%",
            True,
        ),
        (
            "Link Rate RX",
            _get_nested(before, ("wifi_link", "receive_rate_mbps")),
            _get_nested(after, ("wifi_link", "receive_rate_mbps")),
            " Mbps",
            True,
        ),
        (
            "Link Rate TX",
            _get_nested(before, ("wifi_link", "transmit_rate_mbps")),
            _get_nested(after, ("wifi_link", "transmit_rate_mbps")),
            " Mbps",
            True,
        ),
        (
            "USB 2.0 Bottleneck",
            _get_nested(before, ("usb_audit", "usb2_bottleneck_on_usb3_hub")),
            _get_nested(after, ("usb_audit", "usb2_bottleneck_on_usb3_hub")),
            "",
            None,
        ),
        (
            "Idle Gateway Avg Latency",
            _get_nested(before, ("baseline_latency", "gateway", "avg_ms")),
            _get_nested(after, ("baseline_latency", "gateway", "avg_ms")),
            " ms",
            False,
        ),
        (
            "Idle Gateway P95 Latency",
            _get_nested(before, ("baseline_latency", "gateway", "p95_ms")),
            _get_nested(after, ("baseline_latency", "gateway", "p95_ms")),
            " ms",
            False,
        ),
        (
            "Idle Gateway Loss",
            _get_nested(before, ("baseline_latency", "gateway", "loss_pct")),
            _get_nested(after, ("baseline_latency", "gateway", "loss_pct")),
            "%",
            False,
        ),
        (
            "Idle WAN Avg Latency",
            _get_nested(before, ("baseline_latency", "wan", "avg_ms")),
            _get_nested(after, ("baseline_latency", "wan", "avg_ms")),
            " ms",
            False,
        ),
        (
            "Idle WAN P95 Latency",
            _get_nested(before, ("baseline_latency", "wan", "p95_ms")),
            _get_nested(after, ("baseline_latency", "wan", "p95_ms")),
            " ms",
            False,
        ),
        (
            "Current DNS Avg Latency",
            _dns_avg_by_label(before, "Current DNS"),
            _dns_avg_by_label(after, "Current DNS"),
            " ms",
            False,
        ),
        (
            "Download Throughput",
            _get_nested(before, ("load_test", "download", "throughput_mbps")),
            _get_nested(after, ("load_test", "download", "throughput_mbps")),
            " Mbps",
            True,
        ),
        (
            "Download Gateway Bloat",
            _get_nested(before, ("load_test", "download", "gateway_bloat_ms")),
            _get_nested(after, ("load_test", "download", "gateway_bloat_ms")),
            " ms",
            False,
        ),
        (
            "Download WAN Bloat",
            _get_nested(before, ("load_test", "download", "wan_bloat_ms")),
            _get_nested(after, ("load_test", "download", "wan_bloat_ms")),
            " ms",
            False,
        ),
        (
            "Upload Throughput",
            _get_nested(before, ("load_test", "upload", "throughput_mbps")),
            _get_nested(after, ("load_test", "upload", "throughput_mbps")),
            " Mbps",
            True,
        ),
        (
            "Upload Gateway Bloat",
            _get_nested(before, ("load_test", "upload", "gateway_bloat_ms")),
            _get_nested(after, ("load_test", "upload", "gateway_bloat_ms")),
            " ms",
            False,
        ),
        (
            "Upload WAN Bloat",
            _get_nested(before, ("load_test", "upload", "wan_bloat_ms")),
            _get_nested(after, ("load_test", "upload", "wan_bloat_ms")),
            " ms",
            False,
        ),
    ]

    lines = [
        "# Wi-Fi & Network Audit Comparison (Before vs After)",
        "",
        f"- **Before (UTC):** {_fmt(before.get('timestamp_utc'))}",
        f"- **After (UTC):** {_fmt(after.get('timestamp_utc'))}",
        "",
        "| Metric | Before | After | Delta |",
        "| :--- | :---: | :---: | :---: |",
    ]

    for label, b_val, a_val, unit, hib in rows:
        b_is_num = isinstance(b_val, (int, float)) and not isinstance(b_val, bool)
        a_is_num = isinstance(a_val, (int, float)) and not isinstance(a_val, bool)
        b_str = _fmt(b_val, unit if b_is_num else "")
        a_str = _fmt(a_val, unit if a_is_num else "")
        d_str = _format_diff_cell(b_val, a_val, unit, hib)
        lines.append(f"| {label} | {b_str} | {a_str} | {d_str} |")

    lines.append("")
    return "\n".join(lines)


def _read_text(path: Optional[str]) -> str:
    if path and path != "-":
        return Path(path).read_text(encoding="utf-8-sig")
    return sys.stdin.read()


def _write_text(content: str, output_path: Optional[str]) -> None:
    if output_path and output_path != "-":
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="format_report.py",
        description="Anonymize, render, or compare wifi-network-audit JSON reports.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_anon = sub.add_parser("anonymize", help="Anonymize a JSON report or raw text.")
    p_anon.add_argument("input", nargs="?", default="-", help="Input file path (default: stdin).")
    p_anon.add_argument("-o", "--output", "--out", dest="output", default="-", help="Output file path (default: stdout).")
    p_anon.add_argument(
        "--text",
        action="store_true",
        help="Treat input as raw text instead of structured JSON.",
    )

    p_render = sub.add_parser("render", help="Render a JSON report to Markdown.")
    p_render.add_argument("input", nargs="?", default="-", help="Input JSON path (default: stdin).")
    p_render.add_argument("-o", "--output", "--out", dest="output", default="-", help="Output Markdown path (default: stdout).")
    p_render.add_argument(
        "--anonymize",
        action="store_true",
        help="Anonymize the report before rendering Markdown.",
    )

    p_cmp = sub.add_parser("compare", help="Generate a Before vs After Markdown comparison table.")
    p_cmp.add_argument("before", help="Path to before.json report.")
    p_cmp.add_argument("after", help="Path to after.json report.")
    p_cmp.add_argument("-o", "--output", "--out", dest="output", default="-", help="Output Markdown path (default: stdout).")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "anonymize":
        raw = _read_text(args.input)
        if args.text:
            _write_text(anonymize_text(raw), args.output)
        else:
            data = json.loads(raw)
            out = json.dumps(anonymize_report(data), indent=2, ensure_ascii=False)
            _write_text(out, args.output)
        return 0

    if args.command == "render":
        data = json.loads(_read_text(args.input))
        if args.anonymize:
            data = anonymize_report(data)
        _write_text(render_markdown(data), args.output)
        return 0

    if args.command == "compare":
        before = json.loads(_read_text(args.before))
        after = json.loads(_read_text(args.after))
        _write_text(compare_reports(before, after), args.output)
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
