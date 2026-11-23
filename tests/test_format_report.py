"""Unit and CLI tests for scripts/format_report.py (Python stdlib unittest only)."""

from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import format_report  # noqa: E402


def _sample_report(
    *,
    band: str = "5 GHz",
    channel: int = 52,
    is_dfs: bool = True,
    signal: int = 55,
    rx_mbps: float = 300.0,
    tx_mbps: float = 240.0,
    usb2_bottleneck: bool = True,
    selective_suspend: str = "Enabled",
    vpn_detected: bool = True,
    gw_avg: float = 12.5,
    gw_p95: float = 28.0,
    gw_loss: float = 2.0,
    wan_avg: float = 25.0,
    wan_p95: float = 42.0,
    dns_avg: float = 38.0,
    skip_load: bool = False,
    dl_mbps: float = 180.0,
    dl_gw_bloat: float = 45.0,
    dl_wan_bloat: float = 60.0,
    ul_mbps: float = 90.0,
    ul_gw_bloat: float = 15.0,
    ul_wan_bloat: float = 75.0,
    timestamp: str = "2026-01-01T10:00:00Z",
) -> Dict[str, Any]:
    load_test: Dict[str, Any]
    if skip_load:
        load_test = {
            "skipped": True,
            "tool": None,
            "download": None,
            "upload": None,
        }
    else:
        load_test = {
            "skipped": False,
            "tool": "curl",
            "download": {
                "throughput_mbps": dl_mbps,
                "gateway_bloat_ms": dl_gw_bloat,
                "wan_bloat_ms": dl_wan_bloat,
                "gateway_latency": {"avg_ms": gw_avg + dl_gw_bloat, "loss_pct": 0.0},
                "wan_latency": {"avg_ms": wan_avg + dl_wan_bloat, "loss_pct": 0.0},
            },
            "upload": {
                "throughput_mbps": ul_mbps,
                "gateway_bloat_ms": ul_gw_bloat,
                "wan_bloat_ms": ul_wan_bloat,
                "gateway_latency": {"avg_ms": gw_avg + ul_gw_bloat, "loss_pct": 0.0},
                "wan_latency": {"avg_ms": wan_avg + ul_wan_bloat, "loss_pct": 0.0},
            },
        }

    return {
        "schema_version": "1.0.0",
        "timestamp_utc": timestamp,
        "platform": "windows",
        "anonymized": False,
        "wifi_link": {
            "interface_name": "Wi-Fi",
            "description": "Example USB Wi-Fi 6 Adapter",
            "state": "connected",
            "ssid": "MyHomeSSID_5G",
            "bssid": "AA:BB:CC:11:22:33",
            "band": band,
            "channel": channel,
            "is_dfs": is_dfs,
            "radio_type": "802.11ax",
            "signal_percent": signal,
            "receive_rate_mbps": rx_mbps,
            "transmit_rate_mbps": tx_mbps,
            "interface_errors": {
                "packets_received_errors": 1,
                "packets_outbound_errors": 0,
                "packets_received_discarded": 2,
                "packets_outbound_discarded": 0,
            },
        },
        "rf_scan": {
            "total_bssids": 4,
            "band_2_4ghz": {"ch1": 1, "ch6": 1, "ch11": 0, "other": 0, "total": 2},
            "band_5ghz": {"non_dfs_36_48": 1, "dfs_52_144": 1, "upper_149_plus": 0, "total": 2},
            "networks": [
                {"ssid": "MyHomeSSID_5G", "bssid": "aa-bb-cc-11-22-33", "is_own": True},
                {"ssid": "NeighborAlpha", "bssid": "11:22:33:44:55:66", "is_own": False},
                {"ssid": "NeighborBeta", "bssid": "22:33:44:55:66:77", "is_own": False},
                {"ssid": "<hidden>", "bssid": "33:44:55:66:77:88", "is_own": False},
            ],
        },
        "usb_audit": {
            "applicable": True,
            "root_hub_type": "USB 3.0 Root Hub",
            "bcd_usb": "0x0210",
            "negotiated_speed_label": "High-Speed (480 Mbps)",
            "usb2_bottleneck_on_usb3_hub": usb2_bottleneck,
            "selective_suspend_ac": selective_suspend,
            "selective_suspend_dc": "Enabled",
            "wlan_events_recent": [
                {
                    "id": 8003,
                    "message": "Disconnected from aa:bb:cc:11:22:33 via ISP 203.0.113.45",
                },
                {
                    "id": 11004,
                    "message": "SSID de red: PastPrivateNet_5G\nNetwork SSID: OtherPrivateNet",
                },
            ],
            "note": "Adapter MAC AA-BB-CC-11-22-33 on gateway 192.168.1.1 and WAN 198.51.100.9",
        },
        "vpn_and_tunnel": {"detected": vpn_detected},
        "baseline_latency": {
            "gateway_ip": "192.168.1.1",
            "gateway": {
                "sent": 20,
                "received": 19,
                "loss_pct": gw_loss,
                "min_ms": 2.0,
                "avg_ms": gw_avg,
                "p95_ms": gw_p95,
                "max_ms": 35.0,
            },
            "wan_target": "1.1.1.1",
            "wan": {
                "sent": 20,
                "received": 20,
                "loss_pct": 0.0,
                "min_ms": 18.0,
                "avg_ms": wan_avg,
                "p95_ms": wan_p95,
                "max_ms": 50.0,
            },
        },
        "dns_latency": {
            "configured_servers": ["192.168.1.1", "203.0.113.53", "1.1.1.1"],
            "results": [
                {
                    "label": "Current DNS",
                    "server": "203.0.113.53",
                    "min_ms": 30.0,
                    "avg_ms": dns_avg,
                    "max_ms": 48.0,
                    "status": "ok",
                },
                {
                    "label": "Cloudflare",
                    "server": "1.1.1.1",
                    "min_ms": 12.0,
                    "avg_ms": 14.0,
                    "max_ms": 18.0,
                    "status": "ok",
                },
            ],
        },
        "load_test": load_test,
    }


class TestAnonymizeText(unittest.TestCase):
    def test_masks_macs_deterministically_and_case_insensitively(self) -> None:
        raw = "AP1 AA:BB:CC:DD:EE:FF, AP2 11-22-33-44-55-66, again aa-bb-cc-dd-ee-ff"
        out = format_report.anonymize_text(raw)
        self.assertNotIn("AA:BB:CC:DD:EE:FF", out)
        self.assertNotIn("11-22-33-44-55-66", out)
        self.assertIn("AP1 xx:xx:xx:xx:xx:01", out)
        self.assertIn("AP2 xx:xx:xx:xx:xx:02", out)
        self.assertIn("again xx:xx:xx:xx:xx:01", out)

    def test_masks_public_ips_and_preserves_private_and_well_known_dns(self) -> None:
        raw = (
            "GW 192.168.1.1, LAN 10.0.0.5, CORP 172.16.0.9, LOOP 127.0.0.1, "
            "LL 169.254.10.20, CGNAT 100.64.1.2, CF 1.1.1.1, G 8.8.8.8, Q9 9.9.9.9, "
            "ISP1 203.0.113.10, ISP2 198.51.100.20, ISP1_AGAIN 203.0.113.10"
        )
        out = format_report.anonymize_text(raw)
        for preserved in (
            "192.168.1.1",
            "10.0.0.5",
            "172.16.0.9",
            "127.0.0.1",
            "169.254.10.20",
            "100.64.1.2",
            "1.1.1.1",
            "8.8.8.8",
            "9.9.9.9",
        ):
            self.assertIn(preserved, out)
        self.assertNotIn("203.0.113.10", out)
        self.assertNotIn("198.51.100.20", out)
        self.assertIn("ISP1 [PUBLIC_IP_01]", out)
        self.assertIn("ISP2 [PUBLIC_IP_02]", out)
        self.assertIn("ISP1_AGAIN [PUBLIC_IP_01]", out)

    def test_masks_public_ipv6_and_preserves_local_ipv6(self) -> None:
        raw = "local fe80::1 ula fd12:3456:789a::1 pub 2001:db8:85a3:0:0:8a2e:370:7334"
        out = format_report.anonymize_text(raw)
        self.assertIn("fe80::1", out)
        self.assertIn("fd12:3456:789a::1", out)
        self.assertNotIn("2001:db8:85a3", out)
        self.assertIn("[PUBLIC_IP_01]", out)

    def test_idempotent_and_empty_input(self) -> None:
        self.assertEqual(format_report.anonymize_text(""), "")
        already = "MAC xx:xx:xx:xx:xx:01 IP [PUBLIC_IP_01]"
        self.assertEqual(format_report.anonymize_text(already), already)


class TestAnonymizeReport(unittest.TestCase):
    def test_anonymize_report_deep_copies_and_masks_all_sensitive_fields(self) -> None:
        original = _sample_report()
        snapshot = copy.deepcopy(original)

        masked = format_report.anonymize_report(original)

        # Original must not be mutated
        self.assertEqual(original, snapshot)
        self.assertTrue(masked["anonymized"])

        # Own Wi-Fi link
        self.assertEqual(masked["wifi_link"]["ssid"], "Own_WiFi")
        self.assertEqual(masked["wifi_link"]["bssid"], "xx:xx:xx:xx:xx:01")

        # RF scan networks: own SSID & BSSID consistent, neighbors numbered, <hidden> kept
        nets = masked["rf_scan"]["networks"]
        self.assertEqual(nets[0]["ssid"], "Own_WiFi")
        self.assertEqual(nets[0]["bssid"], "xx:xx:xx:xx:xx:01")
        self.assertEqual(nets[1]["ssid"], "Neighbor_01")
        self.assertEqual(nets[1]["bssid"], "xx:xx:xx:xx:xx:02")
        self.assertEqual(nets[2]["ssid"], "Neighbor_02")
        self.assertEqual(nets[2]["bssid"], "xx:xx:xx:xx:xx:03")
        self.assertEqual(nets[3]["ssid"], "<hidden>")
        self.assertEqual(nets[3]["bssid"], "xx:xx:xx:xx:xx:04")

        # USB notes and WLAN events
        self.assertIn("xx:xx:xx:xx:xx:01", masked["usb_audit"]["note"])
        self.assertIn("192.168.1.1", masked["usb_audit"]["note"])
        self.assertNotIn("198.51.100.9", masked["usb_audit"]["note"])
        self.assertIn("[PUBLIC_IP_01]", masked["usb_audit"]["note"])

        ev_msg = masked["usb_audit"]["wlan_events_recent"][0]["message"]
        self.assertIn("xx:xx:xx:xx:xx:01", ev_msg)
        self.assertNotIn("203.0.113.45", ev_msg)
        self.assertIn("[PUBLIC_IP_02]", ev_msg)

        ev_msg_2 = masked["usb_audit"]["wlan_events_recent"][1]["message"]
        self.assertNotIn("PastPrivateNet_5G", ev_msg_2)
        self.assertNotIn("OtherPrivateNet", ev_msg_2)
        self.assertIn("SSID de red: [REDACTED_SSID]", ev_msg_2)
        self.assertIn("Network SSID: [REDACTED_SSID]", ev_msg_2)

        # Baseline & DNS
        self.assertEqual(masked["baseline_latency"]["gateway_ip"], "192.168.1.1")
        self.assertEqual(masked["baseline_latency"]["wan_target"], "1.1.1.1")
        self.assertEqual(
            masked["dns_latency"]["configured_servers"],
            ["192.168.1.1", "[PUBLIC_IP_03]", "1.1.1.1"],
        )
        self.assertEqual(masked["dns_latency"]["results"][0]["server"], "[PUBLIC_IP_03]")
        self.assertEqual(masked["dns_latency"]["results"][1]["server"], "1.1.1.1")

        # Idempotency
        masked_twice = format_report.anonymize_report(masked)
        self.assertEqual(masked_twice, masked)


class TestRenderMarkdown(unittest.TestCase):
    def test_render_full_report_with_findings(self) -> None:
        report = format_report.anonymize_report(_sample_report(band="2.4 GHz"))
        md = format_report.render_markdown(report)

        self.assertIn("# Wi-Fi & Network Audit Report (windows)", md)
        self.assertIn("## Key Findings", md)
        self.assertIn("DFS Channel Active (Ch 52)", md)
        self.assertIn("Connected on 2.4 GHz", md)
        self.assertIn("Weak Wi-Fi Signal (55%)", md)
        self.assertIn("USB 2.0 Bottleneck on USB 3.0 Root Hub", md)
        self.assertIn("USB Selective Suspend Enabled (AC)", md)
        self.assertIn("Recent WLAN AutoConfig Events (8003/11004)", md)
        self.assertIn("Active VPN/Tunnel Detected", md)
        self.assertIn("Idle Packet Loss to Gateway (2.0%)", md)
        self.assertIn("First-Hop (Download) Bufferbloat (+45.0 ms to gateway)", md)
        self.assertIn("WAN (Upload) Bufferbloat (+75.0 ms to WAN)", md)
        self.assertIn("## 1. Active Wi-Fi Link", md)
        self.assertIn("## 2. RF Spectrum & Neighbor Congestion", md)
        self.assertIn("## 3. USB Adapter, Power & WLAN Events", md)
        self.assertIn("## 4. VPN / Tunnels & Idle Baseline Latency (Sequential)", md)
        self.assertIn("## 5. Uncached DNS Latency", md)
        self.assertIn("## 6. Load Test & Bufferbloat (Sequential DL -> 2s Drain -> UL)", md)

    def test_render_skipped_load_and_minimal_report(self) -> None:
        skipped = format_report.anonymize_report(_sample_report(skip_load=True))
        md_skipped = format_report.render_markdown(skipped)
        self.assertIn("_Skipped._", md_skipped)

        md_empty = format_report.render_markdown({})
        self.assertIn("# Wi-Fi & Network Audit Report (unknown)", md_empty)
        self.assertIn("N/A", md_empty)


class TestCompareReports(unittest.TestCase):
    def test_compare_reports_deltas_and_directions(self) -> None:
        before = format_report.anonymize_report(
            _sample_report(
                channel=52,
                is_dfs=True,
                signal=55,
                rx_mbps=300.0,
                tx_mbps=240.0,
                usb2_bottleneck=True,
                gw_avg=12.5,
                gw_p95=28.0,
                gw_loss=2.0,
                wan_avg=25.0,
                wan_p95=42.0,
                dns_avg=38.0,
                dl_mbps=180.0,
                dl_gw_bloat=45.0,
                dl_wan_bloat=60.0,
                ul_mbps=90.0,
                ul_gw_bloat=15.0,
                ul_wan_bloat=75.0,
                timestamp="2026-01-01T10:00:00Z",
            )
        )
        after = format_report.anonymize_report(
            _sample_report(
                channel=36,
                is_dfs=False,
                signal=82,
                rx_mbps=866.0,
                tx_mbps=866.0,
                usb2_bottleneck=False,
                gw_avg=3.0,
                gw_p95=6.0,
                gw_loss=0.0,
                wan_avg=25.0,
                wan_p95=30.0,
                dns_avg=14.0,
                dl_mbps=520.0,
                dl_gw_bloat=8.0,
                dl_wan_bloat=12.0,
                ul_mbps=300.0,
                ul_gw_bloat=5.0,
                ul_wan_bloat=10.0,
                timestamp="2026-01-01T11:00:00Z",
            )
        )

        md = format_report.compare_reports(before, after)
        self.assertIn("# Wi-Fi & Network Audit Comparison (Before vs After)", md)
        self.assertIn("| Wi-Fi Band / Channel | 5 GHz / Ch 52 | 5 GHz / Ch 36 | changed |", md)
        self.assertIn("| DFS Channel | True | False | changed |", md)
        self.assertIn("| Wi-Fi Signal | 55% | 82% | +27.00% (better) |", md)
        self.assertIn("| Idle Gateway Avg Latency | 12.5 ms | 3.0 ms | -9.50 ms (better) |", md)
        self.assertIn("| Idle WAN Avg Latency | 25.0 ms | 25.0 ms | 0 ms (unchanged) |", md)
        self.assertIn("| Current DNS Avg Latency | 38.0 ms | 14.0 ms | -24.00 ms (better) |", md)
        self.assertIn("| Download Throughput | 180.0 Mbps | 520.0 Mbps | +340.00 Mbps (better) |", md)
        self.assertIn("| Download Gateway Bloat | 45.0 ms | 8.0 ms | -37.00 ms (better) |", md)

    def test_compare_reports_worse_and_missing_values(self) -> None:
        before = {"wifi_link": {"signal_percent": 80}, "baseline_latency": {"gateway": {"avg_ms": 5.0}}}
        after = {"wifi_link": {"signal_percent": 60}, "baseline_latency": {"gateway": {"avg_ms": 15.0}}}
        md = format_report.compare_reports(before, after)
        self.assertIn("-20.00% (worse)", md)
        self.assertIn("+10.00 ms (worse)", md)
        self.assertIn("| Download Throughput | N/A | N/A | N/A |", md)


class TestFormatReportCLI(unittest.TestCase):
    def test_cli_anonymize_render_compare_with_out_flag_and_auto_mkdir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            before_raw = tmp_path / "before_raw.json"
            after_raw = tmp_path / "after_raw.json"
            before_raw.write_text(json.dumps(_sample_report(signal=55)), encoding="utf-8")
            after_raw.write_text(json.dumps(_sample_report(signal=85, channel=36, is_dfs=False)), encoding="utf-8")

            # 1. anonymize JSON -> nested --out path
            anon_out = tmp_path / "nested" / "before_anon.json"
            rc = format_report.main(["anonymize", str(before_raw), "--out", str(anon_out)])
            self.assertEqual(rc, 0)
            anon_data = json.loads(anon_out.read_text(encoding="utf-8"))
            self.assertTrue(anon_data["anonymized"])
            self.assertEqual(anon_data["wifi_link"]["ssid"], "Own_WiFi")

            # 2. anonymize --text
            raw_txt = tmp_path / "raw.txt"
            raw_txt.write_text("MAC AA:BB:CC:11:22:33 IP 203.0.113.77", encoding="utf-8")
            txt_out = tmp_path / "clean.txt"
            rc = format_report.main(["anonymize", "--text", str(raw_txt), "-o", str(txt_out)])
            self.assertEqual(rc, 0)
            cleaned = txt_out.read_text(encoding="utf-8")
            self.assertIn("xx:xx:xx:xx:xx:01", cleaned)
            self.assertIn("[PUBLIC_IP_01]", cleaned)

            # 3. render --anonymize
            md_out = tmp_path / "rendered" / "report.md"
            rc = format_report.main(["render", "--anonymize", str(before_raw), "--output", str(md_out)])
            self.assertEqual(rc, 0)
            rendered = md_out.read_text(encoding="utf-8")
            self.assertIn("Own_WiFi", rendered)
            self.assertNotIn("MyHomeSSID_5G", rendered)

            # 4. compare via subprocess using --out
            cmp_out = tmp_path / "reports" / "comparison.md"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(SCRIPTS_DIR / "format_report.py"),
                    "compare",
                    str(before_raw),
                    str(after_raw),
                    "--out",
                    str(cmp_out),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            cmp_text = cmp_out.read_text(encoding="utf-8")
            self.assertIn("+30.00% (better)", cmp_text)

    def test_cli_stdout_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw_txt = Path(tmp) / "in.txt"
            raw_txt.write_text("Host 198.51.100.5", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = format_report.main(["anonymize", "--text", str(raw_txt)])
            self.assertEqual(rc, 0)
            self.assertIn("[PUBLIC_IP_01]", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
