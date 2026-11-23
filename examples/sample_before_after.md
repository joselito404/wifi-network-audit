# Wi-Fi Network Audit — Before vs. After (Sample Report)

> **Note:** This is a 100% fictional, anonymized example generated to illustrate the output format of `scripts/format_report.py compare`.

## Environment Summary

- **Host:** `DESKTOP-ANON01` (Windows 11)
- **Adapter:** `USB Wi-Fi 6 AX1800 Adapter`
- **Network:** `SSID_A1B2C3` (5 GHz, BSSID `XX:XX:XX:XX:01:02`)
- **Changes Applied:**
  1. Moved USB Wi-Fi adapter from front-panel USB 2.0 header to rear motherboard USB 3.2 port.
  2. Disabled Windows USB Selective Suspend (resolved Event ID `8003` resets).
  3. Switched 5 GHz router channel from DFS `ch. 100 (160 MHz)` to non-DFS `ch. 36 (80 MHz)`.
  4. Changed router DHCP DNS from ISP default to `1.1.1.1`.

---

## Before vs. After Comparison

| Metric | Before | After | Delta | Status |
| :--- | :---: | :---: | :---: | :---: |
| **USB Bus Speed** | `480 Mbps` (USB 2.0) | `5000 Mbps` (USB 3.0) | `+4520 Mbps` | Fixed |
| **PHY Link Rate** | `433 Mbps` | `1201 Mbps` | `+768 Mbps` | Improved |
| **RSSI / Signal** | `-64 dBm` | `-58 dBm` | `+6 dBm` | Improved |
| **5 GHz Channel / Width** | `ch. 100 (DFS, 160 MHz)` | `ch. 36 (Non-DFS, 80 MHz)` | Non-DFS | Stabilized |
| **Event ID 8003 (24h)** | `7` | `0` | `-7` | Fixed |
| **Gateway Idle RTT (avg)** | `3.8 ms` | `1.4 ms` | `-2.4 ms` | Improved |
| **Gateway Loaded RTT (p95)** | `68.4 ms` | `6.2 ms` | `-62.2 ms` | Fixed |
| **External Idle RTT (avg)** | `18.2 ms` | `14.5 ms` | `-3.7 ms` | Improved |
| **External Loaded RTT (p95)** | `112.0 ms` | `31.4 ms` | `-80.6 ms` | Improved |
| **Download Throughput** | `241 Mbps` | `584 Mbps` | `+343 Mbps` | Improved |
| **Upload Throughput** | `188 Mbps` | `312 Mbps` | `+124 Mbps` | Improved |
| **DNS Uncached Lookup** | `94 ms` | `16 ms` | `-78 ms` | Fixed |
| **Packet Loss** | `1.2%` | `0.0%` | `-1.2%` | Fixed |

---

## Remaining Notes

- Local Wi-Fi contention and USB bus throttling are eliminated.
- External loaded RTT (`31.4 ms`) is within healthy limits; no additional router SQM tuning is required at this time.
