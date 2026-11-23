# Router Optimization Guide (Click-by-Click Protocol)

Use this guide after identifying RF, channel, or WAN bufferbloat issues in the baseline audit. Always ask the user for a screenshot of their router's **Wireless Settings** (and **QoS / SQM** page if applicable) so you can reference the exact menu labels on their firmware.

---

## 1. Band & SSID Separation

- **When to change:** The client keeps roaming down to 2.4 GHz or bouncing between bands (Band Steering / Smart Connect).
- **Recommended setting:** Either split 5 GHz into its own SSID (e.g., `HomeNet_5G`) for desktops/gaming rigs, or disable aggressive Band Steering if the client is stationary with good 5 GHz signal (`>= -68 dBm`).

---

## 2. Channel Selection (5 GHz)

- **Avoid "Auto" if it parks on congested or DFS channels.**
- **Non-DFS 5 GHz channels (prefer these for stability):**
  - Low band: **36, 40, 44, 48**
  - High band (region-dependent): **149, 153, 157, 161**
- **DFS channels (52–144):** Only use if non-DFS bands are severely saturated by neighbors *and* no radar events occur in your area.
- **2.4 GHz (if needed for IoT/legacy):** Use only **1, 6, or 11** at **20 MHz** width to avoid adjacent-channel interference.

---

## 3. Channel Width (5 GHz & 6 GHz)

- **5 GHz — 80 MHz (Recommended default):** Best balance of throughput (866–1200+ Mbps PHY) and interference resistance.
- **5 GHz — 40 MHz:** Use only in extremely dense apartment buildings where 80 MHz causes constant jitter.
- **5 GHz — 160 MHz:** Avoid unless you have a clean RF environment and Wi-Fi 6/6E clients; it forces DFS overlap in most regions.
- **Wi-Fi 6E / 6 GHz (if supported by router and client):**
  - **Channels:** Always pick a **PSC (Preferred Scanning Channel)** such as `37`, `53`, `69`, or `85` so clients discover the 6 GHz band reliably without falling back to 5 GHz.
  - **Width:** `160 MHz` is the standard sweet spot on 6 GHz (no DFS radar interference); `320 MHz` (Wi-Fi 7) is optional for short-range line-of-sight setups.
  - **Security:** **WPA3-SAE** is mandatory on 6 GHz — do not disable WPA3 on the 6 GHz SSID.

---

## 4. Bufferbloat Mitigation (SQM / QoS)

- **When to enable:** Gateway latency stays low under load (`< 10 ms`), but external RTT spikes (`+50 ms` to `+300 ms`) during download or upload.
- **Best option (OpenWrt, Asuswrt-Merlin, UniFi, Firewalla, etc.):** Enable **SQM** with **CAKE** or **FQ-CoDel**, setting bandwidth limits to **85–90%** of measured stable download and upload speeds.
- **ISP / consumer routers without SQM:** Look for **Smart Queue**, **Adaptive QoS**, or **Bandwidth Control**. Avoid legacy static priority rules that disable hardware NAT without fixing queue depth.

---

## 5. DNS & Misc Settings

- **DNS:** Set primary/secondary DNS on the router's LAN/DHCP settings (e.g., `1.1.1.1` / `1.0.0.1` or `9.9.9.9`) so all devices benefit.
- **WPA Security:** Use **WPA2-AES (CCMP)** or **WPA2/WPA3-Transition**. Never use TKIP (caps Wi-Fi to 54 Mbps).
- **Transmit Power:** Keep at `High` or `100%` for single-router homes; only lower it in multi-AP setups to fix sticky roaming.
- **Apply & Verify:** Remind the user that changing wireless settings drops Wi-Fi for 15–60 seconds. Wait for reconnection, then run the **After** audit.
