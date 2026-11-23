# Wi-Fi & Network Audit Interpretation Rubric

Use this rubric to isolate the true bottleneck layer from sequential audit telemetry. Always evaluate from **Layer 1 (Physical)** up to **Layer 5 (DNS)**.

---

## 1. Physical & Bus Layer

| Metric | Healthy | Warning | Critical / Bottleneck |
| :--- | :--- | :--- | :--- |
| **USB Bus Speed** (USB Wi-Fi adapters) | SuperSpeed (`5 Gbps` / USB 3.0+) | — | High-Speed (`480 Mbps` / USB 2.0) on a Wi-Fi 5/6/6E adapter |
| **RSSI / Signal** | `-30` to `-65 dBm` | `-66` to `-74 dBm` | `<= -75 dBm` (high retries, rate drops) |
| **PHY Link Rate (5 GHz 80 MHz)** | `>= 600 Mbps` | `300–599 Mbps` | `< 300 Mbps` (likely 2.4 GHz fallback, 20/40 MHz, or poor SNR) |

**Diagnostic Notes:**
- A USB 3.0 adapter plugged into a front-panel header, unpowered hub, or worn port frequently falls back to USB 2.0 (`480 Mbps` half-duplex ceiling, ~250–300 Mbps real throughput) and causes micro-stutters. Move it directly to a rear motherboard USB 3.0/3.2 port.

---

## 2. OS & Driver Layer

- **Event ID `8003` (Windows WLAN-AutoConfig / USB):** Classic signature of USB Selective Suspend or power-saving disconnecting the adapter briefly.
- **Event ID `5002` / `5005` / `10002`:** Driver crash, firmware hang, or link reset.
- **Action:** Disable USB Selective Suspend for the adapter (Power Options + Device Manager → Power Management → uncheck *"Allow the computer to turn off this device to save power"*) and update to the chipset vendor's latest stable driver (Intel / Realtek / MediaTek).

---

## 3. RF & Channel Layer

- **Band:** Desktops and low-latency workloads should be on **5 GHz** or **6 GHz**, never 2.4 GHz (unless distance makes 5 GHz unusable `<= -78 dBm`).
- **DFS Channels (5 GHz ch. 52–144):** If the router sits on a DFS channel and detects weather/airport radar, it must vacate the channel (causing 10–60s drops or silent fallback to 20 MHz / congested channels). Prefer non-DFS channels (`36–48` or `149–161`, depending on region) when stability matters.
- **Channel Width (5 GHz):** `80 MHz` is the sweet spot on 5 GHz. `160 MHz` often overlaps DFS and increases interference; `20/40 MHz` caps peak throughput.
- **Wi-Fi 6E / 6 GHz:**
  - **PSC (Preferred Scanning Channels):** 6 GHz clients discover APs fastest on PSC channels (`5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213`). Non-PSC primary channels can cause slow discovery or fallback to 5 GHz.
  - **Channel Width (`160 MHz` / `320 MHz`):** Unlike 5 GHz, `160 MHz` is clean and practical on 6 GHz (no DFS radar vacates); `320 MHz` (Wi-Fi 7) is viable in low-noise environments at short range, though 6 GHz attenuates faster through walls than 5 GHz.
  - **Mandatory WPA3-SAE:** 6 GHz requires **WPA3-SAE** (and PMF) by specification; legacy WPA2-only clients cannot connect to 6 GHz, and misconfigured security modes can prevent 6 GHz association.

---

## 4. Latency & Bufferbloat Layer (First-Hop vs. ISP)

Compare **Idle RTT** against **Loaded RTT** (during download and upload) for both the **Gateway (first hop)** and **External Target (e.g., 1.1.1.1 / 8.8.8.8)**:

| Pattern | Gateway Idle → Loaded | External Idle → Loaded | Root Cause |
| :--- | :--- | :--- | :--- |
| **Healthy** | `1–4 ms → < 15 ms` | `10–25 ms → < 45 ms` | No significant bottleneck |
| **Local Wi-Fi Contention** | `2 ms → > 40 ms` (or spikes `> 100 ms`) | Mirrors gateway spike | Airtime congestion, weak RSSI, USB 2.0 bus, or bad channel |
| **ISP / Router WAN Bufferbloat** | `2 ms → < 10 ms` (stays low) | `15 ms → > 80–300 ms` | Router WAN queue bloat under load; needs SQM (CAKE / FQ-CoDel) or QoS |
| **Packet Loss (`> 0.5%`)** | Loss on gateway | Loss on external | Local RF interference, failing adapter, or bad cable |

---

## 5. DNS Layer

| Metric | Healthy | Warning | Critical |
| :--- | :--- | :--- | :--- |
| **Uncached Lookup** | `< 35 ms` | `35–80 ms` | `> 80 ms` (sluggish page loads despite fast bandwidth) |
| **Cached Lookup** | `< 5 ms` | `5–15 ms` | `> 15 ms` |

**Action:** If uncached DNS is consistently slow, test switching the router's DHCP DNS (or OS DNS) to a low-latency resolver (e.g., Cloudflare `1.1.1.1`, Quad9 `9.9.9.9`, or Google `8.8.8.8`) and re-measure.

---

## Placebo Tweaks to Avoid

Do **not** recommend:
- Global Windows Registry TCP/IP hacks (`TcpAckFrequency`, `TCPNoDelay`, `NetworkThrottlingIndex`).
- Disabling Windows Receive Window Auto-Tuning (`netsh int tcp set global autotuninglevel=disabled`) — this usually **reduces** throughput on high-speed links.
- Third-party "ping booster" or "registry optimizer" utilities.
