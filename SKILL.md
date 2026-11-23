---
name: wifi-network-audit
description: Audits Wi-Fi and local network performance sequentially across Windows, macOS, and Linux to isolate hardware, driver, RF channel, DNS, and bufferbloat bottlenecks. Use when the user asks to diagnose slow Wi-Fi, high ping, packet loss, lag spikes, USB adapter drops, or optimize router settings with a Before vs. After report.
---

# Wi-Fi & Local Network Audit

## Core Rules

1. **Read-Only by Default:** Never modify power plans, USB selective suspend, adapter advanced properties, Windows Registry keys, DNS settings, or router configuration without explicit user confirmation.
2. **Strict Sequential Execution:** Never run idle ping, download throughput, upload throughput, or loaded latency tests in parallel. Concurrent traffic contaminates RTT, jitter, and bufferbloat measurements.
3. **Privacy First:** Keep all outputs anonymized by default (hashed or masked SSIDs, BSSIDs, MAC addresses, and public IPs). Never paste raw credentials or unredacted network identifiers into reports.
4. **No Placebo Tweaks:** Reject unverified registry hacks (e.g., disabling Nagle globally, random TCP autotuning overrides, or "gaming optimizer" scripts). Recommend only evidence-backed fixes tied to observed metrics.

---

## Step 1: Collect Baseline Telemetry (Before)

> **Path Resolution:** All `scripts/` and `references/` paths in this skill (`scripts/audit_windows.ps1`, `scripts/audit_unix.sh`, `scripts/format_report.py`, and `references/*.md`) are relative to the **skill's own directory** (where `SKILL.md` resides) — **not** the user's current workspace. When installed globally (e.g., `~/.gemini/antigravity/skills/wifi-network-audit/`, `~/.claude/skills/wifi-network-audit/`, or `~/.codex/skills/wifi-network-audit/`), resolve those paths from the skill directory while saving output reports (`reports/before.json`, `reports/after.json`, `reports/comparison.md`) in the user's working directory (or a writable `reports/` folder).

Detect the host OS and run the corresponding read-only audit script sequentially, saving the JSON report under `reports/before.json` (replace `<SKILL_DIR>` with the directory containing this `SKILL.md` when running from another workspace):

- **Windows (PowerShell):**
  ```powershell
  powershell -ExecutionPolicy Bypass -File "<SKILL_DIR>/scripts/audit_windows.ps1" -Format Json -OutFile reports/before.json
  ```
- **macOS / Linux (Bash):**
  ```bash
  bash "<SKILL_DIR>/scripts/audit_unix.sh" --format json --out reports/before.json
  ```

Wait for the script to finish completely before reading `reports/before.json`.

---

## Step 2: Diagnose Bottlenecks

Read `references/interpretation_rubric.md` and evaluate the baseline JSON across all five layers in order:

1. **Physical / Bus Layer:** Check for USB Wi-Fi adapters negotiating at USB 2.0 (`High-Speed` / `480 Mbps`) instead of USB 3.0 (`SuperSpeed` / `5 Gbps`), low PHY link rate, or weak RSSI.
2. **OS & Driver Layer:** Check Windows Event Log for Wi-Fi resets or USB selective suspend disconnects (Event ID `8003` / `10002` / `5002`), outdated drivers, or aggressive power saving.
3. **RF & Channel Layer:** Check band (2.4 GHz vs 5 GHz / 6 GHz), channel width (`20/40/80/160 MHz`), DFS radar-channel overlap, and neighbor co-channel congestion.
4. **Latency & Bufferbloat Layer:** Compare idle vs. loaded RTT to the **first hop (gateway)** against **external ISP/internet targets** to separate local Wi-Fi contention from ISP/router WAN bufferbloat.
5. **DNS Layer:** Compare uncached vs. cached DNS resolution times to detect slow ISP resolvers.

Present a concise, prioritized findings table to the user: **Root Cause**, **Evidence (exact metric)**, **Impact**, and **Recommended Fix**.

---

## Step 3: Guided Router & Host Optimization

If the diagnosis points to router settings (channel, width, band steering, QoS/SQM, transmit power, or DNS):

1. Ask the user for a screenshot of their router's **Wireless Settings** (and **QoS / WAN** page if bufferbloat was detected) — remind them to blur passwords or WAN IPs.
2. Consult `references/router_optimization_guide.md` and guide the user **click-by-click** using the exact labels visible in their screenshot.
3. For host-side fixes (e.g., moving a USB adapter to a rear motherboard USB 3.0 port, disabling USB Selective Suspend, or updating the driver), provide exact reversible commands or UI steps and wait for user confirmation before running anything that mutates system state.

---

## Step 4: Re-Audit & Generate Before vs. After Report

After the user applies the approved changes:

1. Run the exact same audit script sequentially (resolved from `<SKILL_DIR>`, where `SKILL.md` resides) to capture `reports/after.json`:
   - Windows: `powershell -ExecutionPolicy Bypass -File "<SKILL_DIR>/scripts/audit_windows.ps1" -Format Json -OutFile reports/after.json`
   - macOS / Linux: `bash "<SKILL_DIR>/scripts/audit_unix.sh" --format json --out reports/after.json`
2. Generate the formatted comparison report:
   ```bash
   python "<SKILL_DIR>/scripts/format_report.py" compare reports/before.json reports/after.json --out reports/comparison.md
   ```
3. Present the Before vs. After Markdown table, highlight verified gains, and note any remaining bottlenecks or external ISP limits that cannot be solved locally.
