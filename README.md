# Wi-Fi Network Audit (Agent Skill)

[![CI](https://github.com/joselito404/wifi-network-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/joselito404/wifi-network-audit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/joselito404/wifi-network-audit?label=Release)](https://github.com/joselito404/wifi-network-audit/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Standard: Agent Skills](https://img.shields.io/badge/Standard-Agent%20Skills-green.svg)](SKILL.md)
[![Platforms: Windows | macOS | Linux](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#installation--usage)

A cross-platform, read-only **Agent Skill** and sequential diagnostic toolkit for isolating Wi-Fi, USB adapter, RF channel, DNS, and bufferbloat bottlenecks — complete with guided router optimization and automated **Before vs. After** comparison reports.

> **Credit:** Inspired by the sequential Wi-Fi diagnostic methodology originally shared by [`@brunovolpato`](https://x.com/brunovolpato).

### Example Output (Before vs. After)

| Metric | Before | After | Delta | Status |
| :--- | :---: | :---: | :---: | :---: |
| **USB Bus Speed** | `480 Mbps` (USB 2.0) | `5000 Mbps` (USB 3.0) | `+4520 Mbps` | Fixed |
| **5 GHz Channel / Width** | `ch. 100 (DFS, 160 MHz)` | `ch. 36 (Non-DFS, 80 MHz)` | Non-DFS | Stabilized |
| **Gateway Loaded RTT (p95)** | `68.4 ms` | `6.2 ms` | `-62.2 ms` | Fixed |
| **Download Throughput** | `241 Mbps` | `584 Mbps` | `+343 Mbps` | Improved |
| **DNS Uncached Lookup** | `94 ms` | `16 ms` | `-78 ms` | Fixed |

*Full fictional anonymized report in [`examples/sample_before_after.md`](examples/sample_before_after.md).*

---

## Requirements

- **Windows:** PowerShell `5.1+` or PowerShell `7+` (`pwsh`), `curl` (built into Windows 10/11)
- **macOS / Linux:** `bash 3.2+`, `curl`
- **Optional:** `python3` (`3.11+` recommended) for generating Markdown comparison tables locally with `scripts/format_report.py compare` (web AI users can skip Python and paste both JSON reports directly into the web prompt)

---

## What It Detects

| Category | Specific Issues Caught |
| :--- | :--- |
| **USB & Hardware** | USB 3.0 Wi-Fi adapters silently negotiating at **USB 2.0** (`480 Mbps`), poor PHY link rates, weak RSSI. |
| **OS & Power Management** | Windows **USB Selective Suspend** disconnects and adapter resets (e.g., Event ID `8003`), aggressive power-saving states. |
| **RF & Channel Congestion** | **DFS channel** overlap/radar fallback, 2.4 GHz crowding, mismatched channel widths (`20/40/80/160 MHz`). |
| **Latency & Bufferbloat** | **First-hop (local Wi-Fi/gateway)** latency spikes vs. **ISP/WAN** bufferbloat under download and upload load. |
| **DNS Performance** | Slow uncached ISP DNS lookups vs. fast cached resolution. |

---

## Multi-AI Compatibility

| AI Tool / Platform | Support | Integration Method |
| :--- | :---: | :--- |
| **Google Antigravity / Gemini CLI** | Native | Agent Skill (`.agents/skills/` or `~/.gemini/antigravity/skills/`) |
| **Anthropic Claude Code** | Native | Agent Skill (`.claude/skills/` or `~/.claude/skills/`) |
| **OpenAI Codex CLI** | Native | Agent Skill (`.codex/skills/` or `~/.codex/skills/`) |
| **ChatGPT / Claude.ai / Gemini Web** | Manual | Run script locally + paste anonymized output with `prompts/web_analyzer_prompt.md` |

---

## Installation & Usage

### 1. Google Antigravity / Gemini CLI

**Workspace-level:**
```bash
git clone https://github.com/joselito404/wifi-network-audit.git .agents/skills/wifi-network-audit
```

**Global (user-level):**
```bash
git clone https://github.com/joselito404/wifi-network-audit.git ~/.gemini/antigravity/skills/wifi-network-audit
```

Then ask your agent: *"Audit my Wi-Fi connection and find why my ping spikes."*

---

### 2. Anthropic Claude Code

**Project-level:**
```bash
git clone https://github.com/joselito404/wifi-network-audit.git .claude/skills/wifi-network-audit
```

**Global (user-level):**
```bash
git clone https://github.com/joselito404/wifi-network-audit.git ~/.claude/skills/wifi-network-audit
```

Then ask Claude Code: *"Run a Wi-Fi network audit and help me optimize my router."*

---

### 3. OpenAI Codex CLI

**Project-level:**
```bash
git clone https://github.com/joselito404/wifi-network-audit.git .codex/skills/wifi-network-audit
```

**Global (user-level):**
```bash
git clone https://github.com/joselito404/wifi-network-audit.git ~/.codex/skills/wifi-network-audit
```

Then ask Codex: *"Use the wifi-network-audit skill to diagnose my slow Wi-Fi."*

---

### 4. ChatGPT / Claude.ai / Gemini Web (No Terminal Agent)

**Option A — Without `git` (direct download):**
Download the latest [Release ZIP](https://github.com/joselito404/wifi-network-audit/releases/latest) or fetch only the script for your OS:
- **Windows (PowerShell):**
  ```powershell
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/joselito404/wifi-network-audit/main/scripts/audit_windows.ps1" -OutFile "audit_windows.ps1"
  powershell -ExecutionPolicy Bypass -File .\audit_windows.ps1 -Format Json -OutFile before.json
  ```
- **macOS / Linux (Bash):**
  ```bash
  curl -fsSL "https://raw.githubusercontent.com/joselito404/wifi-network-audit/main/scripts/audit_unix.sh" -o audit_unix.sh
  bash audit_unix.sh --format json --out before.json
  ```

**Option B — From a cloned repository:**
1. Run the read-only audit script locally (output is anonymized by default):
   - **Windows (PowerShell):**
     ```powershell
     powershell -ExecutionPolicy Bypass -File scripts/audit_windows.ps1 -Format Json -OutFile reports/before.json
     ```
   - **macOS / Linux (Bash):**
     ```bash
     bash scripts/audit_unix.sh --format json --out reports/before.json
     ```

**Then analyze in your browser:**
1. Copy the contents of [`prompts/web_analyzer_prompt.md`](prompts/web_analyzer_prompt.md) into ChatGPT, Claude.ai, or Gemini Web.
2. Paste the contents of `before.json` (or both `before.json` and `after.json` for an automatic Before vs. After table without Python) at the bottom of the prompt.

---

## Comparing Before vs. After

After applying your hardware, OS, or router fixes, run a second audit to `reports/after.json` and generate a Markdown comparison table:

```bash
python scripts/format_report.py compare reports/before.json reports/after.json --out reports/comparison.md
```

See [`examples/sample_before_after.md`](examples/sample_before_after.md) for a fictional example output.

---

## Privacy & Safety

- **Read-Only by Default:** Audit scripts never change registry keys, power plans, drivers, or router settings.
- **Anonymized by Default:** SSIDs, BSSIDs, MAC addresses, hostnames, and public IPs are masked/hashed before writing JSON reports so they are safe to share with AI assistants or in issue trackers.
- **Sequential Testing:** Idle latency, download, upload, and loaded latency tests run strictly one after another to prevent self-inflicted measurement noise.

---

## License

Released under the [MIT License](LICENSE).
