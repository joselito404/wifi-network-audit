# Wi-Fi Network Audit (Agent Skill)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Standard: Agent Skills](https://img.shields.io/badge/Standard-Agent%20Skills-green.svg)](SKILL.md)
[![Platforms: Windows | macOS | Linux](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#installation--usage)

A cross-platform, read-only **Agent Skill** and sequential diagnostic toolkit for isolating Wi-Fi, USB adapter, RF channel, DNS, and bufferbloat bottlenecks — complete with guided router optimization and automated **Before vs. After** comparison reports.

> **Credit:** Inspired by the sequential Wi-Fi diagnostic methodology originally shared by [`@brunovolpato`](https://x.com/brunovolpato).

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
git clone https://github.com/your-username/wifi-network-audit.git .agents/skills/wifi-network-audit
```

**Global (user-level):**
```bash
git clone https://github.com/your-username/wifi-network-audit.git ~/.gemini/antigravity/skills/wifi-network-audit
```

Then ask your agent: *"Audit my Wi-Fi connection and find why my ping spikes."*

---

### 2. Anthropic Claude Code

**Project-level:**
```bash
git clone https://github.com/your-username/wifi-network-audit.git .claude/skills/wifi-network-audit
```

**Global (user-level):**
```bash
git clone https://github.com/your-username/wifi-network-audit.git ~/.claude/skills/wifi-network-audit
```

Then ask Claude Code: *"Run a Wi-Fi network audit and help me optimize my router."*

---

### 3. OpenAI Codex CLI

**Project-level:**
```bash
git clone https://github.com/your-username/wifi-network-audit.git .codex/skills/wifi-network-audit
```

**Global (user-level):**
```bash
git clone https://github.com/your-username/wifi-network-audit.git ~/.codex/skills/wifi-network-audit
```

Then ask Codex: *"Use the wifi-network-audit skill to diagnose my slow Wi-Fi."*

---

### 4. ChatGPT / Claude.ai / Gemini Web (No Terminal Agent)

1. Run the read-only audit script locally (output is anonymized by default):
   - **Windows (PowerShell):**
     ```powershell
     powershell -ExecutionPolicy Bypass -File scripts/audit_windows.ps1 -Format Json -OutFile reports/before.json
     ```
   - **macOS / Linux (Bash):**
     ```bash
     bash scripts/audit_unix.sh --format json --out reports/before.json
     ```
2. Copy the contents of [`prompts/web_analyzer_prompt.md`](prompts/web_analyzer_prompt.md) into ChatGPT, Claude.ai, or Gemini Web.
3. Paste the contents of `reports/before.json` at the bottom of the prompt.

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
