"""Repository integrity, syntax, metadata, CLI coherence, and privacy leak tests."""

from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Base64-encoded local environment identifiers so the test file itself never
# embeds raw private SSIDs, BSSIDs, or ISP IPs in plain text.
_FORBIDDEN_TOKENS_B64 = (
    "TGl2ZWJveDYtNDAzNw==",          # Livebox SSID
    "UkVEV0lGSV9UY1Ey",              # Local SSID
    "VFAtTGlua18xRUQy",              # Neighbor SSID 1
    "VFAtTGlua19FODBG",              # Neighbor SSID 2
    "dm9kYWZvbmVDQkIw",              # Neighbor SSID 3
    "TU9WSVNUQVItV0lGSTc=",          # Neighbor SSID 4
    "Njg6OGY6Yzk6MGQ6ZDg6MWY=",      # Local BSSID 1
    "YWM6YjY6ODc6Y2M6NDA6MzU=",      # Local BSSID 2
    "ODI6YjY6ODc6Y2M6NDA6MzY=",      # Local BSSID 3
    "ODcuMjE3LjU4LjE=",              # ISP IP 1
    "MTkzLjI1MS4yNTE=",              # ISP IP prefix 2
)


class TestRepoIntegrity(unittest.TestCase):
    def test_powershell_syntax(self) -> None:
        ps_script = REPO_ROOT / "scripts" / "audit_windows.ps1"
        self.assertTrue(ps_script.is_file(), "scripts/audit_windows.ps1 missing")

        ps_exe = shutil.which("powershell") or shutil.which("pwsh")
        self.assertIsNotNone(ps_exe, "PowerShell executable not found on PATH")

        cmd = (
            "$tokens = $null; $errors = $null; "
            f"[void][System.Management.Automation.Language.Parser]::ParseFile('{ps_script}', [ref]$tokens, [ref]$errors); "
            "if ($errors.Count -gt 0) { "
            "$errors | ForEach-Object { Write-Error ($_.Extent.StartLineNumber.ToString() + ': ' + $_.Message) }; "
            "exit 1 } else { Write-Output 'OK' }"
        )
        proc = subprocess.run(
            [ps_exe, "-NoProfile", "-Command", cmd],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=f"PowerShell parse errors:\n{proc.stderr}\n{proc.stdout}")
        self.assertIn("OK", proc.stdout)

    def test_bash_syntax_and_lf_line_endings(self) -> None:
        sh_script = REPO_ROOT / "scripts" / "audit_unix.sh"
        self.assertTrue(sh_script.is_file(), "scripts/audit_unix.sh missing")

        raw_bytes = sh_script.read_bytes()
        self.assertNotIn(b"\r\n", raw_bytes, "scripts/audit_unix.sh must use LF (Unix) line endings, not CRLF")
        self.assertTrue(raw_bytes.startswith(b"#!/usr/bin/env bash\n"), "Missing bash shebang with LF")

        git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
        bash_exe = str(git_bash) if git_bash.is_file() else shutil.which("bash")
        self.assertIsNotNone(bash_exe, "No bash executable found to validate scripts/audit_unix.sh")

        proc = subprocess.run(
            [bash_exe, "-n", str(sh_script)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=f"Bash syntax error:\n{proc.stderr}")

    def test_skill_md_frontmatter(self) -> None:
        skill_md = REPO_ROOT / "SKILL.md"
        self.assertTrue(skill_md.is_file(), "SKILL.md missing")
        content = skill_md.read_text(encoding="utf-8")

        match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", content, flags=re.DOTALL)
        self.assertIsNotNone(match, "SKILL.md must start with YAML frontmatter delimited by ---")
        frontmatter = match.group(1)

        name_match = re.search(r"^name:\s*(.+?)\s*$", frontmatter, flags=re.MULTILINE)
        desc_match = re.search(r"^description:\s*(.+?)\s*$", frontmatter, flags=re.MULTILINE)
        self.assertIsNotNone(name_match, "SKILL.md frontmatter missing 'name'")
        self.assertIsNotNone(desc_match, "SKILL.md frontmatter missing 'description'")

        name = name_match.group(1).strip().strip("'\"")
        description = desc_match.group(1).strip().strip("'\"")
        self.assertEqual(name, "wifi-network-audit")
        self.assertGreater(len(description), 20)
        self.assertLessEqual(len(description), 1024, f"description too long: {len(description)} chars")

    def test_cli_docs_coherence(self) -> None:
        skill_text = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
        readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        ps_text = (REPO_ROOT / "scripts" / "audit_windows.ps1").read_text(encoding="utf-8")
        sh_text = (REPO_ROOT / "scripts" / "audit_unix.sh").read_text(encoding="utf-8")
        py_text = (REPO_ROOT / "scripts" / "format_report.py").read_text(encoding="utf-8")

        # Docs explicitly pass JSON format when saving .json files
        for doc_name, doc_text in (("SKILL.md", skill_text), ("README.md", readme_text)):
            self.assertIn("-Format Json -OutFile reports/before.json", doc_text, msg=f"{doc_name} Windows CLI mismatch")
            self.assertIn("--format json --out reports/before.json", doc_text, msg=f"{doc_name} Unix CLI mismatch")
            self.assertRegex(
                doc_text,
                r'format_report\.py"?\s+compare reports/before\.json reports/after\.json --out reports/comparison\.md',
                msg=f"{doc_name} compare CLI mismatch",
            )

        # Scripts actually implement the documented flags
        self.assertIn("[string]$OutFile", ps_text)
        self.assertIn("-o|--out)", sh_text)
        self.assertIn('"-o", "--output", "--out"', py_text)

    def test_gitattributes_and_ci_workflow(self) -> None:
        gitattributes = REPO_ROOT / ".gitattributes"
        self.assertTrue(gitattributes.is_file(), ".gitattributes missing")
        gitattr_lines = [line.strip() for line in gitattributes.read_text(encoding="utf-8").splitlines()]
        self.assertIn("*.sh text eol=lf", gitattr_lines, ".gitattributes must enforce LF for *.sh")

        ci_yml = REPO_ROOT / ".github" / "workflows" / "ci.yml"
        self.assertTrue(ci_yml.is_file(), ".github/workflows/ci.yml missing")
        ci_text = ci_yml.read_text(encoding="utf-8")
        self.assertNotIn("\t", ci_text, "ci.yml must not contain tab characters")
        self.assertRegex(ci_text, r"(?m)^name:\s*\S+")
        self.assertRegex(ci_text, r"(?m)^on:\s*$")
        self.assertRegex(ci_text, r"(?m)^jobs:\s*$")
        self.assertIn("unittest", ci_text, "ci.yml must run unittest")
        self.assertIn("bash -n", ci_text, "ci.yml must run bash -n")

    def test_windows_multi_interface_parsing(self) -> None:
        ps_script = REPO_ROOT / "scripts" / "audit_windows.ps1"
        ps_exe = shutil.which("powershell") or shutil.which("pwsh")
        self.assertIsNotNone(ps_exe, "PowerShell executable not found on PATH")

        ps_harness = rf"""
$ErrorActionPreference = 'Stop'
$scriptPath = '{ps_script}'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {{ throw 'AST parse errors' }}

$needed = @('Test-IsDfsChannel', 'Get-BandFromChannel', 'Get-WifiLinkAudit')
$funcs = $ast.FindAll({{ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($needed -contains $n.Name) }}, $true)
if ($funcs.Count -ne $needed.Count) {{ throw "Expected $($needed.Count) functions, found $($funcs.Count)" }}
foreach ($fn in $funcs) {{ Invoke-Expression $fn.Extent.Text }}

function Get-NetAdapter {{ @() }}
function Get-NetAdapterStatistics {{ $null }}
function Get-CimInstance {{ $null }}
function Protect-Ssid {{ param([string]$Ssid, [switch]$IsOwn) if ($IsOwn) {{ 'Own_WiFi' }} else {{ $Ssid }} }}
function Protect-MacAddress {{ param([string]$Mac) 'xx:xx:xx:xx:xx:01' }}
function netstat {{ @() }}
function netsh {{
    @(
        'There are 2 interfaces on the system:',
        '',
        '    Name                   : Wi-Fi',
        '    Description            : Built-in Legacy Adapter',
        '    GUID                   : 11111111-1111-1111-1111-111111111111',
        '    Physical address       : 00:11:22:33:44:55',
        '    State                  : disconnected',
        '    Radio type             : 802.11n',
        '    Signal                 : 12%',
        '',
        '    Name                   : Wi-Fi 2',
        '    Description            : USB Wi-Fi 6 Adapter',
        '    GUID                   : 22222222-2222-2222-2222-222222222222',
        '    Physical address       : aa:bb:cc:11:22:33',
        '    State                  : connected',
        '    SSID                   : TestLab_5G',
        '    AP BSSID               : aa:bb:cc:11:22:33',
        '    Band                   : 5 GHz',
        '    Channel                : 36',
        '    Radio type             : 802.11ax',
        '    Receive rate (Mbps)    : 866.7',
        '    Transmit rate (Mbps)   : 780',
        '    Signal                 : 88%'
    )
}}

$result = Get-WifiLinkAudit
$result | ConvertTo-Json -Depth 5 -Compress
"""
        proc = subprocess.run(
            [ps_exe, "-NoProfile", "-Command", ps_harness],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=f"PowerShell harness failed:\n{proc.stderr}\n{proc.stdout}")
        data = json.loads(proc.stdout.strip())
        self.assertEqual(data["interface_name"], "Wi-Fi 2")
        self.assertEqual(data["description"], "USB Wi-Fi 6 Adapter")
        self.assertEqual(data["state"], "connected")
        self.assertEqual(data["raw_ssid"], "TestLab_5G")
        self.assertEqual(data["raw_bssid"], "aa:bb:cc:11:22:33")
        self.assertEqual(data["band"], "5 GHz")
        self.assertEqual(data["channel"], 36)
        self.assertFalse(data["is_dfs"])
        self.assertEqual(data["radio_type"], "802.11ax")
        self.assertEqual(data["signal_percent"], 88)
        self.assertAlmostEqual(float(data["receive_rate_mbps"]), 866.7, places=1)
        self.assertAlmostEqual(float(data["transmit_rate_mbps"]), 780.0, places=1)

    def test_unix_is_preserved_ip(self) -> None:
        sh_script = REPO_ROOT / "scripts" / "audit_unix.sh"
        sh_text = sh_script.read_text(encoding="utf-8")
        match = re.search(r"(?ms)^is_preserved_ip\(\)\s*\{.*?^\}", sh_text)
        self.assertIsNotNone(match, "is_preserved_ip function not found in scripts/audit_unix.sh")
        func_def = match.group(0)

        git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
        bash_exe = str(git_bash) if git_bash.is_file() else shutil.which("bash")
        self.assertIsNotNone(bash_exe, "No bash executable found to test is_preserved_ip")

        cases = [
            # Preserved IPv4 (private, loopback, link-local, CGNAT, well-known DNS)
            ("192.168.1.1", 0),
            ("10.0.0.5", 0),
            ("172.16.0.1", 0),
            ("100.64.0.1", 0),
            ("127.0.0.1", 0),
            ("169.254.1.2", 0),
            ("1.1.1.1", 0),
            ("8.8.8.8", 0),
            ("9.9.9.9", 0),
            # Public IPv4 (must NOT be preserved)
            ("203.0.113.10", 1),
            ("198.51.100.5", 1),
            ("172.32.0.1", 1),
            ("100.128.0.1", 1),
            # Preserved IPv6 (unspecified, loopback, link-local with/without zone, ULA)
            ("::", 0),
            ("::1", 0),
            ("fe80::1", 0),
            ("fe80::1%eth0", 0),
            ("FE80::abcd:1234", 0),
            ("fc00::1", 0),
            ("fd12:3456:789a::1", 0),
            # Public IPv6 (must NOT be preserved)
            ("2001:4860:4860::8888", 1),
            ("2606:4700:4700::1111", 1),
            ("2a00:1450:4003::200e", 1),
        ]

        checks = "\n".join(
            f'is_preserved_ip "{ip}"; rc=$?; '
            f'if [ "$rc" -ne {expected} ]; then echo "FAIL:{ip}:got=$rc:expected={expected}"; exit 1; fi'
            for ip, expected in cases
        )
        bash_cmd = f"{func_def}\n{checks}\necho OK\n"
        proc = subprocess.run(
            [bash_exe, "-c", bash_cmd],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=f"is_preserved_ip test failed:\n{proc.stdout}\n{proc.stderr}")
        self.assertIn("OK", proc.stdout)

    def test_privacy_leak_scan(self) -> None:
        forbidden = [base64.b64decode(tok).decode("utf-8") for tok in _FORBIDDEN_TOKENS_B64]
        leaks = []
        scanned_rel = set()

        for path in REPO_ROOT.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {"__pycache__", ".git"} for part in path.parts):
                continue
            if path.suffix.lower() in {".pyc", ".pyo", ".png", ".jpg", ".ico"}:
                continue

            rel_posix = path.relative_to(REPO_ROOT).as_posix()
            scanned_rel.add(rel_posix)
            text = path.read_text(encoding="utf-8", errors="ignore")
            lowered = text.lower()
            for token in forbidden:
                if token.lower() in lowered:
                    leaks.append((rel_posix, token))

        self.assertIn("README.md", scanned_rel)
        self.assertIn(".github/workflows/ci.yml", scanned_rel)
        self.assertTrue(any(p.startswith("references/") for p in scanned_rel), "references/ not scanned")
        self.assertTrue(any(p.startswith("prompts/") for p in scanned_rel), "prompts/ not scanned")
        self.assertEqual(leaks, [], msg=f"Privacy leak(s) detected in repository: {leaks}")


if __name__ == "__main__":
    unittest.main()
