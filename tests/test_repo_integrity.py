"""Repository integrity, syntax, metadata, CLI coherence, and privacy leak tests."""

from __future__ import annotations

import base64
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
            self.assertIn("format_report.py compare reports/before.json reports/after.json --out reports/comparison.md", doc_text, msg=f"{doc_name} compare CLI mismatch")

        # Scripts actually implement the documented flags
        self.assertIn("[string]$OutFile", ps_text)
        self.assertIn("-o|--out)", sh_text)
        self.assertIn('"-o", "--output", "--out"', py_text)

    def test_privacy_leak_scan(self) -> None:
        forbidden = [base64.b64decode(tok).decode("utf-8") for tok in _FORBIDDEN_TOKENS_B64]
        leaks = []

        for path in REPO_ROOT.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {"__pycache__", ".git"} for part in path.parts):
                continue
            if path.suffix.lower() in {".pyc", ".pyo", ".png", ".jpg", ".ico"}:
                continue

            text = path.read_text(encoding="utf-8", errors="ignore")
            lowered = text.lower()
            for token in forbidden:
                if token.lower() in lowered:
                    leaks.append((str(path.relative_to(REPO_ROOT)), token))

        self.assertEqual(leaks, [], msg=f"Privacy leak(s) detected in repository: {leaks}")


if __name__ == "__main__":
    unittest.main()
