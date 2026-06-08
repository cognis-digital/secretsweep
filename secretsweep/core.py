"""SECRETSWEEP — Repo secret scanner."""
from __future__ import annotations
import re, time
from pathlib import Path
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "SECRETSWEEP"
TOOL_VERSION = "0.1.0"

SECRETS = [
    ("SEC-AWS-001","critical",3.0,"AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}"),
    ("SEC-AWS-002","critical",3.0,"AWS_SECRET", r"(?i)aws[_-]?secret[_-]?access[_-]?key[\s:=]{1,4}[A-Za-z0-9/+=]{40}"),
    ("SEC-GH-001", "critical",3.0,"GITHUB_PAT", r"ghp_[A-Za-z0-9]{36}"),
    ("SEC-GH-002", "critical",3.0,"GITHUB_FINEGRAINED", r"github_pat_[A-Za-z0-9_]{82}"),
    ("SEC-SLACK-001","high",2.5,"SLACK_TOKEN", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("SEC-STRIPE-001","critical",3.0,"STRIPE_LIVE", r"sk_live_[A-Za-z0-9]{24,}"),
    ("SEC-OPENAI-001","high",2.5,"OPENAI_KEY", r"sk-[A-Za-z0-9]{20,}"),
    ("SEC-ANTHROPIC-001","high",2.5,"ANTHROPIC_KEY", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("SEC-PRIVKEY-001","critical",3.0,"PRIVATE_KEY", r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("SEC-JWT-001","medium",2.0,"JWT", r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
]
SKIP_DIRS = {".git","node_modules","__pycache__",".venv","dist","build"}

def scan(target: str, **opts) -> ScanResult:
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    p = Path(target)
    files: list[Path] = []
    if p.is_dir():
        for f in p.rglob("*"):
            if not f.is_file(): continue
            if any(part in SKIP_DIRS for part in f.parts): continue
            if f.stat().st_size > 5_000_000: continue
            files.append(f)
    elif p.is_file():
        files = [p]
    result.items_scanned = len(files)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rid,sev,w,cat,pat in SECRETS:
            for m in re.finditer(pat, text):
                line = text.count("\n", 0, m.start()) + 1
                result.add(Finding(
                    id=rid, severity=sev, weight=w, title=cat,
                    description=f"{cat} likely exposed in source: {m.group(0)[:18]}…",
                    location=f"{f}:{line}",
                    remediation=f"Rotate the {cat} immediately. Move to a secret manager (Vault / SSM / Doppler).",
                    category="secret-leak",
                ))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time()-t0)*1000)
    return result
