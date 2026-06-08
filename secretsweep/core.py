"""Core engine for SECRETSWEEP.

Provider-aware credential detection (regex + entropy verification), in-place
redaction, and a provider-specific rotation playbook. No network access.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, Iterable, List, Optional, Pattern

# Files/dirs we never walk into during a directory scan.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar",
    ".whl", ".exe", ".dll", ".so", ".pyc", ".ico", ".woff", ".woff2",
}
_MAX_BYTES = 2 * 1024 * 1024  # skip files larger than 2 MiB


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. High entropy => looks random/secret-like."""
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass(frozen=True)
class Detector:
    """A single provider credential detector."""
    id: str
    provider: str
    description: str
    pattern: Pattern[str]
    # minimum entropy of the matched secret group required to flag (0 = skip)
    min_entropy: float = 0.0
    # how to rotate the secret once leaked (human playbook)
    rotation: str = ""

    def verify(self, secret: str) -> bool:
        if self.min_entropy <= 0:
            return True
        return shannon_entropy(secret) >= self.min_entropy


@dataclass
class Finding:
    detector_id: str
    provider: str
    description: str
    path: str
    line: int
    column: int
    match: str          # redacted representation of the secret
    entropy: float
    rotation: str
    raw_len: int

    def to_dict(self) -> dict:
        return asdict(self)


def _C(p: str) -> Pattern[str]:
    return re.compile(p)


# Capture group 1 (or the named 'secret' group) is the sensitive value.
DETECTORS: List[Detector] = [
    Detector(
        id="aws-access-key-id",
        provider="aws",
        description="AWS Access Key ID",
        pattern=_C(r"\b((?:AKIA|ASIA|AIDA|AGPA)[0-9A-Z]{16})\b"),
        rotation="aws iam create-access-key then delete the leaked key id; "
                 "prefer STS/role-based creds.",
    ),
    Detector(
        id="aws-secret-access-key",
        provider="aws",
        description="AWS Secret Access Key",
        pattern=_C(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        min_entropy=4.0,
        rotation="Deactivate+delete the access key pair in IAM; audit CloudTrail.",
    ),
    Detector(
        id="github-pat",
        provider="github",
        description="GitHub Personal Access Token",
        pattern=_C(r"\b(ghp_[A-Za-z0-9]{36})\b"),
        rotation="Revoke at github.com/settings/tokens; regenerate with least scope.",
    ),
    Detector(
        id="github-fine-grained-pat",
        provider="github",
        description="GitHub Fine-grained PAT",
        pattern=_C(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        rotation="Revoke the fine-grained token in developer settings.",
    ),
    Detector(
        id="slack-token",
        provider="slack",
        description="Slack Token",
        pattern=_C(r"\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b"),
        rotation="Revoke via api.slack.com/apps -> OAuth, rotate signing secret.",
    ),
    Detector(
        id="stripe-secret-key",
        provider="stripe",
        description="Stripe Secret Key",
        pattern=_C(r"\b(sk_(?:live|test)_[0-9A-Za-z]{24,99})\b"),
        rotation="Roll the key in the Stripe Dashboard -> Developers -> API keys.",
    ),
    Detector(
        id="google-api-key",
        provider="google",
        description="Google API Key",
        pattern=_C(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        rotation="Regenerate/restrict the key in Google Cloud Console -> Credentials.",
    ),
    Detector(
        id="openai-api-key",
        provider="openai",
        description="OpenAI API Key",
        pattern=_C(r"\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b"),
        rotation="Revoke at platform.openai.com/api-keys and issue a new key.",
    ),
    Detector(
        id="private-key-block",
        provider="generic",
        description="PEM Private Key block",
        pattern=_C(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        rotation="Generate a new keypair; revoke the old public key everywhere it is trusted.",
    ),
    Detector(
        id="jwt",
        provider="generic",
        description="JSON Web Token",
        pattern=_C(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        min_entropy=3.5,
        rotation="Rotate the signing secret/key so existing tokens are invalidated.",
    ),
    Detector(
        id="generic-high-entropy-assignment",
        provider="generic",
        description="High-entropy secret assignment",
        pattern=_C(
            r"(?i)(?:secret|token|passwd|password|api[_-]?key|access[_-]?key)"
            r"\s*[:=]\s*['\"]([A-Za-z0-9/+_\-=]{20,100})['\"]"
        ),
        min_entropy=4.0,
        rotation="Rotate the credential at its source provider and purge from history.",
    ),
]

_DETECTOR_INDEX = {d.id: d for d in DETECTORS}


def redact(secret: str) -> str:
    """Mask a secret leaving only a short prefix/suffix for identification."""
    n = len(secret)
    if n <= 8:
        return "*" * n
    keep = 3
    return f"{secret[:keep]}{'*' * (n - 2 * keep)}{secret[-keep:]}"


def _select(detectors: Iterable[Detector], providers: Optional[Iterable[str]]) -> List[Detector]:
    if not providers:
        return list(detectors)
    want = {p.lower() for p in providers}
    return [d for d in detectors if d.provider in want]


def scan_text(
    text: str,
    path: str = "<stdin>",
    providers: Optional[Iterable[str]] = None,
    detectors: Optional[Iterable[Detector]] = None,
) -> List[Finding]:
    """Scan a blob of text and return findings (entropy-verified)."""
    dets = _select(detectors or DETECTORS, providers)
    # Precompute line start offsets for column/line resolution.
    line_starts = [0]
    for m in re.finditer(r"\n", text):
        line_starts.append(m.end())

    def locate(offset: int) -> tuple[int, int]:
        # binary-ish search over line starts
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, offset - line_starts[lo] + 1

    findings: List[Finding] = []
    seen: set[tuple[str, int]] = set()
    for det in dets:
        for m in det.pattern.finditer(text):
            secret = m.group(1) if m.groups() else m.group(0)
            if not det.verify(secret):
                continue
            start = m.start(1) if m.groups() else m.start(0)
            key = (det.id, start)
            if key in seen:
                continue
            seen.add(key)
            line, col = locate(start)
            findings.append(
                Finding(
                    detector_id=det.id,
                    provider=det.provider,
                    description=det.description,
                    path=path,
                    line=line,
                    column=col,
                    match=redact(secret),
                    entropy=round(shannon_entropy(secret), 3),
                    rotation=det.rotation,
                    raw_len=len(secret),
                )
            )
    findings.sort(key=lambda f: (f.path, f.line, f.column))
    return findings


def _is_scannable(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in _BINARY_EXTS:
        return False
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            return False
    except OSError:
        return False
    return True


def scan_path(
    target: str,
    providers: Optional[Iterable[str]] = None,
    detectors: Optional[Iterable[Detector]] = None,
) -> List[Finding]:
    """Scan a file or directory tree, returning all findings."""
    findings: List[Finding] = []
    if os.path.isfile(target):
        files = [target]
    elif os.path.isdir(target):
        files = []
        for root, dirs, names in os.walk(target):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in names:
                files.append(os.path.join(root, name))
    else:
        raise FileNotFoundError(f"no such file or directory: {target}")

    for fp in files:
        if not _is_scannable(fp):
            continue
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (OSError, UnicodeError):
            continue
        findings.extend(scan_text(text, path=fp, providers=providers, detectors=detectors))
    return findings


def rotation_plan(findings: List[Finding]) -> List[dict]:
    """Group findings by provider into an actionable rotation playbook."""
    by_provider: Dict[str, List[Finding]] = {}
    for f in findings:
        by_provider.setdefault(f.provider, []).append(f)
    plan: List[dict] = []
    for provider in sorted(by_provider):
        items = by_provider[provider]
        steps = sorted({i.rotation for i in items if i.rotation})
        plan.append(
            {
                "provider": provider,
                "leaked_count": len(items),
                "locations": [f"{i.path}:{i.line}" for i in items],
                "rotation_steps": steps,
            }
        )
    return plan
