"""SECRETSWEEP core — secret-scanning engine with bundled provider rules.

A zero-install, standard-library-only secret scanner in the spirit of
gitleaks and trufflehog. It ships:

  * RULES        — 50+ curated provider regex rules (AWS, GCP, Azure,
                   Stripe, GitHub, GitLab, Slack, Twilio, SendGrid, JWT,
                   private keys, OpenAI/Anthropic, ...), each with a
                   precompiled pattern, an optional keyword pre-filter, an
                   entropy floor and a severity.
  * Shannon entropy detection for generic high-entropy strings that no
    provider rule matches (the trufflehog-style "entropy" heuristic).
  * An allowlist layer (literal strings, regex patterns, path globs and a
    placeholder/stop-word heuristic) to suppress test fixtures and
    known-safe values — without clobbering real, structured tokens.
  * Inline allow comments (gitleaks-style ``# secretsweep:allow`` and
    ``# gitleaks:allow``) so a single line can be acknowledged in-place.
  * A baseline layer: a set of finding fingerprints that are known and
    accepted, so ``verify`` only fails on *new* secrets (gitleaks baseline).
  * A line/file/path scanner with redaction and secret fingerprinting so
    the same secret seen twice gets a stable id.

Everything here is real, working logic over real bundled rules — no stubs.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Optional

TOOL_NAME = "secretsweep"
TOOL_VERSION = "2.1.0"

# Standard severities, ordered weakest -> strongest for sorting.
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Inline acknowledgement comments (gitleaks-compatible).
_INLINE_ALLOW_RE = re.compile(
    r"(?:#|//|/\*|--|;)\s*(?:secretsweep|gitleaks)\s*:\s*allow", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------
def shannon_entropy(data: str) -> float:
    """Shannon entropy in bits/char of ``data`` (0.0 for empty)."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return ent


_B64_RE = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{20,}\b")


def _max_entropy_token(line: str, charset: str = "b64") -> tuple[str, float]:
    """Return the (token, entropy) with the highest entropy on ``line``."""
    rx = _B64_RE if charset == "b64" else _HEX_RE
    best, best_e = "", 0.0
    for m in rx.finditer(line):
        tok = m.group(0)
        e = shannon_entropy(tok)
        if e > best_e:
            best, best_e = tok, e
    return best, best_e


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    """A single secret-detection rule."""

    id: str
    description: str
    regex: re.Pattern
    severity: str = "high"
    # Cheap substring gate; if set, the line must contain one of these
    # (case-insensitive) before the regex is tried.
    keywords: tuple[str, ...] = ()
    # Minimum Shannon entropy (bits/char) the matched secret must have.
    entropy: float = 0.0
    # Which group of the match holds the actual secret (default whole match).
    secret_group: int = 0
    # If True, the allowlist placeholder heuristic is skipped for this rule:
    # the token is so structured (provider prefix) that placeholder words
    # appearing inside it are almost certainly part of a real-shaped key.
    structured: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "severity": self.severity,
            "regex": self.regex.pattern,
            "keywords": list(self.keywords),
            "entropy": self.entropy,
            "structured": self.structured,
        }


def _r(id, desc, pattern, severity="high", keywords=(), entropy=0.0,
       group=0, flags=0, structured=False):
    return Rule(
        id=id,
        description=desc,
        regex=re.compile(pattern, flags),
        severity=severity,
        keywords=tuple(k.lower() for k in keywords),
        entropy=entropy,
        secret_group=group,
        structured=structured,
    )


# A generic "assignment" context that many provider rules reuse to capture a
# quoted/bare value following key= / key: / key => style declarations.
_ASSIGN = r"""(?:=|:|:=|=>|\s)\s*['"]?"""

RULES: tuple[Rule, ...] = (
    # --- Cloud: AWS ---------------------------------------------------------
    _r("aws-access-key-id",
       "AWS Access Key ID",
       r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b",
       "high", keywords=("akia", "abia", "acca", "asia"), group=1,
       structured=True),
    _r("aws-secret-access-key",
       "AWS Secret Access Key",
       r"(?i)aws_?(?:secret)?_?(?:access)?_?key" + _ASSIGN +
       r"([A-Za-z0-9/+=]{40})",
       "critical", keywords=("aws", "secret"), entropy=3.5, group=1),
    _r("aws-session-token",
       "AWS Session Token",
       r"(?i)aws_session_token" + _ASSIGN + r"([A-Za-z0-9/+=]{100,})",
       "high", keywords=("aws_session_token",), entropy=4.0, group=1),
    _r("aws-mws-key",
       "AWS MWS auth token",
       r"\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
       r"[0-9a-f]{4}-[0-9a-f]{12})\b",
       "high", keywords=("amzn.mws",), group=1, structured=True),

    # --- Cloud: GCP / Google ------------------------------------------------
    _r("gcp-api-key",
       "Google API key",
       r"\b(AIza[0-9A-Za-z\-_]{35,36})\b",
       "high", keywords=("aiza",), group=1, structured=True),
    _r("gcp-oauth-client-id",
       "Google OAuth client ID",
       r"\b([0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com)\b",
       "medium", keywords=("googleusercontent",), group=1, structured=True),
    _r("gcp-service-account",
       "GCP service-account private_key_id block",
       r'(?i)"private_key_id"\s*:\s*"([0-9a-f]{40})"',
       "critical", keywords=("private_key_id",), group=1),
    _r("firebase-cloud-messaging",
       "Firebase Cloud Messaging server key",
       r"\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})\b",
       "high", keywords=("aaaa",), group=1, structured=True),

    # --- Cloud: Azure -------------------------------------------------------
    _r("azure-storage-key",
       "Azure storage account key (AccountKey=)",
       r"(?i)AccountKey" + _ASSIGN + r"([A-Za-z0-9+/=]{86}==)",
       "critical", keywords=("accountkey",), entropy=4.0, group=1),
    _r("azure-sas-token",
       "Azure shared-access-signature token",
       r"(?i)\bsig=([A-Za-z0-9%/+=]{40,})",
       "medium", keywords=("sig=",), group=1),
    _r("azure-ad-client-secret",
       "Azure AD client secret",
       r"\b([A-Za-z0-9_~.\-]{3}8Q~[A-Za-z0-9_~.\-]{34})\b",
       "high", keywords=("8q~",), group=1, structured=True),

    # --- Payments -----------------------------------------------------------
    _r("stripe-secret-key",
       "Stripe secret/restricted key",
       r"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,})\b",
       "critical", keywords=("sk_live", "sk_test", "rk_live", "rk_test"),
       group=1, structured=True),
    _r("stripe-publishable-key",
       "Stripe publishable key",
       r"\b(pk_(?:live|test)_[0-9A-Za-z]{20,})\b",
       "low", keywords=("pk_live", "pk_test"), group=1, structured=True),
    _r("square-access-token",
       "Square access token",
       r"\b(sq0atp-[0-9A-Za-z\-_]{22})\b",
       "high", keywords=("sq0atp",), group=1, structured=True),
    _r("square-oauth-secret",
       "Square OAuth secret",
       r"\b(sq0csp-[0-9A-Za-z\-_]{43})\b",
       "high", keywords=("sq0csp",), group=1, structured=True),
    _r("paypal-braintree-token",
       "PayPal/Braintree access token",
       r"\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b",
       "high", keywords=("access_token$production",), group=1,
       structured=True),

    # --- Source hosting -----------------------------------------------------
    _r("github-pat",
       "GitHub personal access token (classic/fine-grained)",
       r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{36,255})\b",
       "critical", keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_",
                             "github_pat"), group=1, structured=True),
    _r("github-oauth",
       "GitHub OAuth access token (40 hex with context)",
       r"(?i)github.{0,20}" + _ASSIGN + r"([0-9a-f]{40})",
       "high", keywords=("github",), entropy=3.0, group=1),
    _r("gitlab-pat",
       "GitLab personal access token",
       r"\b(glpat-[0-9A-Za-z\-_]{20})\b",
       "high", keywords=("glpat-",), group=1, structured=True),
    _r("gitlab-pipeline-token",
       "GitLab CI/CD pipeline trigger token",
       r"\b(glptt-[0-9a-f]{40})\b",
       "high", keywords=("glptt-",), group=1, structured=True),
    _r("npm-access-token",
       "npm access token",
       r"\b(npm_[0-9A-Za-z]{36})\b",
       "high", keywords=("npm_",), group=1, structured=True),
    _r("pypi-upload-token",
       "PyPI upload token",
       r"\b(pypi-AgEIcHlwaS5vcmc[0-9A-Za-z\-_]{50,})\b",
       "high", keywords=("pypi-",), group=1, structured=True),
    _r("dockerhub-pat",
       "Docker Hub personal access token",
       r"\b(dckr_pat_[0-9A-Za-z\-_]{27})\b",
       "high", keywords=("dckr_pat_",), group=1, structured=True),
    _r("atlassian-api-token",
       "Atlassian/Jira/Confluence API token",
       r"\b(ATATT3[A-Za-z0-9_\-=]{180,})\b",
       "high", keywords=("atatt3",), group=1, structured=True),

    # --- Messaging / comms --------------------------------------------------
    _r("slack-token",
       "Slack token (bot/user/app/legacy)",
       r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b",
       "high", keywords=("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"),
       group=1, structured=True),
    _r("slack-webhook",
       "Slack incoming webhook URL",
       r"(https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/"
       r"[0-9A-Za-z]{24})",
       "medium", keywords=("hooks.slack.com",), group=1, structured=True),
    _r("discord-bot-token",
       "Discord bot token",
       r"\b([MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\."
       r"[A-Za-z0-9_\-]{27,})\b",
       "high", keywords=(), entropy=4.0, group=1, structured=True),
    _r("discord-webhook",
       "Discord webhook URL",
       r"(https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/"
       r"[0-9A-Za-z_\-]{60,})",
       "medium", keywords=("discord",), group=1, structured=True),
    _r("telegram-bot-token",
       "Telegram bot token",
       r"\b([0-9]{8,10}:AA[0-9A-Za-z_\-]{33})\b",
       "high", keywords=(":aa",), group=1, structured=True),
    _r("twilio-api-key",
       "Twilio API key SID",
       r"\b(SK[0-9a-fA-F]{32})\b",
       "high", keywords=("sk",), entropy=3.0, group=1, structured=True),
    _r("twilio-account-sid",
       "Twilio account SID",
       r"\b(AC[0-9a-fA-F]{32})\b",
       "medium", keywords=("ac",), entropy=3.0, group=1, structured=True),
    _r("sendgrid-api-key",
       "SendGrid API key",
       r"\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b",
       "high", keywords=("sg.",), group=1, structured=True),
    _r("mailgun-api-key",
       "Mailgun API key",
       r"\b(key-[0-9a-f]{32})\b",
       "high", keywords=("key-",), group=1, structured=True),
    _r("mailchimp-api-key",
       "Mailchimp API key",
       r"\b([0-9a-f]{32}-us[0-9]{1,2})\b",
       "high", keywords=("-us",), group=1, structured=True),
    _r("postmark-server-token",
       "Postmark server token",
       r"(?i)postmark.{0,20}" + _ASSIGN +
       r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
       "medium", keywords=("postmark",), group=1),

    # --- SaaS / infra -------------------------------------------------------
    _r("datadog-api-key",
       "Datadog API key",
       r"(?i)datadog.{0,20}" + _ASSIGN + r"([0-9a-f]{32})",
       "medium", keywords=("datadog",), group=1),
    _r("pagerduty-token",
       "PagerDuty API token",
       r"\b([0-9a-zA-Z_\-]{20}\+[0-9a-zA-Z_\-]{20})\b",
       "low", keywords=("pagerduty",), entropy=4.0, group=1),
    _r("newrelic-key",
       "New Relic license/user key",
       r"\b(NRAK-[0-9A-Z]{27})\b",
       "high", keywords=("nrak-",), group=1, structured=True),
    _r("heroku-api-key",
       "Heroku API key (UUID with context)",
       r"(?i)heroku.{0,20}" + _ASSIGN +
       r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
       "high", keywords=("heroku",), group=1),
    _r("digitalocean-pat",
       "DigitalOcean personal access token",
       r"\b(dop_v1_[0-9a-f]{64})\b",
       "high", keywords=("dop_v1_",), group=1, structured=True),
    _r("cloudflare-api-token",
       "Cloudflare API token",
       r"(?i)cloudflare.{0,20}" + _ASSIGN + r"([A-Za-z0-9_\-]{40})",
       "high", keywords=("cloudflare",), entropy=4.0, group=1),
    _r("openai-api-key",
       "OpenAI API key",
       r"\b(sk-(?:proj-)?[0-9A-Za-z_\-]{20,})\b",
       "high", keywords=("sk-",), entropy=3.5, group=1, structured=True),
    _r("anthropic-api-key",
       "Anthropic API key",
       r"\b(sk-ant-[0-9A-Za-z_\-]{90,})\b",
       "high", keywords=("sk-ant-",), group=1, structured=True),
    _r("huggingface-token",
       "Hugging Face access token",
       r"\b(hf_[0-9A-Za-z]{34})\b",
       "high", keywords=("hf_",), group=1, structured=True),
    _r("shopify-token",
       "Shopify access token",
       r"\b(shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32})\b",
       "high", keywords=("shpat_", "shpca_", "shppa_", "shpss_"), group=1,
       structured=True),
    _r("algolia-admin-key",
       "Algolia admin API key",
       r"(?i)algolia.{0,20}" + _ASSIGN + r"([0-9a-f]{32})",
       "medium", keywords=("algolia",), group=1),
    _r("airtable-key",
       "Airtable API key",
       r"\b(key[0-9A-Za-z]{14})\b",
       "low", keywords=("airtable",), group=1),
    _r("linear-api-key",
       "Linear API key",
       r"\b(lin_api_[0-9A-Za-z]{40})\b",
       "high", keywords=("lin_api_",), group=1, structured=True),
    _r("sentry-dsn",
       "Sentry DSN with secret",
       r"(https://[0-9a-f]{32}(?::[0-9a-f]{32})?@[0-9a-z.\-]+/[0-9]+)",
       "medium", keywords=("sentry.io", "@",), group=1, structured=True),
    _r("databricks-token",
       "Databricks personal access token",
       r"\b(dapi[0-9a-f]{32}(?:-[0-9]+)?)\b",
       "high", keywords=("dapi",), group=1, structured=True),
    _r("planetscale-token",
       "PlanetScale database password",
       r"\b(pscale_pw_[0-9A-Za-z_\-]{43})\b",
       "high", keywords=("pscale_pw_",), group=1, structured=True),
    _r("supabase-service-key",
       "Supabase service-role JWT context",
       r"(?i)supabase.{0,20}service.{0,12}" + _ASSIGN +
       r"(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})",
       "high", keywords=("supabase",), group=1, structured=True),

    # --- Generic / crypto ---------------------------------------------------
    _r("private-key",
       "PEM-encoded private key block",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
       "critical", keywords=("private key",), structured=True),
    _r("ssh-encrypted-private-key",
       "Encrypted/PuTTY private key header",
       r"PuTTY-User-Key-File-[0-9]",
       "critical", keywords=("putty-user-key",), structured=True),
    _r("jwt",
       "JSON Web Token (header.payload.signature)",
       r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}"
       r"\.[A-Za-z0-9_\-]{10,})\b",
       "medium", keywords=("eyj",), group=1, structured=True),
    _r("basic-auth-url",
       "Credentials embedded in URL",
       r"\b([a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]{3,}@[^/\s]+)",
       "high", keywords=("://",), group=1, structured=True),
    _r("generic-password-assign",
       "Hard-coded password assignment",
       r"(?i)(?:password|passwd|pwd)" + _ASSIGN + r"([^'\"\s]{8,})['\"]?",
       "medium", keywords=("password", "passwd", "pwd"), entropy=2.5, group=1),
    _r("generic-api-key-assign",
       "Hard-coded api key/token/secret assignment",
       r"(?i)(?:api[_-]?key|secret|token|access[_-]?key)" + _ASSIGN +
       r"([0-9A-Za-z/+=_\-]{16,})['\"]?",
       "medium", keywords=("api", "secret", "token", "key"),
       entropy=3.0, group=1),
)


def rule_by_id(rule_id: str) -> Optional[Rule]:
    for r in RULES:
        if r.id == rule_id:
            return r
    return None


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------
# Placeholder tokens that mark a candidate as a fixture/example rather than a
# real leaked secret. These are matched as *whole words* (split on non-alnum)
# so they don't accidentally suppress real keys that merely contain "test" or
# a "1234567890" run as a substring.
DEFAULT_STOPWORDS = (
    "example", "examplekey", "sample", "placeholder", "changeme", "change",
    "redacted", "dummy", "test", "fake", "foo", "bar", "baz", "todo",
    "xxxx", "xxxxxx", "your", "yourkey", "yourapikey", "mysecret", "secret",
    "password", "deadbeef", "abcdef", "lorem", "ipsum", "notarealkey",
    "donotuse", "insertkey", "replaceme",
)

_WORD_SPLIT = re.compile(r"[^a-z0-9]+")


@dataclass
class Allowlist:
    """Suppresses known-safe values / paths / fixtures."""

    literals: set[str] = field(default_factory=set)
    regexes: list[re.Pattern] = field(default_factory=list)
    path_globs: list[str] = field(default_factory=list)
    stopwords: tuple[str, ...] = DEFAULT_STOPWORDS

    @classmethod
    def from_iterables(cls, literals=(), regexes=(), path_globs=(),
                       stopwords=None) -> "Allowlist":
        compiled: list[re.Pattern] = []
        for pat in regexes:
            try:
                compiled.append(re.compile(pat))
            except re.error as exc:
                raise ValueError(
                    f"Invalid allowlist regex {pat!r}: {exc}"
                ) from exc
        return cls(
            literals=set(literals),
            regexes=compiled,
            path_globs=list(path_globs),
            stopwords=tuple(stopwords) if stopwords is not None
            else DEFAULT_STOPWORDS,
        )

    @classmethod
    def from_config(cls, cfg: dict) -> "Allowlist":
        """Build from a parsed JSON config dict (see ``load_config``)."""
        al = cfg.get("allowlist", {}) if cfg else {}
        return cls.from_iterables(
            literals=al.get("literals", ()),
            regexes=al.get("regexes", ()),
            path_globs=al.get("paths", ()),
            stopwords=al.get("stopwords") if al.get("stopwords") else None,
        )

    def path_allowed(self, path: str) -> bool:
        norm = path.replace("\\", "/")
        for g in self.path_globs:
            if fnmatch.fnmatch(norm, g) or fnmatch.fnmatch(
                    os.path.basename(norm), g):
                return True
        return False

    def _is_placeholder(self, secret: str) -> bool:
        """True only when placeholder words *dominate* the candidate.

        We tokenize the secret on non-alphanumeric boundaries and on
        camelCase-ish runs, then check whether the matched stop-words cover a
        majority of the alphabetic content. This stops fixtures like
        ``your_api_key_here_changeme`` while leaving structured keys such as
        ``ghp_aBcDeF...0123456789`` (which merely *contains* a digit run)
        untouched.
        """
        low = secret.lower()
        words = [w for w in _WORD_SPLIT.split(low) if w]
        if not words:
            return False
        sw = set(self.stopwords)
        # Count letters belonging to a stop-word token.
        covered = 0
        total_alpha = sum(sum(c.isalpha() for c in w) for w in words)
        for w in words:
            # exact word, or word that is itself a stop-word run
            if w in sw:
                covered += sum(c.isalpha() for c in w)
        if total_alpha == 0:
            return False
        return covered / total_alpha >= 0.6

    def secret_allowed(self, secret: str, structured: bool = False) -> bool:
        if secret in self.literals:
            return True
        for rx in self.regexes:
            if rx.search(secret):
                return True
        # Structured provider tokens are not subjected to the placeholder
        # heuristic — their shape is the evidence.
        if not structured and self._is_placeholder(secret):
            return True
        return False


# ---------------------------------------------------------------------------
# Config / baseline (gitleaks-style)
# ---------------------------------------------------------------------------
def load_config(path: str) -> dict:
    """Load a JSON config file. Returns {} if missing/empty.

    Schema (all optional)::

        {
          "allowlist": {
            "literals": ["..."],
            "regexes": ["..."],
            "paths": ["*/tests/*", "*.lock"],
            "stopwords": ["example", ...]
          },
          "entropy": {"enabled": true, "threshold": 4.3, "min_len": 20},
          "disabled_rules": ["stripe-publishable-key"]
        }

    Raises:
        ValueError: if the file exists but contains invalid JSON.
        OSError: if the file exists but cannot be read.
    """
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise OSError(f"Cannot read config file {path!r}: {exc}") from exc
    if not raw.strip():
        return {}
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Config file {path!r} contains invalid JSON: {exc}"
        ) from exc
    if not isinstance(result, dict):
        raise ValueError(
            f"Config file {path!r} must be a JSON object, got "
            f"{type(result).__name__}"
        )
    return result


def load_baseline(path: str) -> set[str]:
    """Load a baseline file: a JSON list of accepted finding fingerprints.

    Accepts either a bare ``["fp1", "fp2"]`` list or a
    ``{"fingerprints": [...]}`` object, or a newline-delimited text file.

    Raises:
        OSError: if the file exists but cannot be read.
    """
    if not path or not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    except OSError as exc:
        raise OSError(f"Cannot read baseline file {path!r}: {exc}") from exc
    if not raw:
        return set()
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            fps = data.get("fingerprints", [])
            if not isinstance(fps, list):
                raise ValueError(
                    f"Baseline {path!r}: 'fingerprints' must be a list"
                )
            return set(str(fp) for fp in fps if fp)
        if isinstance(data, list):
            return set(str(fp) for fp in data if fp)
        raise ValueError(
            f"Baseline {path!r} must be a JSON list or object, got "
            f"{type(data).__name__}"
        )
    except json.JSONDecodeError:
        # Fall back to newline-delimited text format.
        return {ln.strip() for ln in raw.splitlines() if ln.strip()
                and not ln.lstrip().startswith("#")}


def write_baseline(path: str, findings: "list[Finding]") -> int:
    """Write the fingerprints of ``findings`` to a baseline file. Returns n.

    Raises:
        OSError: if the file cannot be created or written.
    """
    fps = sorted({f.fingerprint for f in findings})
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"tool": TOOL_NAME, "version": TOOL_VERSION,
                       "fingerprints": fps}, fh, indent=2)
    except OSError as exc:
        raise OSError(f"Cannot write baseline to {path!r}: {exc}") from exc
    return len(fps)


# ---------------------------------------------------------------------------
# Findings + scanner
# ---------------------------------------------------------------------------
def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return (secret[0] + "*" * (len(secret) - 1)) if secret else ""
    return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"


def _fingerprint(rule_id: str, secret: str) -> str:
    h = hashlib.sha256(f"{rule_id}:{secret}".encode("utf-8")).hexdigest()
    return h[:16]


@dataclass
class Finding:
    rule_id: str
    description: str
    severity: str
    path: str
    line: int
    col: int
    match: str          # redacted
    entropy: float
    fingerprint: str

    # ------------------------------------------------------------------
    # Convenience aliases
    # ------------------------------------------------------------------
    @property
    def detector_id(self) -> str:
        """Alias for :attr:`rule_id` (compatibility with older API)."""
        return self.rule_id

    @property
    def provider(self) -> str:
        """Provider name derived from the rule id (e.g. ``"aws"``, ``"github"``)."""
        return self.rule_id.split("-")[0]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "col": self.col,
            "match": self.match,
            "entropy": round(self.entropy, 3),
            "fingerprint": self.fingerprint,
        }


@dataclass
class Engine:
    """Holds the active rule set, allowlist and entropy config."""

    rules: tuple[Rule, ...] = RULES
    allowlist: Allowlist = field(default_factory=Allowlist)
    entropy_enabled: bool = True
    entropy_threshold: float = 4.3   # bits/char; trufflehog-ish default
    min_entropy_len: int = 20
    baseline: set[str] = field(default_factory=set)
    respect_inline_allow: bool = True

    @classmethod
    def from_config(cls, cfg: dict, baseline: Optional[set[str]] = None,
                    **overrides) -> "Engine":
        ent = (cfg or {}).get("entropy", {})
        disabled = set((cfg or {}).get("disabled_rules", []))
        rules = tuple(r for r in RULES if r.id not in disabled)
        eng = cls(
            rules=rules,
            allowlist=Allowlist.from_config(cfg or {}),
            entropy_enabled=ent.get("enabled", True),
            entropy_threshold=ent.get("threshold", 4.3),
            min_entropy_len=ent.get("min_len", 20),
            baseline=baseline or set(),
        )
        for k, v in overrides.items():
            setattr(eng, k, v)
        return eng

    def scan_line(self, line: str, path: str, lineno: int) -> Iterator[Finding]:
        if self.respect_inline_allow and _INLINE_ALLOW_RE.search(line):
            return
        low = line.lower()
        seen: set[str] = set()
        for rule in self.rules:
            if rule.keywords and not any(k in low for k in rule.keywords):
                continue
            for m in rule.regex.finditer(line):
                secret = m.group(rule.secret_group) if rule.secret_group \
                    else m.group(0)
                if not secret:
                    continue
                ent = shannon_entropy(secret)
                if rule.entropy and ent < rule.entropy:
                    continue
                if self.allowlist.secret_allowed(secret, rule.structured):
                    continue
                fp = _fingerprint(rule.id, secret)
                if fp in self.baseline:
                    continue
                key = f"{rule.id}:{m.start()}"
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    rule_id=rule.id,
                    description=rule.description,
                    severity=rule.severity,
                    path=path,
                    line=lineno,
                    col=(m.start(rule.secret_group) + 1) if rule.secret_group
                    else m.start() + 1,
                    match=_redact(secret),
                    entropy=ent,
                    fingerprint=fp,
                )

        if self.entropy_enabled:
            yield from self._scan_entropy(line, path, lineno, seen)

    def _scan_entropy(self, line, path, lineno, seen) -> Iterator[Finding]:
        for charset in ("b64", "hex"):
            tok, ent = _max_entropy_token(line, charset)
            if len(tok) < self.min_entropy_len:
                continue
            if ent < self.entropy_threshold:
                continue
            if self.allowlist.secret_allowed(tok):
                continue
            fp = _fingerprint("high-entropy", tok)
            if fp in self.baseline or fp in seen:
                continue
            seen.add(fp)
            col = line.find(tok) + 1
            yield Finding(
                rule_id="high-entropy-string",
                description=f"High-entropy {charset} string "
                            f"({ent:.2f} bits/char)",
                severity="low",
                path=path,
                line=lineno,
                col=col,
                match=_redact(tok),
                entropy=ent,
                fingerprint=fp,
            )

    def scan_lines(self, lines: Iterable[str], path: str = "<stdin>"
                   ) -> list[Finding]:
        out: list[Finding] = []
        for i, line in enumerate(lines, start=1):
            out.extend(self.scan_line(line.rstrip("\n"), path, i))
        return out

    def scan_text(self, text: str, path: str = "<text>") -> list[Finding]:
        return self.scan_lines(text.splitlines(), path)

    def scan_file(self, path: str) -> list[Finding]:
        if self.allowlist.path_allowed(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return self.scan_lines(fh, path)
        except (IsADirectoryError, PermissionError):
            return []

    def scan_path(self, root: str) -> list[Finding]:
        if os.path.isfile(root):
            return self.scan_file(root)
        if not os.path.exists(root):
            raise FileNotFoundError(
                f"scan_path: path does not exist: {root!r}"
            )
        findings: list[Finding] = []
        for dirpath, dirnames, filenames in os.walk(root):
            # skip obvious VCS / dependency dirs
            dirnames[:] = [d for d in dirnames if d not in
                           (".git", ".hg", ".svn", "node_modules",
                            "__pycache__", ".venv", "venv")]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if self.allowlist.path_allowed(full):
                    continue
                if _looks_binary(full):
                    continue
                findings.extend(self.scan_file(full))
        return findings


_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".wav", ".so", ".dll",
    ".exe", ".class", ".pyc", ".o", ".a", ".bin", ".dat",
}


def _looks_binary(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in _BINARY_EXTS:
        return True
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(1024)
        return b"\x00" in chunk
    except OSError:
        return True


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.path, f.line),
    )


def summarize(findings: list[Finding]) -> dict:
    by_sev: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_rule": by_rule,
    }


# ---------------------------------------------------------------------------
# Public aliases / convenience helpers
# ---------------------------------------------------------------------------

# DETECTORS is a public alias for RULES (same object, different name style).
DETECTORS: tuple[Rule, ...] = RULES


def redact(secret: str) -> str:
    """Return a redacted copy of *secret* (public alias for ``_redact``)."""
    return _redact(secret)


# Provider name derived from the first dash-delimited segment of a rule id.
# e.g. "aws-access-key-id" -> "aws", "github-pat" -> "github".
def _provider_for_rule(rule_id: str) -> str:
    return rule_id.split("-")[0]


# Per-provider rotation guidance bundled with the tool so callers get
# actionable next steps without a network round-trip.
_ROTATION_STEPS: dict[str, list[str]] = {
    "aws": [
        "Go to IAM console → Users → Security credentials.",
        "Create a new access key before deleting the exposed one.",
        "Update all services/CI with the new key.",
        "Deactivate then delete the old key.",
        "Enable CloudTrail to audit any accesses that occurred.",
    ],
    "github": [
        "Go to GitHub → Settings → Developer settings → Personal access tokens.",
        "Delete or regenerate the exposed token immediately.",
        "Audit recent API activity via the token's last-used timestamp.",
        "Create a new token with minimal required scopes.",
    ],
    "stripe": [
        "Open the Stripe Dashboard → Developers → API keys.",
        "Roll the exposed key using the 'Roll key' button.",
        "Update all integrations with the new key.",
        "Check Stripe Radar for unusual payment activity.",
    ],
    "slack": [
        "Go to api.slack.com → Your Apps → select the app → OAuth & Permissions.",
        "Revoke the exposed token.",
        "Re-install the app to generate a new token.",
        "Audit the audit log in Slack for suspicious bot actions.",
    ],
    "gcp": [
        "Open the GCP Console → APIs & Services → Credentials.",
        "Delete the exposed API key or rotate the service-account key.",
        "Create a replacement with minimal IAM permissions.",
        "Check Cloud Audit Logs for activity on the compromised credential.",
    ],
    "azure": [
        "Open the Azure Portal → Storage account → Access keys.",
        "Regenerate the affected key.",
        "Update all connection strings and apps using that key.",
        "Review Azure Monitor / Activity Log for suspicious operations.",
    ],
    "gitlab": [
        "Go to GitLab → User settings → Access tokens.",
        "Revoke the exposed token.",
        "Create a new token with the minimum required scopes.",
    ],
    "generic": [
        "Treat the secret as compromised — rotate it immediately.",
        "Search your commit history and remove the secret (use git-filter-repo).",
        "Audit access logs for the affected service.",
        "Store the replacement in a secrets manager (Vault, AWS SSM, etc.).",
    ],
}


def rotation_plan(findings: "list[Finding]") -> list[dict]:
    """Return a prioritised rotation checklist for *findings*.

    Each entry describes the provider, the redacted match, and actionable
    rotation steps so the caller can immediately start remediation.
    """
    seen_fps: set[str] = set()
    plan: list[dict] = []
    for f in sort_findings(findings):
        if f.fingerprint in seen_fps:
            continue
        seen_fps.add(f.fingerprint)
        provider = _provider_for_rule(f.rule_id)
        steps = _ROTATION_STEPS.get(provider, _ROTATION_STEPS["generic"])
        plan.append({
            "provider": provider,
            "rule_id": f.rule_id,
            "severity": f.severity,
            "path": f.path,
            "line": f.line,
            "match": f.match,
            "rotation_steps": steps,
        })
    return plan


def scan_text(text: str, path: str = "<text>",
              providers: "Optional[list[str]]" = None) -> "list[Finding]":
    """Convenience wrapper: scan *text* with default engine settings.

    Args:
        text:      The raw text content to scan.
        path:      Label used in ``Finding.path`` (default ``"<text>"``).
        providers: If given, only findings whose provider matches one of the
                   listed names are returned (e.g. ``["github", "aws"]``).

    Returns:
        List of :class:`Finding` objects, sorted by severity.
    """
    engine = Engine()
    findings = engine.scan_text(text, path)
    if providers is not None:
        keep = {p.lower() for p in providers}
        findings = [f for f in findings
                    if _provider_for_rule(f.rule_id) in keep]
    return findings
