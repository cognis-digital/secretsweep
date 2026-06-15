"""SECRETSWEEP command-line interface.

Subcommands:
  scan     - scan files/dirs (or stdin) for secrets
  verify   - scan, but only fail on findings NOT in a baseline (for CI)
  baseline - scan and write a baseline file of accepted fingerprints
  rules    - list the bundled provider rule pack
  entropy  - compute Shannon entropy of a string (debugging aid)

Exit codes:
  0  success, no (new) findings
  1  usage / runtime error
  2  secrets found (scan) / new secrets found (verify)
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    RULES,
    SEVERITY_ORDER,
    Engine,
    Finding,
    load_baseline,
    load_config,
    rotation_plan,
    shannon_entropy,
    sort_findings,
    summarize,
    write_baseline,
)

EXIT_OK = 0
EXIT_ERR = 1
EXIT_FINDINGS = 2


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _table(rows: list[list[str]], headers: list[str]) -> str:
    cols = list(zip(*([headers] + rows))) if rows else [[h] for h in headers]
    widths = [max(len(str(c)) for c in col) for col in cols]
    line = "  ".join(str(h).ljust(w) for h, w in zip(headers, widths))
    out = [line, "  ".join("-" * w for w in widths)]
    for r in rows:
        out.append("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    return "\n".join(out)


def _render_findings(findings: list[Finding], fmt: str, label: str = "found",
                     include_rotation: bool = False) -> None:
    findings = sort_findings(findings)
    if fmt == "json":
        obj: dict = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "count": len(findings),
            "summary": summarize(findings),
            "findings": [f.to_dict() for f in findings],
        }
        if include_rotation:
            obj["rotation_plan"] = rotation_plan(findings)
        _print_json(obj)
        return
    if not findings:
        print("No secrets detected. Clean.")
        return
    rows = [[f.severity.upper(), f.rule_id, f"{f.path}:{f.line}:{f.col}",
             f.match, f"{f.entropy:.2f}", f.fingerprint] for f in findings]
    print(_table(rows, ["severity", "rule", "location", "match",
                        "entropy", "fingerprint"]))
    s = summarize(findings)
    sev = ", ".join(f"{k}={v}" for k, v in sorted(s["by_severity"].items()))
    print(f"\n{s['total']} secret(s) {label} [{sev}].")


# ---------------------------------------------------------------------------
# Engine construction from common args
# ---------------------------------------------------------------------------
def _build_engine(args) -> "tuple[Engine, None] | tuple[None, str]":
    """Return ``(engine, None)`` on success or ``(None, error_message)``."""
    import re as _re

    cfg_path = getattr(args, "config", None) or ""
    try:
        cfg = load_config(cfg_path)
    except (OSError, ValueError) as exc:
        return None, f"error: {exc}"

    baseline: set[str] = set()
    bpath = getattr(args, "baseline", None)
    if bpath:
        try:
            baseline = load_baseline(bpath)
        except (OSError, ValueError) as exc:
            return None, f"error: {exc}"

    eng = Engine.from_config(cfg, baseline=baseline)

    # CLI flags override config.
    if getattr(args, "no_entropy", False):
        eng.entropy_enabled = False
    if getattr(args, "entropy_threshold", None) is not None:
        thr = args.entropy_threshold
        if thr < 0:
            return None, "error: --entropy-threshold must be >= 0"
        eng.entropy_threshold = thr
    if getattr(args, "no_inline_allow", False):
        eng.respect_inline_allow = False

    # Merge CLI allowlist additions onto the config-derived allowlist.
    extra_lit = list(getattr(args, "allow", None) or [])
    extra_rx = list(getattr(args, "allow_regex", None) or [])
    extra_glob = list(getattr(args, "exclude", None) or [])
    if extra_lit or extra_rx or extra_glob:
        al = eng.allowlist
        al.literals.update(extra_lit)
        for pat in extra_rx:
            try:
                al.regexes.append(_re.compile(pat))
            except _re.error as exc:
                return None, f"error: invalid --allow-regex {pat!r}: {exc}"
        al.path_globs.extend(extra_glob)
    return eng, None


def _collect(engine: Engine, paths) -> list[Finding]:
    findings: list[Finding] = []
    if not paths:
        text = sys.stdin.read()
        findings.extend(engine.scan_text(text, path="<stdin>"))
    else:
        for p in paths:
            findings.extend(engine.scan_path(p))
    return findings


def _severity_filter(findings, floor_name):
    if not floor_name:
        return findings
    floor = SEVERITY_ORDER.get(floor_name, 0)
    return [f for f in findings
            if SEVERITY_ORDER.get(f.severity, 0) >= floor]


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------
def _cmd_scan(args) -> int:
    engine, err = _build_engine(args)
    if err:
        print(err, file=sys.stderr)
        return EXIT_ERR
    # Validate that explicitly provided paths exist.
    for p in (args.paths or []):
        if not (p == "-" or os.path.exists(p)):
            print(f"error: path not found: {p}", file=sys.stderr)
            return EXIT_ERR
    try:
        findings = _collect(engine, args.paths or [])
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERR
    findings = _severity_filter(findings, args.severity)
    include_rotation = getattr(args, "rotate", False)
    _render_findings(findings, args.format, include_rotation=include_rotation)
    return EXIT_FINDINGS if findings else EXIT_OK


def _cmd_verify(args) -> int:
    """Scan and fail only on findings not already in the baseline."""
    engine, err = _build_engine(args)   # baseline already wired into the engine
    if err:
        print(err, file=sys.stderr)
        return EXIT_ERR
    try:
        findings = _collect(engine, args.paths or [])
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERR
    findings = _severity_filter(findings, args.severity)
    if args.format == "table":
        n = len(engine.baseline)
        print(f"verify: baseline has {n} accepted fingerprint(s); "
              f"reporting only NEW secrets.")
    _render_findings(findings, args.format, label="new")
    return EXIT_FINDINGS if findings else EXIT_OK


def _cmd_baseline(args) -> int:
    """Scan and write a baseline file of every fingerprint found."""
    # Build engine WITHOUT a baseline so we capture everything currently
    # present, then write it out as the accepted set.
    args.baseline = None
    engine, err = _build_engine(args)
    if err:
        print(err, file=sys.stderr)
        return EXIT_ERR
    try:
        findings = _collect(engine, args.paths or [])
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERR
    try:
        n = write_baseline(args.output, findings)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERR
    if args.format == "json":
        _print_json({"tool": TOOL_NAME, "baseline": args.output,
                     "fingerprints_written": n,
                     "summary": summarize(findings)})
    else:
        print(f"Wrote {n} fingerprint(s) to baseline {args.output!r}.")
        print("Future `verify` runs will ignore these and fail only on new "
              "secrets.")
    return EXIT_OK


def _cmd_rules(args) -> int:
    if args.format == "json":
        _print_json({"detectors": [r.to_dict() for r in RULES],
                     "count": len(RULES)})
        return EXIT_OK
    rows = [[r.id, r.severity.upper(), r.description] for r in RULES]
    print(_table(rows, ["id", "severity", "description"]))
    print(f"\n{len(RULES)} bundled rules.")
    return EXIT_OK


def _cmd_entropy(args) -> int:
    ent = shannon_entropy(args.string)
    if args.format == "json":
        _print_json({"string_len": len(args.string),
                     "entropy_bits_per_char": ent})
    else:
        print(f"length={len(args.string)} entropy={ent:.4f} bits/char")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def _add_scan_args(sp, with_severity=True):
    sp.add_argument("paths", nargs="*",
                    help="files or directories to scan (default: stdin)")
    sp.add_argument("--config", metavar="FILE",
                    help="JSON config (allowlist/entropy/disabled_rules)")
    sp.add_argument("--exclude", action="append", metavar="GLOB",
                    help="path glob to skip (repeatable)")
    sp.add_argument("--allow", action="append", metavar="VALUE",
                    help="literal secret value to allowlist (repeatable)")
    sp.add_argument("--allow-regex", action="append", metavar="REGEX",
                    help="regex of secret values to allowlist (repeatable)")
    sp.add_argument("--no-entropy", action="store_true",
                    help="disable generic high-entropy detection")
    sp.add_argument("--no-inline-allow", action="store_true",
                    help="ignore '# secretsweep:allow' inline comments")
    sp.add_argument("--entropy-threshold", type=float, default=None,
                    metavar="BITS",
                    help="entropy floor for generic detection "
                         "(default: 4.3 bits/char)")
    if with_severity:
        sp.add_argument("--severity",
                        choices=("low", "medium", "high", "critical"),
                        help="only report findings at/above this severity")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Zero-install secret scanner. 50+ provider rules, "
                    "Shannon-entropy detection, allowlist + baseline, in the "
                    "spirit of gitleaks and trufflehog.",
        epilog="Examples:\n"
               "  secretsweep scan ./src --format json\n"
               "  cat config.yml | secretsweep scan\n"
               "  secretsweep scan . --exclude '*/tests/*' --severity high\n"
               "  secretsweep baseline . --output .secretsweep.baseline\n"
               "  secretsweep verify . --baseline .secretsweep.baseline\n"
               "  secretsweep rules --format json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=("table", "json"), default="table",
                   help="output format (default: table)")

    fmt_parent = argparse.ArgumentParser(add_help=False)
    fmt_parent.add_argument("--format", choices=("table", "json"),
                            default=argparse.SUPPRESS,
                            help="output format (default: table)")

    sub = p.add_subparsers(
        dest="cmd", metavar="{scan,verify,baseline,rules,entropy}")

    sc = sub.add_parser("scan", help="scan files/dirs/stdin for secrets",
                        parents=[fmt_parent])
    _add_scan_args(sc)
    sc.add_argument("--baseline", metavar="FILE",
                    help="suppress findings whose fingerprint is in this file")
    sc.add_argument("--rotate", action="store_true",
                    help="include a per-finding rotation checklist in the output")
    sc.set_defaults(func=_cmd_scan)

    vf = sub.add_parser("verify",
                        help="fail only on secrets not in a baseline (CI)",
                        parents=[fmt_parent])
    _add_scan_args(vf)
    vf.add_argument("--baseline", metavar="FILE", required=True,
                    help="baseline file of accepted fingerprints")
    vf.set_defaults(func=_cmd_verify)

    bl = sub.add_parser("baseline",
                        help="write a baseline of current findings",
                        parents=[fmt_parent])
    _add_scan_args(bl, with_severity=False)
    bl.add_argument("--output", "-o", metavar="FILE", required=True,
                    help="path to write the baseline JSON")
    bl.set_defaults(func=_cmd_baseline)

    rl = sub.add_parser("rules", help="list bundled provider rules",
                        parents=[fmt_parent])
    rl.set_defaults(func=_cmd_rules)

    # "detectors" is a user-friendly alias for "rules".
    det = sub.add_parser("detectors", help="list bundled detectors (alias for 'rules')",
                         parents=[fmt_parent])
    det.set_defaults(func=_cmd_rules)

    en = sub.add_parser("entropy", help="compute Shannon entropy of a string",
                        parents=[fmt_parent])
    en.add_argument("string", help="string to measure")
    en.set_defaults(func=_cmd_entropy)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_OK
    # honor top-level --format if the subparser didn't set one
    if not hasattr(args, "format"):
        args.format = "table"
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERR
    except Exception as exc:  # noqa: BLE001
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return EXIT_ERR


if __name__ == "__main__":
    sys.exit(main())
