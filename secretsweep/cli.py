"""Command-line interface for SECRETSWEEP."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Finding, scan_path, scan_text, rotation_plan, DETECTORS


def _print_table(findings: List[Finding], stream) -> None:
    if not findings:
        print("No secrets found.", file=stream)
        return
    header = f"{'PROVIDER':<10} {'DETECTOR':<32} {'LOCATION':<40} {'ENTROPY':>7}  MATCH"
    print(header, file=stream)
    print("-" * len(header), file=stream)
    for f in findings:
        loc = f"{f.path}:{f.line}:{f.column}"
        print(
            f"{f.provider:<10} {f.detector_id:<32} {loc:<40} {f.entropy:>7.3f}  {f.match}",
            file=stream,
        )
    print(f"\n{len(findings)} finding(s).", file=stream)


def _emit(findings: List[Finding], fmt: str, with_plan: bool, stream) -> None:
    if fmt == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        if with_plan:
            payload["rotation_plan"] = rotation_plan(findings)
        json.dump(payload, stream, indent=2)
        stream.write("\n")
    else:
        _print_table(findings, stream)
        if with_plan and findings:
            print("\nRotation plan:", file=stream)
            for entry in rotation_plan(findings):
                print(f"  [{entry['provider']}] {entry['leaked_count']} leaked", file=stream)
                for step in entry["rotation_steps"]:
                    print(f"    - {step}", file=stream)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Repo secret scanner + auto-rotator across providers.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--format", choices=["table", "json"], default="table",
                        help="output format (default: table)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a file or directory for secrets")
    p_scan.add_argument("path", help="file or directory to scan (use '-' for stdin)")
    p_scan.add_argument("--provider", action="append", dest="providers",
                        help="limit to a provider (repeatable): aws, github, slack, "
                             "stripe, google, openai, generic")
    p_scan.add_argument("--rotate", action="store_true",
                        help="include a provider rotation playbook in the output")

    sub.add_parser("detectors", help="list available provider detectors")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "detectors":
        rows = [
            {"id": d.id, "provider": d.provider, "description": d.description,
             "min_entropy": d.min_entropy}
            for d in DETECTORS
        ]
        if args.format == "json":
            json.dump({"tool": TOOL_NAME, "detectors": rows}, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            for r in rows:
                print(f"{r['provider']:<10} {r['id']:<32} {r['description']}")
        return 0

    if args.command == "scan":
        try:
            if args.path == "-":
                findings = scan_text(sys.stdin.read(), path="<stdin>",
                                     providers=args.providers)
            else:
                findings = scan_path(args.path, providers=args.providers)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        _emit(findings, args.format, args.rotate, sys.stdout)
        # Non-zero exit when secrets are present (CI-friendly).
        return 1 if findings else 0

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
