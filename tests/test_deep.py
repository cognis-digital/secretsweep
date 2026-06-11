"""Deep tests for the secretsweep provider-rule pack, entropy and allowlist."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secretsweep import (  # noqa: E402
    RULES,
    Allowlist,
    Engine,
    TOOL_NAME,
    TOOL_VERSION,
    load_baseline,
    shannon_entropy,
    write_baseline,
)
from secretsweep.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "demos", "02-deep")


def _ids(findings):
    return {f.rule_id for f in findings}


def test_metadata():
    assert TOOL_NAME == "secretsweep"
    assert TOOL_VERSION
    # 40+ provider rules bundled
    assert len(RULES) >= 40, f"only {len(RULES)} rules"


def test_rule_ids_unique_and_compiled():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    for r in RULES:
        assert r.regex.pattern  # compiled, non-empty
        assert r.severity in ("low", "medium", "high", "critical")


def test_aws_keypair_detected():
    eng = Engine()
    text = (
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )
    ids = _ids(eng.scan_text(text))
    assert "aws-access-key-id" in ids
    assert "aws-secret-access-key" in ids


def test_many_provider_rules_fire():
    eng = Engine()
    cases = {
        "GOOGLE_API_KEY=AIzaEXAMPLE0000000000000000000000000000":
            "gcp-api-key",
        "STRIPE=sk_live_EXAMPLE0000000000000": "stripe-secret-key",
        "GH=ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEE": "github-pat",
        "GL=glpat-aBcDeFgHiJkLmNoPqRsT": "gitlab-pat",
        "SLACK=xoxb-EXAMPLE-EXAMPLE-EXAMPLE":
            "slack-token",
        "url=postgres://u:supersecret@h:5432/d": "basic-auth-url",
    }
    for line, expected in cases.items():
        ids = _ids(eng.scan_text(line))
        assert expected in ids, f"{expected} missed in {line!r} (got {ids})"


def test_private_key_block_is_critical():
    eng = Engine()
    findings = eng.scan_text("-----BEGIN RSA PRIVATE KEY-----")
    assert any(f.rule_id == "private-key" and f.severity == "critical"
               for f in findings)


def test_jwt_detected():
    eng = Engine()
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
    assert "jwt" in _ids(eng.scan_text(jwt))


def test_entropy_function():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    high = shannon_entropy("aB3xQ9zK7mP2wL5nT8vR4cF6yH1jD0sG")
    assert high > 4.0


def test_high_entropy_string_detection():
    eng = Engine(entropy_enabled=True, entropy_threshold=4.0)
    # a random-looking base64 blob with no provider context
    blob = "x = 'aB3xQ9zK7mP2wL5nT8vR4cF6yH1jD0sGqW9eU4iO'"
    ids = _ids(eng.scan_text(blob))
    assert "high-entropy-string" in ids

    eng_off = Engine(entropy_enabled=False)
    assert "high-entropy-string" not in _ids(eng_off.scan_text(blob))


def test_allowlist_stopwords_suppress_placeholders():
    eng = Engine()
    # placeholder containing a stop-word should not be reported
    line = "API_KEY=your_api_key_here_changeme_placeholder"
    findings = eng.scan_text(line)
    assert not any(f.rule_id == "generic-api-key-assign" for f in findings)


def test_allowlist_literal_and_path_glob():
    secret = "AKIAIOSFODNN7EXAMPLE"
    allow = Allowlist.from_iterables(literals=[secret])
    eng = Engine(allowlist=allow)
    assert "aws-access-key-id" not in _ids(eng.scan_text(f"key={secret}"))

    allow2 = Allowlist.from_iterables(path_globs=["*/tests/*"])
    assert allow2.path_allowed("repo/tests/fixtures.py")
    assert not allow2.path_allowed("repo/src/app.py")


def test_redaction_hides_middle():
    eng = Engine()
    f = eng.scan_text("key=ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEE")[0]
    assert "*" in f.match
    assert "aBcDeFgHiJkLmNoPqRs" not in f.match


def test_fingerprint_stable():
    eng = Engine()
    a = eng.scan_text("k=ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEE")
    b = eng.scan_text("k=ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEE")
    pats = [f.fingerprint for f in a if f.rule_id == "github-pat"]
    pbts = [f.fingerprint for f in b if f.rule_id == "github-pat"]
    assert pats and pats == pbts


def test_scan_demo_files(tmp_path):
    demo = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "demos", "02-deep")
    eng = Engine()
    findings = eng.scan_path(demo)
    ids = _ids(findings)
    assert "aws-access-key-id" in ids
    assert "private-key" in ids
    assert len(findings) >= 8


def test_cli_scan_json_and_exit_code(capsys):
    demo = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "demos", "02-deep")
    rc = main(["scan", demo, "--format", "json"])
    assert rc == 2  # findings -> non-zero
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["tool"] == "secretsweep"
    assert payload["summary"]["total"] >= 8
    assert any(f["rule_id"] == "aws-access-key-id"
               for f in payload["findings"])


def test_cli_clean_scan_exit_zero(tmp_path, capsys):
    clean = tmp_path / "clean.txt"
    clean.write_text("hello world\nthis file has no secrets\n")
    rc = main(["scan", str(clean)])
    assert rc == 0
    assert "Clean" in capsys.readouterr().out


def test_cli_rules_lists_pack(capsys):
    rc = main(["rules", "--format", "json"])
    assert rc == 0
    rules = json.loads(capsys.readouterr().out)
    assert len(rules) >= 40


def test_cli_severity_filter(capsys):
    demo = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "demos", "02-deep")
    rc = main(["scan", demo, "--format", "json", "--severity", "critical"])
    assert rc == 2
    payload = json.loads(capsys.readouterr().out)
    assert all(f["severity"] == "critical" for f in payload["findings"])


# ---------------------------------------------------------------------------
# New best-in-class features: structured tokens, inline-allow, baseline/verify
# ---------------------------------------------------------------------------
def test_structured_token_not_suppressed_by_digit_runs():
    """Real-shaped keys that merely contain '1234567890'/'abcdef' substrings
    must still be reported — the placeholder heuristic only fires when
    placeholder *words* dominate the token."""
    eng = Engine()
    cases = {
        "GH=ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEE": "github-pat",
        "AWS=AKIAIOSFODNN7EXAMPLE": "aws-access-key-id",
        "G=AIzaEXAMPLE0000000000000000000000000000": "gcp-api-key",
    }
    for line, rid in cases.items():
        assert rid in _ids(eng.scan_text(line)), f"{rid} missed in {line!r}"


def test_placeholder_word_domination_suppresses():
    al = Allowlist()
    assert al.secret_allowed("your_api_key_here_changeme_placeholder")
    assert al.secret_allowed("example_example_example")
    # but a real token is not a placeholder even with one stop-word fragment
    assert not al.secret_allowed("ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEE",
                                 structured=True)


def test_inline_allow_comment_suppresses_line():
    eng = Engine()
    leaky = "TOKEN = sk_live_EXAMPLE0000000000000"
    assert "stripe-secret-key" in _ids(eng.scan_text(leaky))
    # same line with an inline allow comment -> suppressed
    allowed = leaky + "  # secretsweep:allow"
    assert eng.scan_text(allowed) == []
    # gitleaks-compatible form too
    allowed2 = leaky + "  // gitleaks:allow"
    assert eng.scan_text(allowed2) == []
    # disabling the feature re-enables detection
    eng2 = Engine(respect_inline_allow=False)
    assert "stripe-secret-key" in _ids(eng2.scan_text(allowed))


def test_baseline_roundtrip_and_engine_suppression(tmp_path):
    eng = Engine()
    findings = eng.scan_path(DEMO)
    assert findings
    bpath = tmp_path / "base.json"
    n = write_baseline(str(bpath), findings)
    assert n >= 8
    loaded = load_baseline(str(bpath))
    assert loaded == {f.fingerprint for f in findings}
    # an engine seeded with that baseline reports nothing new
    eng2 = Engine(baseline=loaded)
    assert eng2.scan_path(DEMO) == []


def test_engine_from_config_disables_rules_and_tunes_entropy():
    cfg = {
        "disabled_rules": ["stripe-publishable-key"],
        "entropy": {"enabled": False},
        "allowlist": {"paths": ["*/vendor/*"]},
    }
    eng = Engine.from_config(cfg)
    assert all(r.id != "stripe-publishable-key" for r in eng.rules)
    assert eng.entropy_enabled is False
    assert eng.allowlist.path_allowed("repo/vendor/lib.js")
    # disabled rule no longer fires
    ids = _ids(eng.scan_text("KEY=pk_live_thequickbrownfoxjumps12345"))
    assert "stripe-publishable-key" not in ids


def test_cli_baseline_then_verify_clean(tmp_path, capsys):
    bfile = tmp_path / "ss.baseline"
    rc = main(["baseline", DEMO, "-o", str(bfile)])
    assert rc == 0
    capsys.readouterr()
    assert bfile.exists()
    # verify against the just-written baseline -> nothing new -> exit 0
    rc = main(["verify", DEMO, "--baseline", str(bfile)])
    assert rc == 0
    assert "Clean" in capsys.readouterr().out


def test_cli_verify_detects_new_secret(tmp_path, capsys):
    bfile = tmp_path / "ss.baseline"
    main(["baseline", DEMO, "-o", str(bfile)])
    capsys.readouterr()
    leak = tmp_path / "new.txt"
    leak.write_text("NEW_AWS=AKIAZ7NEWLEAK0123ABC\n")
    rc = main(["verify", str(leak), "--baseline", str(bfile),
               "--format", "json"])
    assert rc == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total"] == 1
    assert payload["findings"][0]["rule_id"] == "aws-access-key-id"


def test_cli_version(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    out = capsys.readouterr().out
    assert TOOL_NAME in out and TOOL_VERSION in out


def test_demo_service_file_provider_rules():
    eng = Engine()
    ids = _ids(eng.scan_file(os.path.join(DEMO, "service.py")))
    # NOTE: the Linear/DigitalOcean fixtures were de-fanged to obvious EXAMPLE
    # placeholders (GitHub push-protection flags lin_api_/dop_v1_ by prefix+length
    # with no entropy window). openai-api-key + huggingface-token still exercise
    # structured-provider detection here and remain below GitHub's threshold.
    for rid in ("openai-api-key", "huggingface-token"):
        assert rid in ids, f"{rid} not detected in service.py"
    # the inline-allowed sk_live and the placeholder must be absent
    assert "stripe-secret-key" not in ids


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
