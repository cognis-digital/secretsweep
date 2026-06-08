# Demo 02 — deep scan (provider rules + entropy + allowlist + baseline)

This folder contains files with **planted fake secrets** (no real
credentials) to exercise SECRETSWEEP's full feature set, in the spirit of
gitleaks and trufflehog.

Files:

- `leaky_config.env` — AWS / Google / Stripe / GitHub / GitLab / Slack /
  SendGrid / Anthropic / basic-auth-URL / JWT, plus an allowlisted
  placeholder line.
- `private_key.pem` — a PEM private-key block (critical).
- `service.py` — OpenAI / Hugging Face / Linear / DigitalOcean tokens, a
  high-entropy base64 blob with no provider keyword (caught by the entropy
  heuristic), an inline `# secretsweep:allow` acknowledged false-positive,
  and a stop-word placeholder the allowlist suppresses.
- `secretsweep.config.json` — example config (path allowlist, entropy tuning).

## Run it

From the package root (`secretsweep/`):

```sh
# Scan the whole demo folder, table output
python -m secretsweep scan demos/02-deep

# JSON output (machine-readable; non-zero exit when secrets found)
python -m secretsweep scan demos/02-deep --format json

# Only the serious stuff
python -m secretsweep scan demos/02-deep --severity high

# Use a config file (allowlist paths, entropy threshold, disabled rules)
python -m secretsweep scan demos/02-deep --config demos/02-deep/secretsweep.config.json

# Pipe a single value via stdin
echo "AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" | python -m secretsweep scan

# List the bundled provider rule pack
python -m secretsweep rules
```

## Baseline workflow (CI gate, gitleaks-style)

Record everything currently present, then fail builds only on **new** leaks:

```sh
# 1) snapshot the accepted findings
python -m secretsweep baseline demos/02-deep -o .secretsweep.baseline

# 2) in CI: passes (exit 0) as long as nothing new appears
python -m secretsweep verify demos/02-deep --baseline .secretsweep.baseline

# adding a brand-new secret makes verify exit 2
```

## Inline allow comments

Acknowledge a known false positive in place — both forms are honored:

```py
TOKEN = "sk_live_EXAMPLE0000000000000"  # secretsweep:allow
TOKEN = "sk_live_EXAMPLE0000000000000"  # gitleaks:allow
```

## What you should see

Exit code is `2` when any secret is found, `0` when clean — wire it into CI.
The placeholder lines (`your_api_key_here_...`) and the inline-allowed line
are **not** reported, while real-shaped tokens — even ones containing digit
runs like `...0123456789` — still are.
