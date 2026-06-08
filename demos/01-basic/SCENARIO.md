# Demo 01 - Basic secret scan

A developer accidentally committed a `config.env` containing live credentials
for several providers. SECRETSWEEP scans the repo, flags each leaked secret
(with entropy verification to suppress noise), redacts the value in its report,
and emits a provider-grouped rotation playbook.

## Input

`config.env` mixes real-looking secrets with harmless config so you can see the
entropy gate at work (the `APP_NAME` / `LOG_LEVEL` lines are not flagged).

## Run it

Scan the demo file as a table:

```bash
python -m secretsweep scan demos/01-basic/config.env
```

Machine-readable output plus a rotation plan:

```bash
python -m secretsweep --format json scan demos/01-basic/config.env --rotate
```

Scope to a single provider:

```bash
python -m secretsweep scan demos/01-basic/config.env --provider aws
```

List every detector:

```bash
python -m secretsweep --format json detectors
```

## Expected behavior

- AWS key id, GitHub PAT, Slack token, and Stripe key are all detected.
- Secret values are redacted (e.g. `AKI************MPL`).
- Exit code is `1` because secrets were found (fails CI by design).
- A clean file (no secrets) exits `0`.
