# SECRETSWEEP — Repo secret scanner + auto-rotator across providers

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `dev-supply-chain`

[![PyPI](https://img.shields.io/pypi/v/cognis-secretsweep.svg)](https://pypi.org/project/cognis-secretsweep/)
[![CI](https://github.com/cognis-digital/secretsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/secretsweep/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**Repo secret scanner + auto-rotator across providers.**

*Developer / Supply Chain — secrets, SBOM, CI/CD, and license hygiene.*

## Why

Security and intelligence teams need repo secret scanner + auto-rotator across providers without standing up heavyweight infrastructure. `secretsweep` is single-purpose, scriptable, CI-friendly, and self-hostable: point it at a target, get prioritized findings in the format your workflow already speaks (table, JSON, SARIF, HTML), and wire it into agents over MCP when you want it autonomous.

## Install

```bash
pip install cognis-secretsweep
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
secretsweep --version
secretsweep scan demos/                      # run against the bundled demo
secretsweep scan demos/ --format sarif --out r.sarif --fail-on high
secretsweep scan demos/ --format html --out report.html
secretsweep mcp                              # expose as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## What it detects

| Rule ID | Severity | Signal |
|---|---|---|
| `SEC-AWS-001` | critical | Aws Access Key |
| `SEC-AWS-002` | critical | Aws Secret |
| `SEC-GH-001` | critical | Github Pat |
| `SEC-GH-002` | critical | Github Finegrained |
| `SEC-SLACK-001` | high | Slack Token |
| `SEC-STRIPE-001` | critical | Stripe Live |
| `SEC-OPENAI-001` | high | Openai Key |
| `SEC-ANTHROPIC-001` | high | Anthropic Key |
| `SEC-PRIVKEY-001` | critical | Private Key |
| `SEC-JWT-001` | medium | Jwt |

*Rule set ships in this repo and grows over time — PRs adding detections are welcome.*

## Built-in demo scenarios

Each scenario folder includes a `SCENARIO.md` describing the situation and the findings to expect.

- [`demos/01-monorepo-leaks/`](demos/01-monorepo-leaks/SCENARIO.md)
- [`demos/02-pre-commit-clean/`](demos/02-pre-commit-clean/SCENARIO.md)
- [`demos/03-jwt-in-tests/`](demos/03-jwt-in-tests/SCENARIO.md)

## Output formats

- **Table** (default) — human-readable terminal summary
- **JSON** — machine-readable findings for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes
- **HTML** — shareable report with severity rollups

## Credits / Built on

Cognis composes and credits the best of open source. This tool builds on / interoperates with:

- [`trufflesecurity/trufflehog`](https://github.com/trufflesecurity/trufflehog) — secret detection
- [`gitleaks/gitleaks`](https://github.com/gitleaks/gitleaks) — rules
- [`Yelp/detect-secrets`](https://github.com/Yelp/detect-secrets) — entropy heuristics

Missing a credit? Open a PR — see [CONTRIBUTING.md](CONTRIBUTING.md).

## How it fits the Cognis Neural Suite

`secretsweep` is one of **52 tools** in the [Cognis Neural Suite](https://github.com/cognis-digital). Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents can call them as scoped capabilities.

**Sibling tools in `dev-supply-chain`:** [`depgraph`](https://github.com/cognis-digital/depgraph), [`pipewatch-pro`](https://github.com/cognis-digital/pipewatch-pro), [`ossaudit`](https://github.com/cognis-digital/ossaudit)

## Architecture & roadmap

- Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Planned work: [`ROADMAP.md`](ROADMAP.md)

## Contributing

PRs, new detections, and demo scenarios are welcome under the collaboration-pull model. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## Responsible use

This is dual-use security software. Use it only against systems, data, and identities you own or are explicitly authorized in writing to test, and in compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
