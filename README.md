<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=SECRETSWEEP&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="SECRETSWEEP"/>

# SECRETSWEEP

### Repo secret scanner + auto-rotator across providers

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Repo+secret+scanner++autorotator+across+providers;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-secretsweep.svg?color=6b46c1)](https://pypi.org/project/cognis-secretsweep/) [![CI](https://github.com/cognis-digital/secretsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/secretsweep/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Developer / Supply Chain — secrets, SBOM, CI/CD, and license hygiene.*

</div>

```bash
pip install cognis-secretsweep
secretsweep scan .            # → prioritized findings in seconds
```

## Usage — step by step

`secretsweep` is a zero-install secret scanner with 50+ provider rules, Shannon-entropy detection, and allowlist/baseline support. Console script: `secretsweep`.

1. **Install**:
   ```bash
   pipx install secretsweep     # or: pip install secretsweep
   ```
2. **Scan files, a directory, or stdin** for secrets:
   ```bash
   secretsweep scan ./src --format json | jq '.summary'
   cat config.yml | secretsweep scan
   ```
   Exit `2` = secrets found, `0` = clean, `1` = error.
3. **Record a baseline** of currently-accepted findings so existing secrets don't block the build:
   ```bash
   secretsweep baseline . --output .secretsweep.baseline
   ```
4. **Verify against the baseline in CI** — fail only on *new* secrets at/above a severity floor:
   ```bash
   secretsweep verify . --baseline .secretsweep.baseline --severity high
   ```
5. **Tune the scan** with allowlists and the entropy detector, or list the bundled rule pack:
   ```bash
   secretsweep scan . --exclude '*/tests/*' --allow-regex 'AKIA_EXAMPLE_.*' --entropy-threshold 4.5
   secretsweep rules --format json
   ```

## Contents

- [Why secretsweep?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why secretsweep?

Repo secret scanner + auto-rotator across providers — without standing up heavyweight infrastructure.

`secretsweep` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Shannon Entropy
- ✅ Redact
- ✅ Scan Text
- ✅ Scan Path
- ✅ Rotation Plan
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-secretsweep
secretsweep --version
secretsweep scan .                       # scan current project
secretsweep scan . --format json         # machine-readable
secretsweep scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ secretsweep scan .
  [HIGH    ] SEC-001  example finding             (./src/app.py)
  [MEDIUM  ] SEC-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[secretsweep<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`secretsweep` is interoperable with every popular way of using AI:

- **MCP server** — `secretsweep mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `secretsweep scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis secretsweep** | trufflesecurity |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **trufflesecurity/trufflehog**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`secretsweep mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/secretsweep.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/secretsweep.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/secretsweep.git" # uv
pip install cognis-secretsweep                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/secretsweep:latest --help        # Docker
brew install cognis-digital/tap/secretsweep                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/secretsweep/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/secretsweep` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`depgraph`](https://github.com/cognis-digital/depgraph) — Dependency risk visualizer — Scorecard + OSV + typosquat + maintainer signals
- [`pipewatch-pro`](https://github.com/cognis-digital/pipewatch-pro) — CI/CD supply-chain auditor — GH Actions / GitLab CI / OWASP CI/CD Top 10
- [`ossaudit`](https://github.com/cognis-digital/ossaudit) — OSS license compliance auditor — AGPL contamination + NOTICE generation

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `secretsweep` saved you time, **star it** — it genuinely helps others find it.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
