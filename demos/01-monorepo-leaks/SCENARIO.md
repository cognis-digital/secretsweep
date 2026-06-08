# Scenario: Monorepo with multiple categories of leaked secrets

config.py + deploy.sh together contain 6 categories of leaked credentials.

## Expected findings

- SEC-OPENAI-001 (high)
- SEC-GH-001 (critical)
- SEC-AWS-001 (critical)
- SEC-STRIPE-001 (critical)
- SEC-ANTHROPIC-001 (high)
- SEC-PRIVKEY-001 (critical)

## Why this matters

Rotate everything. Treat as full keystore compromise.
