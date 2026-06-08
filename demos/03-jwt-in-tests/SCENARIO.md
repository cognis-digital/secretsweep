# Scenario: JWT in test code

Tests have a real-looking JWT — even if expired, the pattern is a vector for confusion.

## Expected findings

- SEC-JWT-001

## Why this matters

Replace test JWTs with clearly-fake values or generate at runtime.
