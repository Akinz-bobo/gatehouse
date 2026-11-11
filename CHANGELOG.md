# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org).

## [Unreleased]

## [0.1.0] - 2026-11-11

First release.

### Added

- **Core.** Registration and password sign-in with Argon2id. ES256 access tokens, a JWKS endpoint and signing key rotation. Single-use rotating refresh tokens with reuse detection. Session listing and revocation. Password change and reset. Account lockout with exponential backoff. Per-IP rate limits. A CLI for key generation and superuser management.
- **Module `rbac`.** Roles, permissions with wildcards, role and permission claims in tokens, a live permission check, and delegated administration.
- **Module `abac`.** Allow and deny policies with a condition language over subject, resource and context. Deny overrides, default deny, fail closed.
- **Module `oauth`.** Sign-in through any OAuth 2.0 provider with PKCE, single-use state, a redirect allow-list and a one-time exchange code. Explicit account linking.
- **Module `mfa`.** TOTP two-factor with replay protection and single-use recovery codes.
- **Module `audit`.** An append-only log of security events with filtering and cursor pagination.
- OpenAPI description served with Swagger UI at `/docs`, checked against the registered routes by a test.
- Docker image, compose stack, an end-to-end smoke test, and CI with linting, type checks, unit and integration tests, dependency audit and CodeQL.
- Architecture document, threat model, usage guides and decision records.

[Unreleased]: https://github.com/Akinz-bobo/gatehouse/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Akinz-bobo/gatehouse/releases/tag/v0.1.0
