# Contributing

Thanks for your interest. Issues and pull requests are welcome.

## Getting set up

You need Node.js 22, pnpm and Docker.

```bash
pnpm install
make db       # PostgreSQL for the tests, on port 5546
make check    # format, lint, types and the whole test suite
```

`make check` is exactly what CI runs. If it passes locally, CI should pass.

## How the code is organised

- `src/crypto` holds primitives with no dependencies on the rest of the service.
- `src/core` is always on. It must not import from `src/modules`.
- `src/modules/<name>` is one opt-in capability. See [Writing a module](docs/guides/writing-a-module.md).
- `src/http` wires everything into Fastify.

[docs/architecture.md](docs/architecture.md) has the full picture.

## Ground rules

1. **Security changes need a test that fails without them.** A defence nobody tests will be broken by a later refactor.
2. **Test the refusal as well as the success.** For every "allowed" case, cover who must be denied.
3. **Fail closed.** When the code cannot decide, it says no.
4. **No new insecure options.** There should be no setting that turns off hashing, weakens an algorithm or skips a check.
5. **Keep dependencies few.** Each one is code this service trusts with credentials. Explain any addition in the pull request.
6. **Never edit a released migration.** Add a new numbered file.
7. **Keep the spec in step.** `openapi/openapi.yaml` must describe every route. A test enforces it.
8. **Update the threat model** when you add a defence, close a gap or open one.

## Commits and pull requests

Commits follow [Conventional Commits](https://www.conventionalcommits.org): `feat(mfa): ...`, `fix(sessions): ...`, `docs: ...`, `test: ...`, `chore: ...`. Keep each commit to one logical change.

In the pull request, say what changed, why, and how you tested it. Add an entry to `CHANGELOG.md` under "Unreleased".

## Reporting security problems

Not in a public issue, please. See [SECURITY.md](SECURITY.md).
