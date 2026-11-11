# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: go to the **Security** tab of this repository and choose **Report a vulnerability**. If that is not available to you, email adeyemoakinola2@gmail.com with "Gatehouse security" in the subject.

Include what you found, how to reproduce it, and what an attacker could do with it. You can expect an acknowledgement within three working days. Please give a reasonable time for a fix before disclosing publicly, and you will be credited in the changelog unless you would prefer not to be.

## Scope

In scope: anything that lets someone sign in as another user, mint or forge a token, gain permissions they were not granted, bypass two-factor, read secrets from the service, or tamper with the audit log.

Already known and documented: the gaps listed under [What is not defended](docs/threat-model.md#what-is-not-defended). Improvements to those are welcome as ordinary issues and pull requests.

## Supported versions

Gatehouse is pre-1.0. Fixes land on `main` and in the next release.

## Status

This project is a reference implementation. It is tested, and its defences are documented in the [threat model](docs/threat-model.md), but it has not been independently audited. Review it against your own requirements before relying on it.
