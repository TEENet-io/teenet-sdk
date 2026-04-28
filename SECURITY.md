# Security Policy

TEENet SDK handles signing, key metadata, approval flows, and API-secret
operations. Please report suspected vulnerabilities privately and do not publish
technical details until maintainers have had time to investigate and coordinate
a fix.

## Supported Versions

This project is in Developer Preview. Security fixes are targeted at the current
default branch and the latest tagged release.

| Version | Security support |
|---|---|
| Latest tagged release | Supported |
| `main` | Supported for upcoming fixes |
| Older releases | Not supported unless a maintained branch is announced |

## Reporting a Vulnerability

Use GitHub private vulnerability reporting for this repository if it is enabled.

If private vulnerability reporting is unavailable, do not open a public issue
with vulnerability details. Instead, open a minimal public issue asking for a
private security contact, without exploit steps, affected endpoints, secrets, or
technical details.

Include as much of the following as you can in the private report:

- Affected package or component: Go SDK, TypeScript SDK, mock server, examples,
  or docs
- Affected version, commit, or tag
- Impact and expected attacker capability
- Reproduction steps or proof of concept
- Whether real keys, API secrets, passkey credentials, or production app
  instance IDs were involved
- Any suggested mitigation or patch

Do not include real private keys, seed material, API secrets, bearer tokens,
passkey credentials, or production customer data in reports. Redact sensitive
values or use mock data.

## Response Expectations

Maintainers will make a best effort to:

- Acknowledge valid private reports within 3 business days
- Triage severity and affected versions within 14 days
- Coordinate a fix, advisory, and release when the report is accepted

Complex cryptographic, dependency, or platform-adjacent issues may require more
time to validate. Please keep details private while the issue is under review.

## Scope

Examples of in-scope reports:

- Incorrect signature verification or accepted invalid signatures
- Signing behavior that differs from documented hashing requirements
- API secret or approval-token leakage through SDK behavior
- Broken Passkey approval flow checks in SDK or mock-server behavior that could
  mislead integrators
- Dependency vulnerabilities that affect SDK consumers
- Documentation that instructs users to handle keys, tokens, or approvals
  unsafely

Examples of out-of-scope reports:

- Public discussion of a vulnerability before private disclosure
- Social engineering, phishing, or physical attacks
- Denial-of-service issues against public infrastructure not controlled by this
  repository
- Vulnerabilities caused only by committing real secrets to an application
  repository
- Mock-server behavior that is intentionally local-only and does not affect SDK
  security assumptions or user guidance

## Coordinated Disclosure

If a report is accepted, maintainers may publish a GitHub security advisory,
release notes, or changelog entry after a fix is available. Reporter credit can
be included when requested and appropriate.

