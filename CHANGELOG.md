# Changelog

All notable changes to this project are documented here.

This project is in Developer Preview. APIs may evolve; test changes with
non-production keys before upgrading production integrations.

## Unreleased

### Documentation

- Added contributor and security policy documentation.
- Added root README development and testing commands.
- Clarified Go and TypeScript timeout option names.
- Corrected example listings and repository links.
- Improved Go error-handling snippets so structured `SignResult` errors are not
  discarded before callers can inspect `ErrorCode` or approval metadata.

## v1.0.1 - 2026-04-22

### Changed

- Mock server binds to `0.0.0.0` by default so Docker containers and VMs can
  reach it through the host gateway.

## v1.0.0 - 2026-04-22

### Added

- First tagged Developer Preview release of the TEENet SDK.
- Go SDK module under `github.com/TEENet-io/teenet-sdk/go`.
- TypeScript SDK package `@teenet/sdk`.
- Local mock server for signing, voting, Passkey approval, API key, and admin
  endpoint development.
- Bilingual Docsify documentation site.

