# Changelog

All notable public API and compatibility changes are documented here. This
project follows Semantic Versioning; breaking changes during `0.x` releases are
called out explicitly.

## Unreleased

- Add framework-neutral gateway assertion verification and Node HTTP
  middleware with exact authority, request, origin, expiry, and replay checks.
- Add application Control APIs for resource lifecycle, Catalog management,
  organization provisioning, and resource-type configuration.

## [0.1.1-rc.2](https://github.com/2kims/lotor-sdk/compare/v0.1.0-rc.2...v0.1.1-rc.2) (2026-09-05)


### Miscellaneous Chores

* **release:** automate trusted npm publishing ([e1857c6](https://github.com/2kims/lotor-sdk/commit/e1857c654d03681a10d88dba09059bdf176f41be))
* sync [@lotor](https://github.com/lotor).dev/sdk public export ([#4](https://github.com/2kims/lotor-sdk/issues/4)) ([d932daf](https://github.com/2kims/lotor-sdk/commit/d932dafa54ddfd047e4f3f007b4b3349758b5ac6))

## 0.1.0-rc.2

- Keep the npm package page intentionally free of repository README content.

## 0.1.0-rc.1

- Add the ESM-only `@lotor.dev/sdk` Node.js package.
- Add LWP/LWPS connectivity, ownership discovery, authenticated owner retry,
  reconnect, watch events, and data-plane operations.
- License the public distribution under Apache-2.0.
