# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This package tracks the verification engine published in
[signedbyai/truedoc](https://github.com/signedbyai/truedoc) — see that
repository's own `CHANGELOG.md` for the engine's behavioural history prior
to this package existing.

---

## [0.1.0] — 2026-08-24

Initial release.

### Added

- `src/verify-core.mjs` — the RFC 3161 / CAdES / PAdES-LTA PDF verification
  engine, unchanged from the version deployed at
  [truedoc.eu](https://truedoc.eu), published as a standalone,
  zero-dependency npm package for embedding in other applications.
- Hand-written TypeScript declarations (`src/verify-core.d.ts`) covering
  the full exported surface: `verify`, `extractSignatures`, `KNOWN_ROOTS`,
  `registerResolver`, `resolveIdentity`.
- README with quickstart, full API reference, and the status-verdict table.
- Runnable examples for Node, a browser `<script type="module">`, and
  Deno/Bun (`examples/`).
- Smoke test (`test/smoke.mjs`) covering the exported surface and the
  `no-signature` path, which needs no PDF fixtures. Full behavioural
  regression coverage against real signed/timestamped PDFs lives in the
  `truedoc` repository's fixture harness, since the engine itself is
  unchanged here.
