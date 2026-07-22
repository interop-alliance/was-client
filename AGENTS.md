# Agent Guidelines

This is a client implementation of the Wallet Attached Storage spec, a W3C CCG
work item (home: <https://github.com/w3c-ccg/wallet-attached-storage-spec>;
rendered: <https://w3c-ccg.github.io/wallet-attached-storage-spec/>).

The internal design (layering, request lifecycle, the codec/encryption seam, and
the invariants to preserve when changing things) is documented in
[ARCHITECTURE.md](./ARCHITECTURE.md) -- read it before making structural
changes.

Other useful reference documents:

- /home/dmitri/code/Interop/zcap-developer-guide
- /home/dmitri/code/Interop/was-teaching-server/AGENTS.md
- /home/dmitri/code/Interop/ezcap/AGENTS.md

## Toolchain & Project Layout

### Package Manager

Use `pnpm` (not `npm` or `yarn`). The lockfile is `pnpm-lock.yaml`. Install deps
with `pnpm install`; run scripts with `pnpm run <script>` or `pnpm <script>`.

### Build

The library is built with `tsc` (not `vite build`). `vite.config.ts` exists only
to configure Vitest and to run `vite dev` as a server for Playwright. Running
`pnpm run build` compiles `src/` to `dist/` via `tsconfig.json`.

### Two tsconfigs

- `tsconfig.json` — library build only; includes `src/**/*`
- `tsconfig.dev.json` — extends the above with `noEmit: true`; adds `test/**/*`,
  `vite.config.ts`, and `playwright.config.ts` so ESLint's type-aware rules
  cover all files

Do not add test files to `tsconfig.json` — they would be emitted into `dist/`.

### Tests

- `test/node/` — Vitest unit tests (`pnpm run test:node`); run in Node
- `test/browser/` — Playwright tests (`pnpm run test:browser`); run in real
  Chromium via a Vite dev server (`pnpm run dev`)

The `dev` script exists solely to give Playwright a server that can serve and
transform TypeScript source files on the fly. There is no browser app.

### ESM & import paths

The package is ESM-only (`"type": "module"`). Local imports must use the `.js`
extension even though source files are `.ts` — e.g.
`import { Example } from '../../src/index.js'`. TypeScript's
`moduleResolution: Bundler` resolves these to the `.ts` source at compile time.

## Conventions

Code style, refactoring, JSDoc, comment, and error-handling conventions live in
@CONTRIBUTING.md -- follow them.
