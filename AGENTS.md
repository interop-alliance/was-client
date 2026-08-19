# Agent Guidelines

This is a client implementation of the Wallet Attached Storage spec, a W3C CCG
work item (home: <https://github.com/w3c-ccg/wallet-attached-storage-spec>;
rendered: <https://w3c-ccg.github.io/wallet-attached-storage-spec/>).

The internal design (layering, request lifecycle, the codec/encryption seam, and
the invariants to preserve when changing things) is documented in
[ARCHITECTURE.md](./ARCHITECTURE.md) -- read it before making structural
changes.

Other useful reference documents:

- <https://github.com/interop-alliance/zcap-developer-guide>
- <https://github.com/interop-alliance/was-teaching-server/blob/main/AGENTS.md>
- the AGENTS.md in <https://github.com/interop-alliance/ezcap>

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

## Roadmap & Task Conventions

Roadmap tracking lives in [ROADMAP.md](./ROADMAP.md): narrative context plus
structured `### WCL-N` work items, following the item structure shared with the
freewallet, was-teaching-server, was-react, and isomorphic-lib-template
roadmaps. Never create a parallel task list elsewhere. The full item schema
lives in that file's "Item format" header (the generic schema is canonical in
isomorphic-lib-template's AGENTS.md under "Roadmap & Task Conventions"); the
rules that apply when working an item:

- Item ids are permanent and never reused; a new item takes the next unused
  number regardless of section.
- Statuses are edited in place; acceptance checkboxes are ticked as they are
  met.
- **Completing an item includes archiving it**: in the same pass that marks it
  `done`, move it verbatim (number, title, field block, prose, with its `done`
  date) from ROADMAP.md to [archived-roadmap.md](./archived-roadmap.md),
  append-only at the bottom. A `done` item left in ROADMAP.md is an unfinished
  task. CHANGELOG.md remains the record of what landed; do not rewrite or
  summarize items on the way into the archive.
- An item carrying a `touches:` field may not flip to `done` while any entry in
  it is unresolved -- an unresolved entry is unfinished work of the item itself,
  not a follow-up.
- Work discovered mid-implementation gets its own WCL-N item immediately, noting
  `discovered-from: WCL-N` in its prose.

## Ecosystem conventions

- Cross-repo lessons (invariants, gotchas, and process recipes that span repos)
  live in the ecosystem learnings file,
  [byoe-ecosystem/LEARNINGS.md](https://github.com/interop-alliance/byoe-ecosystem/blob/main/LEARNINGS.md)
  (usually checked out beside this repo as `../byoe-ecosystem`); read it at the
  start of any cross-repo task.
- Cross-repo decisions are recorded as `decisions/NNNN-slug.md` in the repo that
  owns the contract; the convention and template are canonical in
  [isomorphic-lib-template's `decisions/`](https://github.com/interop-alliance/isomorphic-lib-template/tree/main/decisions).

## Conventions

Code style, refactoring, JSDoc, comment, and error-handling conventions live in
@CONTRIBUTING.md -- follow them.
