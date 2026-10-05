# Agent Guidelines

This is a client implementation of the Wallet Attached Storage spec, a W3C CCG
work item (home: <https://github.com/w3c-ccg/wallet-attached-storage-spec>;
rendered: <https://w3c-ccg.github.io/wallet-attached-storage-spec/>).

The internal design (layering, request lifecycle, the codec/encryption seam, the
invariants to preserve when changing things, and the glossary) is documented in
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
- `test/integration/` — live-server tests (`pnpm run test:integration`); the
  vitest global setup boots `was-teaching-server` in-process over a temp
  filesystem backend, unless `TEST_SERVER_URL` names a server to use instead

The `dev` script exists solely to give Playwright a server that can serve and
transform TypeScript source files on the fly. There is no browser app.

### ESM & import paths

The package is ESM-only (`"type": "module"`). Local imports must use the `.js`
extension even though source files are `.ts` — e.g.
`import { Example } from '../../src/index.js'`. TypeScript's
`moduleResolution: Bundler` resolves these to the `.ts` source at compile time.

## Roadmap & Task Conventions

All roadmap tracking lives in [ROADMAP.md](./ROADMAP.md): narrative context
(section preambles) plus structured `### WCL-N` work items, following the item
structure shared with the freewallet, was-teaching-server, was-react, and
isomorphic-lib-template roadmaps. Never create a parallel task list elsewhere
(no `TODO.md`, no task lists in other docs).

Each work item follows this schema:

- A heading `### WCL-N: [P] Title`, then a field block, then free prose context.
  `[P]` is the priority tag (`[H]`, `[M]`, `[L]`), computed from the `priority`
  field by the ordering script, which may also add `[blocks N]` and
  `[after WCL-X]` after it. No marker in a title is edited by hand.
- Fields: `status` (`todo` / `in-progress` / `draft` / `done`), `priority`
  (`high` / `medium` / `low`), `labels` (comma-separated), optional
  `discovered-from` (the item, review, or question the item came out of, with
  its date), optional `blocked-by` (other `WCL-N` ids, or an external id such as
  `WAS-N`, `WASS-N` or `FW-N`), `blocks` (derived, written by the script), a
  `touches:` list where it applies, and an `acceptance:` checklist.
- `draft` marks items with no actionable done-state yet (blocked externally or
  parking records); a draft states _why_ instead of acceptance criteria and must
  gain acceptance criteria when promoted to `todo`.
- `touches:` is the field defined in the canonical schema in
  isomorphic-lib-template's AGENTS.md ("Roadmap & Task Conventions"): required
  for any item changing a spec, a wire contract, or a shared `@interop/*` API,
  it lists the affected repos and their ARCHITECTURE/AGENTS files. Each entry is
  a reminder to file follow-up work in that repo, annotated before `done` with
  the item filed there, what already shipped, or `unaffected: <repo> (<why>)`;
  it does not block `done`. See that file for the full definition.

Sections are kinds of work, ordered by what an open item costs: Security,
Correctness and consistency, Spec and protocol, Features, Performance,
Docs/tests/cleanup, Someday / Maybe, Parking (every `draft`). An item goes in
the section for what it is, not for where it was found; provenance is the
`discovered-from` field. The "Recorded decisions" section at the end holds
settled design decisions, not items.

Rules:

- After any edit to ROADMAP.md, run `pnpm roadmap`
  (`node scripts/roadmap-order.mjs`). It orders each section so a dependency
  precedes its dependents (ties broken by priority, then prior order; the
  Someday / Maybe section is ordered by id), writes `blocks:` as the reverse of
  the open `blocked-by` edges, rewrites the title markers, and regenerates the
  "Index (generated)" block under the H1. It never moves an item between
  sections. `--check` reports without writing; `--satisfied` lists `blocked-by`
  entries that name archived items, which can be removed.
- Item ids are permanent and never reused. The `nextAvailableId: <n>` line at
  the top of ROADMAP.md is the sole source of the next id: filing an item takes
  `n` and rewrites the line to `n + 1`, in the same edit. Never derive the next
  id by scanning the roadmap; the highest id usually lives in
  archived-roadmap.md, not in the open roadmap. If the counter's id already
  appears in either file, the counter is stale: reset it to one past the highest
  id across both files, then take it.
- Every non-draft item needs acceptance criteria before it may be moved to
  `in-progress`.
- Statuses are edited in place (change the `status:` field); acceptance
  checkboxes are ticked as they are met.
- **Completing an item includes archiving it**: in the same pass that marks it
  `done`, move it verbatim (number, title, field block, prose, with its `done`
  date) from ROADMAP.md to [archived-roadmap.md](./archived-roadmap.md),
  append-only at the bottom. A `done` item left in ROADMAP.md is an unfinished
  task. CHANGELOG.md remains the record of what landed; do not rewrite or
  summarize items on the way into the archive, and do not fix old references.
- A `touches:` entry does not block `done`. An item is done when its own repo's
  work is done and every entry carries its annotation, so the cross-repo
  follow-ups are on record in their own roadmaps.
- Work discovered mid-implementation gets its own WCL-N item immediately, with
  `discovered-from: WCL-N` in its field block, plus a `blocked-by` link if it
  blocks anything.
- Reference item ids only in the roadmap documents (ROADMAP.md and
  archived-roadmap.md). Do not put them in commit messages, PR descriptions, or
  CHANGELOG.md entries -- those describe the change itself, not the tracking
  item.
- `blocked-by` links only express dependencies implied by the work itself; do
  not invent orderings.

## Ecosystem conventions

- Cross-repo lessons (invariants, gotchas, and process recipes that span repos)
  live in the ecosystem learnings file,
  [byoe-ecosystem/LEARNINGS.md](https://github.com/interop-alliance/byoe-ecosystem/blob/main/LEARNINGS.md)
  (usually checked out beside this repo as `../byoe-ecosystem`); read it at the
  start of any cross-repo task.
- Cross-repo decisions are recorded as `decisions/NNNN-slug.md` in the repo that
  owns the contract; the convention and template are canonical in
  [isomorphic-lib-template's `decisions/`](https://github.com/interop-alliance/isomorphic-lib-template/tree/main/decisions).
- The domain vocabulary is [ARCHITECTURE.md](./ARCHITECTURE.md)'s Glossary; the
  refinement rules and the mapping for skills that expect `CONTEXT.md` or
  `docs/adr/` are canonical in
  [isomorphic-lib-template's AGENTS.md](https://github.com/interop-alliance/isomorphic-lib-template/blob/main/AGENTS.md)
  ("Domain language") and its
  [`decisions/README.md`](https://github.com/interop-alliance/isomorphic-lib-template/blob/main/decisions/README.md)
  ("Qualifying test").

## Conventions

Code style, refactoring, JSDoc, comment, and error-handling conventions live in
@CONTRIBUTING.md -- follow them.
