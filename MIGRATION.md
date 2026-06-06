# Migrating an existing library to this template's infrastructure

This guide describes how to convert an existing TypeScript/JavaScript library to follow the
**infrastructure** of `isomorphic-lib-template` — package manager, build, lint/format, test
runners, CI, and packaging — **without changing the library's behavior or public API**.

It is source-runner-agnostic: the starting library may use npm/yarn/pnpm, mocha/jest/tape/vitest,
and karma/none for browser tests. The destination is always the same fixed point: this template.

> This document is the **source of truth** for the conversion. Automated tooling (e.g. a Claude
> skill) reads it. When the template's infrastructure changes, update §1 here in the same commit.

---

## 0. The fixed point (read live, at `main` HEAD)

The destination is this repo's infrastructure **as it currently stands on `main`** — there is no
pinned snapshot to keep in sync. Always read the live config files here as the authoritative
source; §1 below is a fast human-readable summary that may lag, and the **live files win on any
conflict**.

- **Canonical infra files** (read these from the template repo at HEAD):
  `package.json`, `tsconfig.json`, `tsconfig.dev.json`, `eslint.config.js`, `prettier.config.js`,
  `vite.config.ts`, `playwright.config.ts`, `.editorconfig`, `.github/workflows/ci.yml`,
  `.github/workflows/publish.yml`, `test/index.html`.

If the local template checkout might be behind its remote, `git -C <template> pull --ff-only`
before reading.

---

## 1. Target infrastructure reference

### Package manager & engine
- `pnpm` pinned via `"packageManager": "pnpm@<version>"`.
- `"engines": { "node": ">=24.0" }`, CI on Node 24. **Always raise the target to this value** (and
  bump the CI Node version to match) — the engine floor is fixed, not a per-library decision. See
  §5.

### Scripts (canonical vocabulary)
```
build         pnpm run clear && tsc
clear         rimraf dist/*
dev           vite
fix           eslint --fix src test && pnpm run format
format        prettier --write "src/**/*.ts" "test/**/*.ts" "*.md"
lint          eslint src test
prepare       pnpm run build
rebuild       pnpm run clear && pnpm run build
test          pnpm run fix && pnpm run lint && pnpm run test-node && pnpm run test-browser
test-node     vitest run
test-browser  playwright test
test-coverage vitest run --coverage
```

### TypeScript — two configs
- `tsconfig.json` (build): `strict`, `target/lib ES2022 + DOM`, `module: ESNext`,
  `moduleResolution: Bundler`, `outDir dist`, `declaration` + `declarationMap` + `sourceMap`,
  `isolatedModules`, `verbatimModuleSyntax`, `noUncheckedIndexedAccess`, `allowSyntheticDefaultImports`,
  `skipLibCheck`, `resolveJsonModule`. `include: ["src/**/*"]`.
- `tsconfig.dev.json`: `extends ./tsconfig.json`, `noEmit: true`, widens `include` to `src`, `test`,
  `vite.config.ts`, `playwright.config.ts` (used by editor + typed eslint).

### ESLint — flat config (`eslint.config.js`)
- eslint 10, `@eslint/js` recommended + `typescript-eslint` (v8) recommended + `eslint-config-prettier`
  (last). `globalIgnores(['dist', '**/*.min.js'])`. `parserOptions.project: ['./tsconfig.dev.json']`.
- Rule posture: permissive. `no-explicit-any: off`; `@typescript-eslint/no-unused-vars` with
  `^_` ignore patterns; `curly: ['error','all']`, `no-var`, `prefer-const`.

### Prettier 3 (`prettier.config.js`, ESM `export default`)
`arrowParens: 'avoid'`, `bracketSameLine: false`, `bracketSpacing: true`, `proseWrap: 'always'`,
`semi: false`, `singleQuote: true`, `trailingComma: 'none'`.

### Tests
- **Node:** vitest. `vite.config.ts` exports a vitest config:
  `test.include: ['test/node/**/*.test.ts', 'src/**/*.test.ts']`, coverage provider `v8`,
  reporters `['text','lcov']`, `include: ['src/**/*.ts']`.
- **Browser:** playwright. `playwright.config.ts` → `testDir: './test/browser'`, chromium project,
  `webServer` runs `pnpm run dev` (vite) at `http://localhost:5173`. Browser specs load
  `/test/index.html` and dynamically import the source. Convention: `test/browser/*.spec.ts`.
- **Layout:** `test/node/` (vitest, `*.test.ts`), `test/browser/` (playwright, `*.spec.ts`),
  `test/index.html` (browser harness page). Co-located `src/**/*.test.ts` also allowed.

### Packaging (`package.json`)
- `"type": "module"`, `"sideEffects": false`.
- `exports`: per entry `{ types, react-native, import, default }` all pointing at the built `dist/*.js` / `.d.ts`. The `default` condition is required so CJS-based resolvers (e.g. tsx's static-import resolver, used by some test runners) can resolve the package — the `import` condition alone is only honored by the native ESM resolver.
- `module`/`browser`/`types` top-level fields set to the built entry.
- `files: ["dist", "README.md", "LICENSE.md"]`.
- `publishConfig: { access: "public", provenance: true }`.

### CI (`.github/workflows/`)
- `ci.yml` on push/PR to main: checkout → `pnpm/action-setup` → `setup-node` (24) →
  `pnpm install --frozen-lockfile` → lint → build → test-node → `playwright install --with-deps
  chromium` → test-browser.
- `publish.yml` on release published: build → `npm publish` with `id-token: write` for provenance
  (npm trusted publishing; needs npm >= 11.5.1).

### Repo hygiene
`.editorconfig` (2-space, lf, utf-8, final newline, max 80), `CONTRIBUTING.md`, `CHANGELOG.md`.

---

## 2. Approach: classify, diff, preserve, phase

0. **Pre-flight — app or library?** This template targets *isomorphic libraries published to npm*.
   Classify the target first; the answer changes — or cancels — the work.

   - **Library signals:** `package.json` has `exports` / `main` / `module` / `types` plus a `files`
     allowlist; builds a consumable `dist`; no root app-entry HTML; not `"private": true`.
   - **App signals:** a root `index.html` (Vite) or a framework app config (`next.config.*`,
     Expo `app.json`, `metro.config.*`, React Native); often `"private": true`; **no** `exports` /
     `files`; the build emits a bundle/site, not a package; has `dev` / `start` / `preview` /
     `serve` scripts.
   - **Edge:** a `bin` entry ⇒ CLI tool — treat as a library for packaging, but it has no browser
     track. Monorepo ⇒ classify each package.

   **If it's a library:** proceed with steps 1–3 and the full §3 playbook. **Then check the source
   language:** if the library's source is **JavaScript** (`.js`/`.cjs`/`.mjs`, no `.ts`), the plan
   **must include a full conversion to TypeScript** — this is expected and in-scope for JS targets,
   not optional, and it is *not* barred by §6 (behavior, public API, and return shapes still stay
   identical). The conversion is what brings the library-packaging half of §1 into play for a JS lib
   (`src/*.ts`, the tsconfig pair, the `tsc`→`dist` build, `.d.ts`, `exports` conditions). See the
   **JavaScript → TypeScript** table in §4 and the dedicated phase in §3. If the source is already
   TypeScript, no conversion is needed.

   **If it's an app:** the library-packaging work **does not apply** — skip `exports` conditions,
   `sideEffects`, the single-entry `tsc` library build, `publishConfig`/provenance, and
   `publish.yml`. Only the **shared-toolchain subset** is in scope: pnpm + `packageManager`,
   vite/vitest (+ playwright if it has a browser surface), eslint flat config + typescript-eslint,
   prettier 3 + `.editorconfig`, and a lint→build→test CI shape. Diff only those. If the app already
   matches them, **say so and do not emit a conversion plan** — report "already aligned" plus any
   cosmetic nits. Don't manufacture work.

1. **Diff** the target's current infra against the in-scope subset of §1. Produce a delta table.
2. **Identify what to preserve** — things the template doesn't have but the target legitimately
   needs. Common cases: extra `exports` subpaths (e.g. `./submodule`), `paths`/type shims for
   untyped deps, networked/opt-in test files that must stay excluded from the default run,
   build outputs beyond a single entry, library-specific CI (issue automation, etc.).
3. **Emit a phased plan** (write to `_spec/template-update-plan.md` in the target repo; `_spec/`
   is conventionally gitignored). Use the phase structure in §3. (Libraries get a phased plan; an
   app that needs only a nudge gets a short checklist, not the full playbook.)

---

## 3. Phase playbook (each phase ends at a green gate)

Work on a branch; one commit per phase for easy bisect/revert.

- **Phase 0 — Baseline.** Run the library's existing tests; record the pass count. Branch
  `infra/template-alignment`. Confirm `pnpm install` reproduces the lockfile (convert lockfile if
  the library was on npm/yarn — see §4). *Gate:* existing tests green; baseline pass count noted.
- **Phase 1 — Package manager + scripts.** Add `packageManager`; rewrite `scripts` to §1's
  vocabulary (keep two-pass build temporarily if multi-tsconfig). Set `engines.node` per Decision 1.
  *Gate:* `pnpm install --frozen-lockfile` clean.
- **Phase 2 — Prettier 3 + `.editorconfig`.** Replace prettier config; run `format` across
  `src`/`test`/markdown. **Commit the reformat alone** so later diffs aren't drowned. *Gate:*
  `prettier --check` clean; diff is formatting-only.
- **Phase 3 — ESLint flat config.** Delete `.eslintrc.*`; add `eslint.config.js`. Swap devDeps
  (remove legacy configs/plugins; add `@eslint/js`, `typescript-eslint` v8, `eslint-config-prettier`,
  `globals`, eslint 10). Point `project` at `tsconfig.dev.json`. *Gate:* `pnpm run lint` green.
- **Phase 3.5 — JavaScript → TypeScript** *(JS libraries only; skip if already TS)*. Do this
  before the tsconfig/build phases so they have `.ts` source to act on. **First generate JSDoc** for
  the existing JS — `@param`/`@returns`/`@typedef` annotations across the public surface — so the
  types are seeded and the rename is largely mechanical. Then move source into `src/` and rename
  `.js`→`.ts`, converting the JSDoc types to TS annotations and adding `import type` where needed.
  Keep behavior, public API, and return shapes byte-for-byte identical. *Gate:* source compiles
  under a minimal `tsc` (strict can come in Phase 7); existing tests still green against the built
  output.
- **Phase 4 — tsconfig consolidation.** Reduce to `tsconfig.json` + `tsconfig.dev.json`. Adopt
  `Bundler` resolution + `ESNext` + `isolatedModules`. **Keep** any `paths` shims. **Defer**
  `verbatimModuleSyntax` + `noUncheckedIndexedAccess` to Phase 7. Single `tsc` build. Verify every
  entry in `exports` still emits and resolves. *Gate:* `pnpm run build` green; built entries import.
- **Phase 5 — Node tests → vitest** *(usually the largest lift)*. Add `vite.config.ts`. Set
  `include` to the library's spec convention (keep `.spec.ts` or rename to `.test.ts` per Decision 2);
  `exclude` networked/opt-in specs. Migrate assertions + hooks per §4. Remove the old runner, its
  config, and the compile-to-`dist/test` dance if present. *Gate:* `pnpm run test-node` green with
  **pass count ≥ Phase 0 baseline**.
- **Phase 6 — Browser tests → playwright.** Add `playwright.config.ts`, `test/index.html`,
  `test/browser/`. Port browser coverage or add a smoke spec per Decision 3. Remove karma + its
  deps. *Gate:* `pnpm run test-browser` green (`playwright install chromium` first).
- **Phase 7 — Strict TS** *(optional / separate PR)*. Enable `verbatimModuleSyntax` (add
  `import type` widely) and `noUncheckedIndexedAccess` (fix real nullability findings — don't blanket-`!`).
  *Gate:* build + lint + tests green. *Fallback:* ship as a follow-up if findings are large.
- **Phase 8 — Packaging + CI + docs.** `sideEffects: false`; extend `exports` with
  `react-native`/`import` conditions (preserve all subpaths); `publishConfig` provenance per
  Decision 6. Replace CI with template `ci.yml`; add `publish.yml` per Decision 6; **keep**
  library-specific workflows. Update README badges/scripts and any `CLAUDE.md` build/test section.
  *Gate:* CI green; `npm pack` contents correct.

**Suggested commit sequence:** one per phase (Phase 5 may be several commits, batched by test
subdir). Isolate the Phase 2 reformat.

---

## 4. Source-runner migration tables

### Package manager → pnpm
- **npm:** delete `package-lock.json`; `pnpm import` then `pnpm install` to generate `pnpm-lock.yaml`;
  add `packageManager`. **yarn:** same, from `yarn.lock`. Replace `npm run`/`yarn` in scripts & CI
  with `pnpm run`.

### Test runner → vitest
| From | describe/it | Assertions | Hooks | Notes |
|---|---|---|---|---|
| **mocha + chai** | same `describe`/`it` | chai BDD → vitest: `.to.equal`→`toBe`, `.to.deep.equal`→`toEqual`, `.to.be.true/false`→`toBe(true/false)`, `.to.be.null`→`toBeNull()`, `.to.be.undefined`→`toBeUndefined()`, `.to.exist`→`toBeDefined()`, `.to.have.length(n)`→`toHaveLength(n)`, `.to.include`→`toContain`/`toMatchObject`, `.to.throw`→`toThrow` | `before/after`→`beforeAll/afterAll`; `beforeEach/afterEach` same | Audit deep vs strict equality per assertion — not a blind find/replace. `this.timeout(n)`→`it(name,fn,{timeout:n})` or config `testTimeout`. Drop `.mocharc`, c8 (vitest v8 coverage), ts-node/tsx compile step. |
| **jest** | same | jest `expect` is ~vitest-compatible | same | Mostly config-only: replace `jest.config` with `vite.config.ts`; `jest.fn/mock`→`vi.fn/vi.mock`; enable `globals: true` or import from `vitest`. |
| **tape** | rewrite to `describe`/`it` | `t.equal`→`expect().toBe`, `t.deepEqual`→`toEqual`, `t.ok`→`toBeTruthy`, `t.throws`→`toThrow`, drop `t.plan`/`t.end` | wrap setup in hooks | Largest structural rewrite of the three. |
| **vitest already** | — | — | — | Just align `vite.config.ts` `include`/coverage to §1. |

### JavaScript → TypeScript (JS libraries only)
The destination is a TS library, so a JS source tree must be converted. Sequence:
1. **JSDoc pass first.** Annotate the existing `.js` with `@param`/`@returns`/`@typedef` (and
   `@type`) across at least the public/exported surface. This documents intent, surfaces implicit
   shapes, and seeds the types — making the subsequent rename mostly mechanical rather than a
   from-scratch typing effort.
2. **Move + rename.** Relocate source to `src/` and rename `.js`→`.ts`. Convert JSDoc types into
   real TS annotations; add `import type` for type-only imports; add explicit return types on the
   exported API.
3. **Wire packaging.** This is where the library-packaging fields of §1 land (they had no JS
   equivalent): the `tsconfig.json`/`tsconfig.dev.json` pair (Phase 4), `tsc`→`dist` build, `.d.ts`
   emission, and `exports` `{ types, react-native, import, default }` conditions (Phase 8).
- **Invariant:** behavior, public API, and return shapes are unchanged — the Phase 0 baseline
  pass-count still holds after conversion.

### Browser tests → playwright
- **karma (often already disabled):** remove `karma.conf.*` + `karma-*` deps. Add
  `playwright.config.ts` + `test/index.html` + `test/browser/*.spec.ts` that dynamically imports the
  source and exercises a representative path. Decide depth per Decision 3.
- **no browser tests:** stand up the harness + one isomorphic smoke spec proving the bundle loads
  and a core API works in-browser.

---

## 5. Decisions

### Fixed (do not ask — apply these)
- **Node engine floor.** Always raise `engines.node` to the template's value (`>=24`) and bump the
  CI Node version to match. Not a per-library decision, regardless of React Native / older-runtime
  history.
- **Coverage service.** Use local vitest v8 + lcov only. **Drop any Codecov/Coveralls upload step**
  and the GitHub token/secret it requires — do not carry it forward or add it.
- **Browser test depth (default).** Default to the harness + **one smoke spec** (prove the bundle
  loads and a core API path works in-browser). Only port fuller browser coverage if the user
  explicitly asks.

### Surface to the user (these still change the work)
1. **Test file naming.** Template uses `.test.ts` (node) / `.spec.ts` (browser). Keep the
   library's existing convention (point vitest `include` at it; less git churn) or rename to match?
2. **Strict TS (Phase 7).** Adopt `verbatimModuleSyntax` + `noUncheckedIndexedAccess` now, or as a
   follow-up PR? (Recommend follow-up — it's source-level work, not infra.)
3. **Provenance / publishing.** Adopt template `publish.yml` + `publishConfig.provenance`, or leave
   the existing release flow?

---

## 6. Out of scope
No changes to library logic, public API, or result/return shapes. Infrastructure only. The Phase 0
baseline pass-count is the contract that behavior is unchanged.
