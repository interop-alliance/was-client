/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The core entry points stay off the encrypted-collection graph. The package
 * is split by subpath rather than by package: `.`, `./paths`, `./log`, and
 * `./sync` are the core client, and `./edv` is the one entry that pulls the
 * encrypted collection graph (`@interop/edv-client`,
 * `@interop/minimal-cipher`, `@interop/x25519-key-agreement-key`). The module
 * headers in `codec.ts`, `edv/index.ts`, and `sync/provisioning.ts` state the
 * rule; this test enforces it by walking each core entry's transitive
 * static-import graph over `src/` and refusing any reach into `src/edv/` or
 * into the three packages. The single allowed `edv/` module is
 * `edv/constants.ts`, which `sync/provisioning.ts` reads for
 * `EDV_SCHEME_VERSION` and which reaches only core modules itself.
 *
 * `./log` is the one core entry that is not crypto-free: it binds
 * `@interop/vh-resource-log`'s store port, and that library's graph includes
 * `@interop/did-method-webvh` and `@noble/curves` -- the hashing and proof
 * kernel only, with no DID resolution. The edv rule above still binds it.
 *
 * `./identity` is a second non-core entry, alongside `./edv`: it pulls
 * `@interop/capability-agent` and `@interop/x25519-key-agreement-key` for its
 * did:key derivation, and like `./edv` it is not walked by this test.
 *
 * A second rule, one level further in, splits the encrypted surface itself:
 * `./edv/core` is the transport-free entry (`edv/core.ts`), and `./edv` is
 * that barrel plus the modules that talk to a server. The offline entry must
 * reach no transport module and none of the HTTP packages, so a consumer that
 * only decrypts bytes it already holds -- `@interop/wallet-backup` opening an
 * archive, say -- never evaluates one. That rule is walked over runtime edges
 * only: a type-only import is erased at build time, and `edv/EdvCodec.ts`
 * legitimately names `WasTransport` as a type. The core-entry rule above
 * deliberately counts type imports instead, since a type reach into `edv/` is
 * the first step of a runtime one.
 *
 * That second rule reports static and dynamic edges apart. The static closure
 * is what an offline consumer evaluates when it imports the entry, and it must
 * hold no transport module. One dynamic edge is allowed, and pinned by name:
 * `createEdvDocCipher` loads `edv/transportFactory.ts` through `import()` when
 * a caller passes a `spaceId`, which only a caller with a server does. Any
 * other `import()` in the closure would be a hole in the static assertions, so
 * the set of dynamic edges is asserted exactly. The core-entry rule makes no
 * such distinction, since a reach into `edv/` is a reach whenever it happens:
 * it walks dynamic edges as if they were static ones.
 *
 * A third rule splits `./edv/core` itself: `./edv/cipher` (`edv/cipher.ts`) is
 * the part of it that also stays off the resource-log graph
 * (`@interop/vh-resource-log`, `@interop/did-method-webvh`,
 * `@interop/storage-core`, and every `src/log/` module), which `./edv/core`
 * reaches only through `edv/logGovernedDescriptorStore.ts`. The assertions
 * mirror the second rule's shape: static and dynamic edges apart, the same
 * gated `transportFactory.ts` import allowed, and a vacuous-pass guard that
 * checks `./edv/core` still reaches the resource-log graph the cipher entry
 * leaves out.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, it, expect } from 'vitest'

const SRC = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../src'
)

const CORE_ENTRIES = ['index.ts', 'paths.ts', 'log/index.ts', 'sync/index.ts']

const ENCRYPTION_PACKAGES = [
  '@interop/edv-client',
  '@interop/minimal-cipher',
  '@interop/x25519-key-agreement-key'
]

const ALLOWED_EDV_MODULES = new Set(['edv/constants.ts'])

/**
 * Matches the module specifier of every static `import ... from '...'`,
 * `export ... from '...'`, and bare `import '...'` in a source file. Type-only
 * imports are included on purpose: a type reach into `edv/` is the first
 * step of a runtime one.
 */
const SPECIFIER =
  /(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]/g

/**
 * Matches the specifier of every dynamic `import('...')` call. The parenthesis
 * must be followed by a quote, so a method named `import` and a bare
 * `import()` inside a comment are both skipped.
 */
const DYNAMIC_SPECIFIER = /(?<!\.)\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g

/**
 * Resolves one specifier against the module that imports it. A relative
 * specifier becomes a `src/`-relative `.ts` path; a bare package specifier is
 * returned unchanged.
 *
 * @param importer {string}     the importing module, `src/`-relative
 * @param specifier {string}
 * @returns {string}
 */
function resolveSpecifier(importer: string, specifier: string): string {
  if (!specifier.startsWith('.')) {
    return specifier
  }
  return path.join(path.dirname(importer), specifier).replace(/\.js$/, '.ts')
}

/**
 * Reads one module and returns its outgoing edges, split by kind: the `src/`
 * modules and the external packages it names in a static import, and the same
 * two for the targets of its dynamic `import()` calls.
 *
 * @param relative {string}    a `src/`-relative module path
 * @param options {object}
 * @param options.specifier {RegExp}   the static-import matcher to apply
 * @returns {{ modules: string[]; packages: string[];
 *   dynamicModules: string[]; dynamicPackages: string[] }}
 */
function edgesOf(
  relative: string,
  { specifier }: { specifier: RegExp }
): {
  modules: string[]
  packages: string[]
  dynamicModules: string[]
  dynamicPackages: string[]
} {
  const source = fs.readFileSync(path.join(SRC, relative), 'utf8')
  const modules: string[] = []
  const packages: string[] = []
  const dynamicModules: string[] = []
  const dynamicPackages: string[] = []
  for (const match of source.matchAll(specifier)) {
    const found = match[1] ?? match[2]
    if (found === undefined) {
      continue
    }
    const target = resolveSpecifier(relative, found)
    if (found.startsWith('.')) {
      modules.push(target)
    } else {
      packages.push(target)
    }
  }
  for (const match of source.matchAll(DYNAMIC_SPECIFIER)) {
    const found = match[1]
    if (found === undefined) {
      continue
    }
    const target = resolveSpecifier(relative, found)
    if (found.startsWith('.')) {
      dynamicModules.push(target)
    } else {
      dynamicPackages.push(target)
    }
  }
  return { modules, packages, dynamicModules, dynamicPackages }
}

/**
 * Walks the import graph from one `src/`-relative entry module and returns
 * every reachable `src/` module (relative paths) and every external package
 * specifier encountered. Dynamic edges are followed alongside static ones: a
 * reach into `edv/` counts whenever it happens.
 *
 * @param entry {string}   a `src/`-relative module path
 * @returns {{ modules: Set<string>; packages: Set<string> }}
 */
function reachableFrom(entry: string): {
  modules: Set<string>
  packages: Set<string>
} {
  const modules = new Set<string>()
  const packages = new Set<string>()
  const queue = [entry]
  while (queue.length > 0) {
    const relative = queue.pop() as string
    if (modules.has(relative)) {
      continue
    }
    modules.add(relative)
    const edges = edgesOf(relative, { specifier: SPECIFIER })
    queue.push(...edges.modules, ...edges.dynamicModules)
    for (const specifier of [...edges.packages, ...edges.dynamicPackages]) {
      packages.add(specifier)
    }
  }
  return { modules, packages }
}

/**
 * Like `SPECIFIER`, but skips `import type ... from` and `export type ... from`
 * so only edges that survive into the build are counted. `verbatimModuleSyntax`
 * is on, so every other form -- including an import whose specifiers are all
 * inline `type` -- emits a module evaluation.
 */
const RUNTIME_SPECIFIER =
  /(?:import|export)\s+(?!type\s)[^'"]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]/g

/**
 * Modules the transport-free entry must not reach at runtime: the WAS-backed
 * EDV transport, the signed-request wrapper, and the four handle classes.
 */
const TRANSPORT_MODULES = [
  'edv/WasTransport.ts',
  'internal/request.ts',
  'WasClient.ts',
  'Space.ts',
  'Collection.ts',
  'Resource.ts'
]

/**
 * Packages the transport-free entry must not reach at runtime. All three load
 * at module scope wherever they are imported.
 */
const HTTP_PACKAGES = [
  '@interop/http-client',
  '@interop/http-signature-zcap-invoke',
  '@interop/ezcap'
]

/**
 * Modules the log-free cipher entry must not reach at runtime, on top of the
 * transport modules above: the log-governed descriptor store and the
 * descriptor-acquisition module that pulls it in. Every `log/*` module counts
 * too, checked separately by its path prefix.
 */
const RESOURCE_LOG_MODULES = [
  'edv/logGovernedDescriptorStore.ts',
  'edv/acquire.ts'
]

/**
 * Packages the log-free cipher entry must not reach through the resource-log
 * modules above: the resource-log verifier and the did:webvh method it
 * resolves through.
 *
 * `@interop/storage-core` is deliberately not asserted here even though
 * `logGovernedDescriptorStore.ts` imports it directly (for
 * `RESOURCE_LOG_METHOD`). It already reaches `edv/cipher.ts` by a second,
 * unrelated path this split does not touch: `edv/EdvCodec.ts` imports the
 * error classes from `errors.ts`, and `errors.ts` imports `ProblemTypes` from
 * `@interop/storage-core` to build `mapError`'s problem-kind table. Removing
 * that edge means moving `mapError` off `errors.ts`, which is used by
 * `internal/request.ts`, `internal/service.ts`, `sync/port.ts`, and
 * re-exported from the package root -- out of scope for this split.
 */
const RESOURCE_LOG_PACKAGES = [
  '@interop/vh-resource-log',
  '@interop/did-method-webvh'
]

/**
 * Walks the runtime import graph from one `src`-relative entry module,
 * counting only the edges that survive type erasure.
 *
 * `modules` and `packages` are the static closure, which is what importing the
 * entry evaluates. `dynamicEdges` holds every `import()` found in that closure
 * and in the graph behind those dynamic targets, as `'<from> -> <target>'`
 * strings, so an `import()` reached only through another one is reported too.
 *
 * @param entry {string}   a `src/`-relative module path
 * @returns {{ modules: Set<string>; packages: Set<string>;
 *   dynamicEdges: Set<string> }}
 */
function runtimeGraphFrom(entry: string): {
  modules: Set<string>
  packages: Set<string>
  dynamicEdges: Set<string>
} {
  const modules = new Set<string>()
  const packages = new Set<string>()
  const queue = [entry]
  while (queue.length > 0) {
    const relative = queue.pop() as string
    if (modules.has(relative)) {
      continue
    }
    modules.add(relative)
    const edges = edgesOf(relative, { specifier: RUNTIME_SPECIFIER })
    queue.push(...edges.modules)
    for (const specifier of edges.packages) {
      packages.add(specifier)
    }
  }

  // A second walk for the dynamic edges, this one following dynamic targets so
  // that an `import()` behind an `import()` still shows up.
  const dynamicEdges = new Set<string>()
  const scanned = new Set<string>()
  const pending = [...modules]
  while (pending.length > 0) {
    const relative = pending.pop() as string
    if (scanned.has(relative)) {
      continue
    }
    scanned.add(relative)
    const edges = edgesOf(relative, { specifier: RUNTIME_SPECIFIER })
    pending.push(...edges.modules, ...edges.dynamicModules)
    for (const target of [...edges.dynamicModules, ...edges.dynamicPackages]) {
      dynamicEdges.add(`${relative} -> ${target}`)
    }
  }

  return { modules, packages, dynamicEdges }
}

describe('core entry import graphs', () => {
  for (const entry of CORE_ENTRIES) {
    describe(entry, () => {
      const { modules, packages } = reachableFrom(entry)

      it('reaches no edv/ module beyond the crypto-free constants', () => {
        const edvModules = [...modules].filter(
          module =>
            module.startsWith('edv/') && !ALLOWED_EDV_MODULES.has(module)
        )
        expect(edvModules).toEqual([])
      })

      it('imports none of the encrypted-collection packages', () => {
        const leaked = [...packages].filter(specifier =>
          ENCRYPTION_PACKAGES.some(
            pkg => specifier === pkg || specifier.startsWith(`${pkg}/`)
          )
        )
        expect(leaked).toEqual([])
      })
    })
  }

  it('the allowed edv module reaches only core modules', () => {
    const { modules, packages } = reachableFrom('edv/constants.ts')
    expect([...modules].filter(module => module.startsWith('edv/'))).toEqual([
      'edv/constants.ts'
    ])
    const leaked = [...packages].filter(specifier =>
      ENCRYPTION_PACKAGES.some(pkg => specifier.startsWith(pkg))
    )
    expect(leaked).toEqual([])
  })

  it('the edv entry does reach the encrypted-collection packages', () => {
    // Guards the test itself: if the walker stopped seeing packages, the
    // core assertions above would pass vacuously.
    const { packages } = reachableFrom('edv/index.ts')
    for (const pkg of ENCRYPTION_PACKAGES) {
      expect([...packages].some(specifier => specifier.startsWith(pkg))).toBe(
        true
      )
    }
  })
})

describe('the transport-free edv entry', () => {
  const { modules, packages, dynamicEdges } = runtimeGraphFrom('edv/core.ts')

  it('reaches no transport module through its static imports', () => {
    const leaked = TRANSPORT_MODULES.filter(module => modules.has(module))
    expect(leaked).toEqual([])
  })

  it('imports none of the HTTP packages through its static imports', () => {
    const leaked = [...packages].filter(specifier =>
      HTTP_PACKAGES.some(
        pkg => specifier === pkg || specifier.startsWith(`${pkg}/`)
      )
    )
    expect(leaked).toEqual([])
  })

  it('makes one dynamic import, the spaceId-gated transport factory', () => {
    // The two assertions above cover what importing the entry evaluates. A
    // dynamic edge runs only if its call site does, and `createEdvDocCipher`
    // reaches this one only when given a `spaceId` -- the caller that has a
    // server. Any other `import()` out of this closure would be a transport
    // reach those assertions cannot see, so the whole set is pinned here.
    expect([...dynamicEdges].sort()).toEqual([
      'edv/docCipher.ts -> edv/transportFactory.ts'
    ])
  })

  it('does reach the cipher and the transport-free edv-client entry', () => {
    // Guards the test itself: an emptied barrel would pass the two
    // assertions above vacuously.
    expect(
      [...packages].some(specifier =>
        specifier.startsWith('@interop/minimal-cipher')
      )
    ).toBe(true)
    expect(packages.has('@interop/edv-client/core')).toBe(true)
  })

  it('the full edv entry does reach the transport', () => {
    // The other half of the split: what `./edv/core` leaves out is exactly
    // what `./edv` adds.
    const reached = runtimeGraphFrom('edv/index.ts').modules
    expect(reached.has('edv/WasTransport.ts')).toBe(true)
  })
})

describe('the log-free edv cipher entry', () => {
  const { modules, packages, dynamicEdges } = runtimeGraphFrom('edv/cipher.ts')

  it('reaches no transport module through its static imports', () => {
    const leaked = TRANSPORT_MODULES.filter(module => modules.has(module))
    expect(leaked).toEqual([])
  })

  it('imports none of the HTTP packages through its static imports', () => {
    const leaked = [...packages].filter(specifier =>
      HTTP_PACKAGES.some(
        pkg => specifier === pkg || specifier.startsWith(`${pkg}/`)
      )
    )
    expect(leaked).toEqual([])
  })

  it('reaches no resource-log module through its static imports', () => {
    const leaked = [...modules].filter(
      module =>
        module.startsWith('log/') || RESOURCE_LOG_MODULES.includes(module)
    )
    expect(leaked).toEqual([])
  })

  it('imports none of the resource-log packages through its static imports', () => {
    const leaked = [...packages].filter(specifier =>
      RESOURCE_LOG_PACKAGES.some(
        pkg => specifier === pkg || specifier.startsWith(`${pkg}/`)
      )
    )
    expect(leaked).toEqual([])
  })

  it('makes one dynamic import, the spaceId-gated transport factory', () => {
    // Same gated edge as `./edv/core`: `createEdvDocCipher` reaches
    // `transportFactory.ts` only when given a `spaceId`.
    expect([...dynamicEdges].sort()).toEqual([
      'edv/docCipher.ts -> edv/transportFactory.ts'
    ])
  })

  it('the core entry does reach the resource-log graph', () => {
    // Guards the test itself: an emptied cipher entry, or a core.ts that
    // stopped naming the log-governed exports, would pass the assertions
    // above vacuously.
    const reached = runtimeGraphFrom('edv/core.ts')
    expect(reached.modules.has('edv/logGovernedDescriptorStore.ts')).toBe(true)
    expect(
      [...reached.packages].some(specifier =>
        specifier.startsWith('@interop/vh-resource-log')
      )
    ).toBe(true)
  })
})
