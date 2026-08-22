/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The crypto-free entry points stay crypto-free. The package is split by
 * subpath rather than by package: `.`, `./paths`, `./log`, and `./sync` are
 * the core client, and `./edv` is the one entry that pulls the encrypted
 * collection graph (`@interop/edv-client`, `@interop/minimal-cipher`,
 * `@interop/x25519-key-agreement-key`). The module headers in `codec.ts`,
 * `edv/index.ts`, and `sync/provisioning.ts` state the rule; this test
 * enforces it by walking each core entry's transitive static-import graph
 * over `src/` and refusing any reach into `src/edv/` or into the three
 * packages. The single allowed `edv/` module is `edv/constants.ts`, which
 * `sync/provisioning.ts` reads for `EDV_SCHEME_VERSION` and which reaches
 * only core modules itself.
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
 * Walks the static-import graph from one `src/`-relative entry module and
 * returns every reachable `src/` module (relative paths) and every external
 * package specifier encountered.
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
    const source = fs.readFileSync(path.join(SRC, relative), 'utf8')
    for (const match of source.matchAll(SPECIFIER)) {
      const specifier = match[1] ?? match[2]
      if (specifier === undefined) {
        continue
      }
      if (specifier.startsWith('.')) {
        const resolved = path
          .join(path.dirname(relative), specifier)
          .replace(/\.js$/, '.ts')
        queue.push(resolved)
      } else {
        packages.add(specifier)
      }
    }
  }
  return { modules, packages }
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
