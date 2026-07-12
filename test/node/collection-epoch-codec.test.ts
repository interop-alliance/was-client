/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the key-epoch codec seam on a Collection handle (no network,
 * no real crypto):
 *
 *  - an epoch-bearing per-handle encryption override is forwarded to the
 *    provider's `codecFor` (so it resolves the epoch path, not the single-key
 *    path);
 *  - rotating the `encryption` marker on a handle (via `replaceDescription`, the
 *    primitive the recipient operations build on) drops the memoized codec, so
 *    the next write on the SAME handle re-resolves under the new epoch rather
 *    than reusing the stale one.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { WasClient } from '../../src/index.js'
import type {
  CollectionEncryption,
  EncryptionOverride,
  EncryptionProvider,
  ResourceCodec,
  ResourceMetadataCustom
} from '../../src/index.js'
import { resolveCodec, identityCodec } from '../../src/internal/codec.js'
import type { ClientContext } from '../../src/internal/request.js'

/**
 * A fake codec bound to a fixed epoch that records each `encode` call, standing
 * in for a real `EdvCodec` whose write key/epoch is frozen at construction.
 *
 * @param epoch {string}
 * @param log {string[]}
 * @returns {ResourceCodec}
 */
function epochCodec(epoch: string, log: string[]): ResourceCodec {
  return {
    async encode({ id, data }) {
      log.push(`encode:${epoch}`)
      return {
        id,
        body: new TextEncoder().encode(JSON.stringify({ epoch, data })),
        contentType: 'application/jose+json'
      }
    },
    async decode(): Promise<Record<string, never>> {
      return {}
    },
    async encodeMeta({ custom }): Promise<{ custom: object }> {
      return { custom }
    },
    async decodeMeta({ custom }): Promise<ResourceMetadataCustom> {
      return (custom ?? {}) as ResourceMetadataCustom
    }
  }
}

describe('epoch-bearing encryption override', () => {
  it('forwards the full marker so codecFor takes the epoch path', async () => {
    const seen: Array<{
      encryption?: CollectionEncryption
      keys?: unknown
    }> = []
    const provider: EncryptionProvider = {
      async codecFor(input) {
        seen.push({ encryption: input.encryption, keys: input.keys })
        return identityCodec
      }
    }
    const marker: CollectionEncryption = {
      scheme: 'edv',
      epochs: [{ id: 'did:key:zEpoch1', recipients: [] }],
      currentEpoch: 'did:key:zEpoch1'
    }
    const context = { encryption: provider } as unknown as ClientContext
    await resolveCodec(context, {
      spaceId: 's',
      collectionId: 'c',
      // A full CollectionEncryption marker is a valid EncryptionOverride.
      override: marker as unknown as EncryptionOverride
    })
    expect(seen).toHaveLength(1)
    expect(seen[0]!.encryption?.epochs?.length).toBe(1)
    expect(seen[0]!.encryption?.currentEpoch).toBe('did:key:zEpoch1')
  })
})

describe('rotate-then-write on the same handle', () => {
  /**
   * Builds a `WasClient` whose collection-description GET returns a mutable
   * marker (a PUT to the description path rotates it), so a handle's marker
   * discovery re-reads the current epoch. `codecFor` records the epoch of every
   * codec it builds.
   *
   * @returns {object}
   */
  function rotatingClient() {
    const builtEpochs: string[] = []
    const encodeLog: string[] = []
    let marker: CollectionEncryption = {
      scheme: 'edv',
      epochs: [{ id: 'epoch-1', recipients: [] }],
      currentEpoch: 'epoch-1'
    }
    const encryption: EncryptionProvider = {
      async codecFor({ encryption: enc }) {
        const epoch = enc?.currentEpoch ?? 'single'
        builtEpochs.push(epoch)
        return epochCodec(epoch, encodeLog)
      }
    }
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      async request(args: {
        url?: string
        method?: string
        json?: { encryption?: CollectionEncryption }
      }) {
        const method = (args.method ?? 'GET').toUpperCase()
        const segments = new URL(args.url ?? '').pathname
          .split('/')
          .filter(Boolean)
        const isCollectionDesc =
          segments.length === 3 && segments[0] === 'space'
        if (method === 'PUT' && isCollectionDesc && args.json?.encryption) {
          // Rotate the served marker (what replaceDescription does server-side).
          marker = args.json.encryption
          return {
            status: 200,
            headers: new Headers({ etag: '"v2"' }),
            data: { id: 'c', type: ['Collection'] },
            async json() {
              return { id: 'c', type: ['Collection'] }
            }
          } as unknown as HttpResponse
        }
        if (method === 'GET' && isCollectionDesc) {
          const description = {
            id: 'c',
            type: ['Collection'],
            encryption: marker
          }
          return {
            status: 200,
            headers: new Headers({
              'content-type': 'application/json',
              etag: '"v1"'
            }),
            data: description,
            async json() {
              return description
            }
          } as unknown as HttpResponse
        }
        // Resource writes/reads: a generic 200.
        return {
          status: 200,
          headers: new Headers({ etag: '"r1"' }),
          data: {},
          async json() {
            return {}
          },
          async blob() {
            return new Blob([])
          }
        } as unknown as HttpResponse
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient,
      encryption
    })
    return { client, builtEpochs, encodeLog }
  }

  it('re-resolves the codec under the new epoch after a marker rotation', async () => {
    const { client, builtEpochs, encodeLog } = rotatingClient()
    const collection = client.space('s').collection('c')

    // First write: marker discovery resolves the codec under epoch-1.
    await collection.put('r1', { a: 1 })
    expect(builtEpochs).toEqual(['epoch-1'])
    expect(encodeLog).toEqual(['encode:epoch-1'])

    // Rotate the marker on the same handle (the recipient ops CAS this field).
    await collection.replaceDescription({
      encryption: {
        scheme: 'edv',
        epochs: [
          { id: 'epoch-1', recipients: [] },
          { id: 'epoch-2', recipients: [] }
        ],
        currentEpoch: 'epoch-2'
      }
    })

    // Second write on the SAME handle must encrypt under epoch-2, not the stale
    // memoized epoch-1 codec.
    await collection.put('r2', { b: 2 })
    expect(builtEpochs).toEqual(['epoch-1', 'epoch-2'])
    expect(encodeLog).toEqual(['encode:epoch-1', 'encode:epoch-2'])
  })
})
