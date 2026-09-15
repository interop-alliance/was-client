/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared test helpers for the codec seam: the single-request narrowing of
 * `ResourceCodec` several suites assert against, a stub backend-feature
 * probe for the affordance gates, and an in-memory backend for chunked reads
 * and writes.
 */
import type { HttpResponse } from '@interop/http-client'
import { featureProbeFrom } from '../../src/internal/features.js'
import type { FeatureProbe } from '../../src/internal/features.js'
import type {
  CodecRequestContext,
  EncodedWrite,
  ResourceCodec
} from '../../src/index.js'

/**
 * The codec seam narrowed to its single-request half. `encode` returns a
 * `CodecWrite` union: the ordinary `EncodedWrite`, or a chunked-write plan for
 * a payload too large for one request. A suite whose fixtures all write
 * payloads that fit one request narrows the codec once with this type instead
 * of discriminating the union at each assertion.
 */
export type SingleWriteCodec = Omit<ResourceCodec, 'encode'> & {
  encode(input: Parameters<ResourceCodec['encode']>[0]): Promise<EncodedWrite>
}

/**
 * A stub {@link FeatureProbe} over a fixed token list, for the tests that drive
 * an affordance gate without a server.
 *
 * @param tokens {string[]}   the feature tokens the backend advertises
 * @param [options] {object}
 * @param [options.descriptorAbsent] {boolean}   whether the probe should report
 *   that the backend descriptor could not be read at all (as opposed to one
 *   that was read and lists `tokens`)
 * @returns {FeatureProbe}
 */
export function stubFeatures(
  tokens: string[],
  { descriptorAbsent = false }: { descriptorAbsent?: boolean } = {}
): FeatureProbe {
  return featureProbeFrom(
    async () => tokens,
    async () => descriptorAbsent
  )
}

/**
 * An in-memory WAS backend for the chunked-blob tests: it answers the request
 * context a handle hands the codec, storing every `PUT` body under its path and
 * serving it back on `GET`. That is the whole surface `WasTransport` needs, so
 * a chunked write plan and a chunked read run end to end with no network.
 *
 * It also answers `DELETE` (dropping the stored body), which the chunked
 * write's failure cleanup needs.
 *
 * @param [options] {object}
 * @param [options.features] {string[]}   the backend's advertised affordances
 * @param [options.descriptorAbsent] {boolean}   whether the feature probe
 *   should report that the backend descriptor could not be read at all
 * @returns {object}   the request context, the stored bodies by path, and the
 *   ordered lists of read, written and deleted paths
 */
export function memoryBackend({
  features = ['chunked-streams', 'conditional-writes'],
  descriptorAbsent = false
}: { features?: string[]; descriptorAbsent?: boolean } = {}): {
  context: CodecRequestContext
  store: Map<string, Uint8Array>
  reads: string[]
  writes: string[]
  deletes: string[]
} {
  const store = new Map<string, Uint8Array>()
  const reads: string[] = []
  const writes: string[] = []
  const deletes: string[] = []
  const respond = (
    body: Uint8Array | undefined,
    etag?: string
  ): HttpResponse => {
    const text = body === undefined ? '' : new TextDecoder().decode(body)
    return {
      headers: {
        get: (name: string) =>
          name.toLowerCase() === 'etag' ? (etag ?? null) : null
      },
      async json() {
        return JSON.parse(text)
      },
      async text() {
        return text
      }
    } as unknown as HttpResponse
  }
  const context: CodecRequestContext = {
    features: stubFeatures(features, { descriptorAbsent }),
    async request(input) {
      const path = input.path as string
      const method = input.method ?? 'GET'
      if (method === 'PUT') {
        writes.push(path)
        store.set(path, input.body as Uint8Array)
        return respond(undefined, '"v1"')
      }
      if (method === 'DELETE') {
        deletes.push(path)
        store.delete(path)
        return respond(undefined)
      }
      reads.push(path)
      const stored = store.get(path)
      if (stored === undefined) {
        throw Object.assign(new Error(`HTTP 404 ${path}`), { status: 404 })
      }
      return respond(stored)
    }
  }
  return { context, store, reads, writes, deletes }
}
