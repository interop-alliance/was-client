/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared backend-feature probe: reads a collection backend's "Collection
 * Backend Selected" descriptor once and answers which optional affordance
 * tokens it advertises (e.g. `conditional-writes`, `blinded-index-query`,
 * `chunked-streams`). Both EDV write paths -- the standalone `WasTransport`
 * and the codec-seam write orchestration -- consult this one helper, so the
 * backend-capability decision is made in a single place instead of being
 * probed in one path and assumed away in the other.
 */
import { httpStatus } from '../errors.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { readJsonData } from './content.js'
import { collectionBackend } from './paths.js'
import type { IZcap } from '../types.js'

/**
 * HTTP statuses that mean the backend-descriptor endpoint is legitimately
 * absent (or explicitly unimplemented), as opposed to transiently failing:
 * `404` (no such endpoint), `405` (endpoint does not answer `GET`), `501`
 * (not implemented). These are a definitive "this server advertises no
 * backend features" answer and are safe to cache -- every affordance gate
 * then falls closed against a server that has no backend descriptors. Any
 * other failure (network error, timeout, `401`, `429`, other `5xx`) is
 * transient/ambiguous and is re-probed instead of cached.
 */
const DESCRIPTOR_ABSENT_STATUSES = new Set([404, 405, 501])

/**
 * A memoizing probe of one collection backend's advertised feature tokens.
 * Memoized once it produces a definitive answer: a successful read (including
 * one that lists no features) and a definitive "endpoint absent"
 * (`404` / `405` / `501`) both resolve to a cached feature list, so every
 * affordance gate falls closed against a server that has no backend
 * descriptors.
 *
 * A transient/ambiguous failure (network error, timeout, `401`, `429`, other
 * `5xx`) is NOT cached: the memo is cleared so the next call re-probes, and
 * the error is rethrown so the caller fails loud rather than silently
 * degrading against a server that may well be capable. (A single transient
 * failure must not poison the probe for its lifetime.)
 */
export class BackendFeatures {
  private _promise?: Promise<string[]>
  private readonly _readDescriptor: () => Promise<unknown>

  /**
   * @param readDescriptor {function}   reads and parses the backend descriptor
   *   JSON (`GET .../backend`); expected to throw an error carrying an HTTP
   *   status (readable via `httpStatus`) on failure
   */
  constructor(readDescriptor: () => Promise<unknown>) {
    this._readDescriptor = readDescriptor
  }

  /**
   * The feature tokens the backend advertises, probed once and cached on a
   * definitive answer.
   *
   * @returns {Promise<string[]>}
   */
  get(): Promise<string[]> {
    this._promise ??= this._probe()
    return this._promise
  }

  /**
   * Whether the backend advertises the given feature token.
   *
   * @param feature {string}   the affordance token (e.g. `conditional-writes`)
   * @returns {Promise<boolean>}
   */
  async has(feature: string): Promise<boolean> {
    return (await this.get()).includes(feature)
  }

  /**
   * Reads and parses the backend descriptor once. On a definitive answer
   * (success, or a `404` / `405` / `501` that means the endpoint is
   * legitimately absent) resolves the feature list, which `get` then caches.
   * On a transient failure, clears the memo (so the next call re-probes) and
   * rethrows.
   *
   * @returns {Promise<string[]>}
   */
  private async _probe(): Promise<string[]> {
    try {
      const descriptor = (await this._readDescriptor()) as {
        features?: unknown
      } | null
      return Array.isArray(descriptor?.features)
        ? descriptor.features.filter(
            (feature): feature is string => typeof feature === 'string'
          )
        : []
    } catch (err) {
      const status = httpStatus(err)
      if (status !== undefined && DESCRIPTOR_ABSENT_STATUSES.has(status)) {
        return []
      }
      // Transient/ambiguous: do not cache this failure -- drop the memo so the
      // next call re-probes -- and rethrow.
      this._promise = undefined
      throw err
    }
  }
}

/**
 * Builds the {@link BackendFeatures} probe for a collection, reading its
 * backend descriptor with a signed `GET` through the shared request layer --
 * the probe the core handles (Collection/Resource) hold, mirroring the one
 * `WasTransport` builds over its own requester. A descriptor that is not
 * readable with the bound capability surfaces as a 404 (WAS masks unauthorized
 * reads), which the probe treats as "no features advertised" -- so every
 * affordance gate falls closed for a capability that cannot read the
 * descriptor.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param [options.capability] {IZcap}   capability attached to the probe
 * @returns {BackendFeatures}
 */
export function collectionBackendFeatures(
  context: ClientContext,
  {
    spaceId,
    collectionId,
    capability
  }: { spaceId: string; collectionId: string; capability?: IZcap }
): BackendFeatures {
  return new BackendFeatures(async () => {
    const response = await send(context, {
      path: collectionBackend(spaceId, collectionId),
      method: 'GET',
      capability
    })
    // Without the `read` flag `send` never resolves `null` (a 404 throws and
    // the probe maps it to "absent"), so this null-guard is for the type only.
    return response === null ? null : readJsonData(response)
  })
}
