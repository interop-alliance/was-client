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
import { Memo } from './memo.js'
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
 * The read side of a backend-feature probe, so a consumer can be handed an
 * already-memoized probe instead of building its own (and repeating the
 * descriptor round trip). {@link BackendFeatures} is the implementation;
 * {@link featureProbeFrom} adapts a bare "resolve the feature tokens" thunk --
 * the shape a handle shares with its children -- to the same interface.
 */
export interface FeatureProbe {
  get(): Promise<string[]>
  has(feature: string): Promise<boolean>
  /**
   * Whether the probe's answer came from a backend descriptor that could not be
   * read at all (`404` / `405` / `501`) rather than from one that was read and
   * advertises a feature set. Both answer "no features", but only the second is
   * evidence about the server's capabilities: the first also covers a deleted
   * collection and a capability that cannot read the descriptor (WAS masks
   * unauthorized reads as 404). An affordance gate consults it so its error
   * names the right cause.
   *
   * @returns {Promise<boolean>}
   */
  descriptorAbsent(): Promise<boolean>
}

/**
 * Adapts a resolve-the-feature-tokens thunk (a handle's shared, memoized probe)
 * to the {@link FeatureProbe} interface, so a consumer that only needs to ask
 * `has(...)` can be driven by someone else's memo.
 *
 * @param get {function}   resolves the backend's advertised feature tokens
 * @param [descriptorAbsent] {function}   resolves whether the descriptor was
 *   unreadable; a bare thunk carries no such signal, so it defaults to `false`
 *   ("a descriptor was read, and it advertises these tokens")
 * @returns {FeatureProbe}
 */
export function featureProbeFrom(
  get: () => Promise<string[]>,
  descriptorAbsent: () => Promise<boolean> = async () => false
): FeatureProbe {
  return {
    get,
    async has(feature: string): Promise<boolean> {
      return (await get()).includes(feature)
    },
    descriptorAbsent
  }
}

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
export class BackendFeatures implements FeatureProbe {
  readonly #memo: Memo<string[]>
  /**
   * Set when the probe's definitive answer was "the descriptor could not be
   * read" rather than "the descriptor lists these features", so a gate can tell
   * a server that lacks an affordance from one whose descriptor is absent (or
   * whose collection is gone, or unreadable with this capability).
   */
  #descriptorAbsent = false
  readonly #readDescriptor: () => Promise<unknown>

  /**
   * @param readDescriptor {function}   reads and parses the backend descriptor
   *   JSON (`GET .../backend`); expected to throw an error carrying an HTTP
   *   status (readable via `httpStatus`) on failure
   */
  constructor(readDescriptor: () => Promise<unknown>) {
    this.#readDescriptor = readDescriptor
    this.#memo = new Memo(() => this.#probe())
  }

  /**
   * The feature tokens the backend advertises, probed once and cached on a
   * definitive answer.
   *
   * @returns {Promise<string[]>}
   */
  get(): Promise<string[]> {
    return this.#memo.get()
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
   * Whether the (definitive) answer came from an unreadable backend descriptor
   * rather than from one that was read. Awaits the probe, so it reports the
   * same answer `get()` resolved.
   *
   * @returns {Promise<boolean>}
   */
  async descriptorAbsent(): Promise<boolean> {
    await this.get()
    return this.#descriptorAbsent
  }

  /**
   * Reads and parses the backend descriptor once. On a definitive answer
   * (success, or a `404` / `405` / `501` that means the endpoint is
   * legitimately absent) resolves the feature list, which the memo then
   * caches. On a transient failure it rethrows, which drops the memo so the
   * next call re-probes.
   *
   * @returns {Promise<string[]>}
   */
  async #probe(): Promise<string[]> {
    try {
      const descriptor = (await this.#readDescriptor()) as {
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
        this.#descriptorAbsent = true
        return []
      }
      // Transient/ambiguous: rethrow, which the memo reads as "do not cache
      // this" -- it drops the rejected promise so the next call re-probes.
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
