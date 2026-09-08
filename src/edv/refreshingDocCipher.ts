/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A self-refreshing EDV document cipher: `createEdvDocCipher` bound to
 * descriptor acquisition and the once-per-session refresh rule, for a host
 * whose decrypt seam is the cipher itself (a sync engine's `decryptDoc`, a
 * conflict resolver) rather than a row-scanning store.
 *
 * Built, the cipher acquires the collection's descriptor (fetch, cache the
 * success, cached fallback whenever the fetch yields none -- see
 * `acquire.ts`) and constructs the underlying EDV cipher from it; with no
 * descriptor, or a descriptor with no epochs, the build refuses fail-closed
 * (every encrypted collection's descriptor carries an epoch roster from
 * provisioning, so the absence can only mean the install has not landed or
 * the host is lying). When a decrypt throws
 * `UnknownEpochError`, the cipher re-acquires the descriptor, rebuilds itself,
 * and retries that decrypt exactly once -- and only once per cipher instance,
 * which the host scopes to one `(profile, collection)` session by dropping
 * its cipher cache when the session ends. A second failure (or any unknown
 * epoch after the one refresh is spent) propagates. A refresh that itself
 * fails does not count as spent -- the original `UnknownEpochError` is
 * rethrown and a later decrypt may try again.
 *
 * Only `UnknownEpochError` drives that refresh, and by design. The client
 * splits the two ways a decrypt can find no key: an epoch the descriptor does
 * not list at all raises `UnknownEpochError`, because a fresher descriptor may
 * well list it; an epoch the descriptor does list but this reader holds no key
 * for raises `KeyUnwrapError` (never a recipient, or removed and the epoch
 * rotated). The second is rethrown immediately, with the refresh left
 * untouched, since re-reading the same descriptor cannot produce a key the
 * reader was not given.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { UnknownEpochError } from '../errors.js'
import { createEdvDocCipher, type DocCipher } from './docCipher.js'
import {
  acquireDescriptor,
  type EncryptionDescriptorCache,
  type EncryptionDescriptorSource
} from './acquire.js'

/**
 * Builds a {@link DocCipher} whose descriptor is acquired through the
 * source/cache seams and refreshed (once per instance) on an unknown-epoch
 * decrypt.
 *
 * With no `source` the descriptor is served from the cache alone and the
 * refresh path is inert (an unknown-epoch decrypt propagates immediately) --
 * the shape for a purely local code path that must never touch the network.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault key pair this
 *   collection's envelopes are sealed to
 * @param options.keyResolver {IKeyResolver}
 * @param options.collectionId {string}
 * @param [options.idDerivation] {'content' | 'random'}   defaults to
 *   `'content'`
 * @param [options.source] {EncryptionDescriptorSource}
 * @param options.cache {EncryptionDescriptorCache}
 * @param [options.onFetchError] {function}   observes swallowed
 *   descriptor-fetch failures
 * @returns {Promise<DocCipher>}
 */
export async function createRefreshingEdvDocCipher({
  keyAgreementKey,
  keyResolver,
  collectionId,
  idDerivation,
  source,
  cache,
  onFetchError
}: {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  collectionId: string
  idDerivation?: 'content' | 'random'
  source?: EncryptionDescriptorSource
  cache: EncryptionDescriptorCache
  onFetchError?: (err: unknown, info: { collectionId: string }) => void
}): Promise<DocCipher> {
  const build = async (): Promise<DocCipher> => {
    const encryption = await acquireDescriptor({
      source,
      cache,
      collectionId,
      onFetchError
    })
    if (!encryption) {
      throw new Error(
        `Collection "${collectionId}" has no encryption descriptor available ` +
          '(fetched or cached). Every encrypted collection carries its key ' +
          'epochs from provisioning; refusing to build a cipher without them.'
      )
    }
    return createEdvDocCipher({
      keyAgreementKey,
      keyResolver,
      collectionId,
      idDerivation,
      encryption
    })
  }

  let inner = await build()
  // The one descriptor refresh this cipher instance (= this collection this
  // session) may spend, shared so concurrent unknown-epoch decrypts ride a
  // single re-read instead of each spending one.
  let refreshed: Promise<void> | null = null

  return {
    encrypt: options => inner.encrypt(options),

    encryptUpdate: options => {
      if (!inner.encryptUpdate) {
        throw new Error(
          `Collection "${collectionId}" cipher has no in-place update.`
        )
      }
      return inner.encryptUpdate(options)
    },

    async decrypt({ envelope }) {
      try {
        return await inner.decrypt({ envelope })
      } catch (err) {
        // `instanceof` is safe here and only here: `inner` is built in this
        // package by `createEdvDocCipher`, which raises this package's own
        // class, so no injected seam is crossed. A caller classifying what
        // THIS cipher throws is crossing one, and uses `isUnknownEpochError` /
        // `isKeyUnwrapError` instead.
        if (!(err instanceof UnknownEpochError) || !source) {
          throw err
        }
        if (!refreshed) {
          const attempt = build().then(cipher => {
            inner = cipher
          })
          refreshed = attempt
          // Only a COMPLETED refresh is spent. A rejected one (the description
          // could not be read and no cached copy answered either) un-arms the
          // guard so a later unknown-epoch decrypt may try again; a successful
          // refresh that still cannot route the envelope stays spent for the
          // session, which is what keeps a genuinely foreign envelope from
          // driving a refetch loop.
          attempt.catch(() => {
            if (refreshed === attempt) {
              refreshed = null
            }
          })
        }
        try {
          await refreshed
        } catch {
          // The refresh failed, so nothing was learned about this envelope's
          // epoch: surface the original UnknownEpochError rather than the
          // build failure, so callers classifying on it (the create-loss
          // re-mint) still see the row they exist to repair.
          throw err
        }
        // One retry under the swapped cipher. If the refresh was already
        // spent before this decrypt began, this re-attempt is a local
        // no-network decrypt that fails the same way -- so a genuinely
        // foreign envelope still surfaces UnknownEpochError, and never a
        // second description read.
        return inner.decrypt({ envelope })
      }
    }
  }
}
