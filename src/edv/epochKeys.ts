/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Resolves a reader's per-epoch keys from a Collection's `encryption` marker.
 * Given the marker (its `epochs` and `currentEpoch`) and the reader's own
 * key-agreement key, it reconstructs each epoch the reader is a recipient of as
 * an X25519 key pair the EDV `documentCipher` can use -- the write epoch's key
 * for writes, and one read key per epoch the reader holds (so a resource written
 * under an older epoch stays readable). The write epoch is unwrapped eagerly;
 * the other epochs' keys unwrap lazily on first decrypt naming them, so a
 * write-only handle does not pay to unwrap history it never reads.
 *
 * This is the read axis: holding an epoch key lets a reader decrypt resources
 * written under it. A reader removed from a later epoch keeps the earlier epoch
 * keys and so keeps reading pre-rotation resources -- rotation is prospective,
 * never retroactive.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { KeyUnwrapError } from '../errors.js'
import type {
  CollectionEncryption,
  CollectionEncryptionEpoch
} from '../types.js'
import {
  epochKeyIdFor,
  reconstructEpochKeyPair,
  unwrapEpochSecret
} from './epochCrypto.js'

/**
 * The reader's resolved key-epoch material for a Collection.
 */
export interface ResolvedEpochKeys {
  /**
   * the epoch id writes encrypt under and stamp (the marker's `currentEpoch`)
   */
  writeEpoch: string
  /**
   * the key writes encrypt under
   */
  writeKey: IKeyAgreementKey
  /**
   * every epoch key this reader can unwrap, for decrypting any epoch (the
   * `writeKey`, unwrapped eagerly, plus a lazily-unwrapped key per other epoch
   * this reader is a recipient of)
   */
  readKeys: IKeyAgreementKey[]
}

/**
 * Resolves the reader's epoch keys from a marker. Returns `null` when the marker
 * declares no epochs (a single-key collection -- the caller keeps its existing
 * single-key path). Throws {@link KeyUnwrapError} when the marker HAS epochs but
 * this reader can unwrap none of them (it is not a recipient), so an encrypted
 * collection is never silently read/written with the wrong key.
 *
 * @param options {object}
 * @param options.encryption {CollectionEncryption}   the Collection's marker
 * @param options.keyAgreementKey {IKeyAgreementKey}   the reader's own KAK; its
 *   `id` must match a recipient `kid` in an epoch for that epoch to unwrap
 * @returns {Promise<ResolvedEpochKeys | null>}
 */
export async function resolveEpochKeys({
  encryption,
  keyAgreementKey
}: {
  encryption: CollectionEncryption
  keyAgreementKey: IKeyAgreementKey
}): Promise<ResolvedEpochKeys | null> {
  const epochs = encryption.epochs
  if (!epochs || epochs.length === 0) {
    return null
  }
  // The epochs this reader is named in (has a recipient entry keyed to its
  // `kid`), in the marker's canonical order. Being named IS being a recipient;
  // whether a named entry actually unwraps is confirmed eagerly for the write
  // epoch and lazily (on first decrypt) for the rest.
  const namedEpochs = epochs.filter(epoch =>
    epoch.recipients.some(
      recipient => recipient.header.kid === keyAgreementKey.id
    )
  )
  if (namedEpochs.length === 0) {
    throw new KeyUnwrapError(
      'This reader is not a recipient of any key epoch on this encrypted ' +
        "collection (none of the marker's recipient entries name this " +
        "reader's key-agreement key). Add this reader with addRecipient, or " +
        'supply the correct key-agreement key.'
    )
  }
  // Choose the write epoch: `currentEpoch` when this reader holds it, otherwise
  // the newest epoch it holds -- defined deterministically as the LAST epoch in
  // the marker's canonical `epochs` order that names this reader, never the
  // incidental order in which secrets happened to unwrap. A reader that is not a
  // recipient of `currentEpoch` is a removed/historical reader whose writes the
  // server rejects via its revoked zcap anyway; selecting a deterministic
  // fallback here only keeps the local `writeEpoch`/`writeKey` well-defined
  // instead of assuming the `epochs` array is append-ordered newest-last.
  const currentEpoch = encryption.currentEpoch
  const writeEpochEntry =
    (currentEpoch !== undefined &&
      namedEpochs.find(epoch => epoch.id === currentEpoch)) ||
    namedEpochs[namedEpochs.length - 1]!
  // The write epoch is unwrapped eagerly: `writeKey` must be a full key pair the
  // EDV cipher can name recipients with and encrypt under right away.
  const writeKey = await unwrapEpochKey({
    epoch: writeEpochEntry,
    keyAgreementKey
  })
  if (!writeKey) {
    throw new KeyUnwrapError(
      `This reader's recipient entry for the write epoch ` +
        `"${writeEpochEntry.id}" did not unwrap (a corrupt entry). Re-add ` +
        'this reader with addRecipient, or supply the correct key-agreement ' +
        'key.'
    )
  }
  // Read keys: the eagerly-unwrapped write key, plus a LAZY key per other named
  // epoch. Each lazy key knows its `id` up front (derived from the epoch id, so
  // the codec's kid-match filter needs no secret) and unwraps + reconstructs its
  // epoch secret only on first decrypt naming it, caching the result. So a
  // write-only handle -- or a reader that only ever touches current-epoch
  // resources -- never pays the ECDH + KDF + key-unwrap for historical epochs it
  // does not read.
  const readKeys: IKeyAgreementKey[] = [writeKey]
  for (const epoch of namedEpochs) {
    if (epoch.id !== writeEpochEntry.id) {
      readKeys.push(lazyEpochKey({ epoch, keyAgreementKey }))
    }
  }
  return { writeEpoch: writeEpochEntry.id, writeKey, readKeys }
}

/**
 * Unwraps and reconstructs a single epoch's key pair for this reader, or returns
 * `null` when the reader is not a recipient of the epoch or its entry does not
 * unwrap (a corrupt entry -- never treat `null` as a key).
 *
 * @param options {object}
 * @param options.epoch {CollectionEncryptionEpoch}   the epoch to unwrap
 * @param options.keyAgreementKey {IKeyAgreementKey}   the reader's own KAK
 * @returns {Promise<IKeyAgreementKey | null>}
 */
async function unwrapEpochKey({
  epoch,
  keyAgreementKey
}: {
  epoch: CollectionEncryptionEpoch
  keyAgreementKey: IKeyAgreementKey
}): Promise<IKeyAgreementKey | null> {
  const entry = epoch.recipients.find(
    recipient => recipient.header.kid === keyAgreementKey.id
  )
  if (!entry) {
    return null
  }
  const secret = await unwrapEpochSecret({ entry, keyAgreementKey })
  if (!secret) {
    return null
  }
  return reconstructEpochKeyPair({ epochId: epoch.id, secret })
}

/**
 * Builds a lazily-unwrapping read key for a named epoch: an `IKeyAgreementKey`
 * whose `id` is known up front (the epoch key's verification-method id, derived
 * from the epoch id -- the `kid` a resource written under this epoch stamps), so
 * the codec can kid-match it before any secret is derived, and whose
 * `deriveSecret` unwraps + reconstructs the real epoch key pair on first call
 * and caches it. This defers the ECDH + KDF + key-unwrap cost until (and unless)
 * a resource named for this epoch is actually decrypted.
 *
 * @param options {object}
 * @param options.epoch {CollectionEncryptionEpoch}   the epoch this key reads
 * @param options.keyAgreementKey {IKeyAgreementKey}   the reader's own KAK
 * @returns {IKeyAgreementKey}
 */
function lazyEpochKey({
  epoch,
  keyAgreementKey
}: {
  epoch: CollectionEncryptionEpoch
  keyAgreementKey: IKeyAgreementKey
}): IKeyAgreementKey {
  let pending: Promise<IKeyAgreementKey> | undefined
  const resolve = (): Promise<IKeyAgreementKey> => {
    if (pending === undefined) {
      pending = unwrapEpochKey({ epoch, keyAgreementKey }).then(key => {
        if (!key) {
          // The reader was named in this epoch (else no lazy key was built) but
          // its entry did not unwrap: a corrupt entry. The codec's `_decrypt`
          // catches this and tries the next candidate before surfacing its own
          // typed failure.
          throw new KeyUnwrapError(
            `This reader's recipient entry for epoch "${epoch.id}" did not ` +
              'unwrap (a corrupt entry).'
          )
        }
        return key
      })
    }
    return pending
  }
  return {
    id: epochKeyIdFor(epoch.id),
    async deriveSecret(options: { publicKey: unknown }): Promise<Uint8Array> {
      const key = await resolve()
      return key.deriveSecret(options)
    }
  }
}
