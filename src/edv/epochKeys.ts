/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Resolves a reader's per-epoch keys from a Collection's `encryption`
 * descriptor. Given the descriptor (its `epochs` and `currentEpoch`) and the
 * reader's own key-agreement key, it reconstructs each epoch the reader is a
 * recipient of as an X25519 key pair the EDV `documentCipher` can use -- the
 * write epoch's key for writes, and one read key per epoch the reader holds (so
 * a resource written under an older epoch stays readable). The write epoch is
 * unwrapped eagerly; the other epochs' keys unwrap lazily on first decrypt
 * naming them, so a write-only handle does not pay to unwrap history it never
 * reads.
 *
 * This is the read axis: holding an epoch key lets a reader decrypt resources
 * written under it. A reader removed from a later epoch keeps the earlier epoch
 * keys and so keeps reading pre-rotation resources -- rotation is prospective,
 * never retroactive.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import {
  EncryptionError,
  EncryptOnlyCipherError,
  KeyUnwrapError
} from '../errors.js'
import { Memo } from '../internal/memo.js'
import type {
  CollectionEncryption,
  CollectionEncryptionEpoch
} from '../types.js'
import {
  didKeyResolver,
  epochKeyIdFor,
  reconstructEpochKeyPair,
  unwrapEpochSecret
} from './epochCrypto.js'
import { currentEpochOf } from './epochRoster.js'

/**
 * The reader's resolved key-epoch material for a Collection.
 */
export interface ResolvedEpochKeys {
  /**
   * the epoch id writes encrypt under and stamp (the descriptor's
   * `currentEpoch`)
   */
  writeEpoch: string
  /**
   * the key writes encrypt under. Where this reader is a recipient of
   * `writeEpoch`, its own unwrapped epoch key pair; where it is not (a reader
   * rotated off the current epoch), a public-only stand-in reconstructed from
   * the epoch id, which seals writes to the current epoch but decrypts nothing
   */
  writeKey: IKeyAgreementKey
  /**
   * every epoch key this reader can unwrap, for decrypting any epoch (the
   * `writeKey`, unwrapped eagerly, plus a lazily-unwrapped key per other epoch
   * this reader is a recipient of). A rotated-off reader's `writeKey` is not
   * among them -- it holds no secret for the current epoch
   */
  readKeys: IKeyAgreementKey[]
  /**
   * whether this reader is a recipient of `writeEpoch`. `false` marks a reader
   * rotated off the current epoch: it reads the history it is still named in,
   * and anything it writes it cannot read back
   */
  namedInWriteEpoch: boolean
}

/**
 * Resolves the reader's epoch keys from a descriptor. Returns `null` when the
 * descriptor declares no epochs (the epoch codec refuses such a descriptor
 * fail-closed before calling this). Throws {@link KeyUnwrapError} when the
 * descriptor HAS epochs but this reader can unwrap none of them (it is not a
 * recipient), so an encrypted collection is never silently read/written with
 * the wrong key.
 *
 * The write epoch is always the descriptor's current epoch, whether or not
 * this reader is a recipient of it: a reader rotated off the current epoch
 * keeps reading the epochs it is still named in, and writes through a
 * public-only stand-in for the current one rather than falling back to an
 * epoch it was rotated off of. `namedInWriteEpoch` reports which of the two it
 * is.
 *
 * @param options {object}
 * @param options.encryption {CollectionEncryption}   the Collection's descriptor
 * @param options.keyAgreementKey {IKeyAgreementKey}   the reader's own KAK; its
 *   `id` must match a recipient `kid` in an epoch for that epoch to unwrap
 * @param [options.label] {string}   names the collection in error messages
 * @returns {Promise<ResolvedEpochKeys | null>}
 */
export async function resolveEpochKeys({
  encryption,
  keyAgreementKey,
  label = '(unnamed)'
}: {
  encryption: CollectionEncryption
  keyAgreementKey: IKeyAgreementKey
  label?: string
}): Promise<ResolvedEpochKeys | null> {
  const epochs = encryption.epochs
  if (!epochs || epochs.length === 0) {
    return null
  }
  // The epochs this reader is named in (has a recipient entry keyed to its
  // `kid`), in the descriptor's canonical order. Being named IS being a
  // recipient; whether a named entry actually unwraps is confirmed eagerly for
  // the write epoch and lazily (on first decrypt) for the rest.
  const namedEpochs = epochs.filter(epoch =>
    epoch.recipients.some(
      recipient => recipient.header.kid === keyAgreementKey.id
    )
  )
  if (namedEpochs.length === 0) {
    throw new KeyUnwrapError(
      'This reader is not a recipient of any key epoch on this encrypted ' +
        "collection (none of the descriptor's recipient entries name this " +
        "reader's key-agreement key). Add this reader with addRecipient, or " +
        'supply the correct key-agreement key.'
    )
  }
  // The write epoch is the descriptor's CURRENT epoch, resolved against the
  // full roster -- never against the subset this reader is named in. Falling
  // back within the reader's own epochs would hand a reader rotated off the
  // current epoch a write key for an epoch it was rotated off OF, so every
  // document it wrote afterward would be sealed to a key each removed
  // recipient of that epoch still holds. The rotation's read axis is
  // prospective on its own terms; it must not depend on the pull axis having
  // already taken effect.
  const writeEpochEntry = currentEpochOf({
    epochs,
    currentEpoch: encryption.currentEpoch,
    label
  })
  const namedInWriteEpoch = writeEpochEntry.recipients.some(
    recipient => recipient.header.kid === keyAgreementKey.id
  )
  if (!namedInWriteEpoch) {
    // A rotated-off reader: still a recipient of older epochs (history stays
    // readable -- rotation is prospective, never retroactive), but of no key
    // for the current one. It seals writes to the current epoch's PUBLIC key,
    // reconstructed from the epoch id exactly as an encrypt-only writer does,
    // so nothing it writes reaches a rotated-out epoch and nothing it writes
    // is readable back to it.
    return {
      writeEpoch: writeEpochEntry.id,
      writeKey: await epochWriteStandIn({
        epochId: writeEpochEntry.id,
        label
      }),
      readKeys: namedEpochs.map(epoch =>
        lazyEpochKey({ epoch, keyAgreementKey })
      ),
      namedInWriteEpoch
    }
  }
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
  // resources -- never pays the ECDH + KDF + key-unwrap for archive epochs it
  // does not read.
  const readKeys: IKeyAgreementKey[] = [writeKey]
  for (const epoch of namedEpochs) {
    if (epoch.id !== writeEpochEntry.id) {
      readKeys.push(lazyEpochKey({ epoch, keyAgreementKey }))
    }
  }
  return {
    writeEpoch: writeEpochEntry.id,
    writeKey,
    readKeys,
    namedInWriteEpoch
  }
}

/**
 * The public-only write key for an epoch this client holds no secret for,
 * reconstructed from the epoch id alone. Sound because encryption in this
 * scheme needs no secret: a write seals a fresh content-encryption key to the
 * epoch's PUBLIC key, and the epoch id IS that key's did:key. Its
 * `deriveSecret` refuses with {@link EncryptOnlyCipherError}, so the key can
 * never be mistaken for one that decrypts.
 *
 * Shared by the encrypt-only build (a writer holding no key-agreement key at
 * all) and the rotated-off reader (one holding keys, but none for the current
 * epoch), so the two cannot drift.
 *
 * @param options {object}
 * @param options.epochId {string}   the epoch to seal to
 * @param options.label {string}   names the collection in error messages
 * @returns {Promise<IKeyAgreementKey>}
 */
export async function epochWriteStandIn({
  epochId,
  label
}: {
  epochId: string
  label: string
}): Promise<IKeyAgreementKey> {
  let id: string
  try {
    id = epochKeyIdFor(epochId)
    // Fail fast on a malformed epoch id: the resolver validates the fragment
    // is a well-formed X25519 public-key fingerprint, exactly what every
    // write's recipient resolution will do.
    await didKeyResolver({ id })
  } catch (err) {
    throw new EncryptionError(
      `Collection ${label} lists a malformed key-epoch id "${epochId}": it ` +
        'is not the did:key of an X25519 key-agreement key, so no write ' +
        'recipient can be reconstructed from it.',
      { cause: err }
    )
  }
  return {
    id,
    async deriveSecret(): Promise<Uint8Array> {
      throw new EncryptOnlyCipherError(
        `The cipher for collection ${label} holds no key-agreement secret ` +
          `for key epoch "${epochId}": it was built from the descriptor ` +
          'alone, or this reader was rotated off that epoch. It encrypts to ' +
          'the epoch and decrypts nothing under it.'
      )
    }
  }
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
  // The memo caches only a successful unwrap: a rejected attempt is dropped so
  // the next read re-attempts (the failure may have been transient), rather
  // than replaying the same cached rejection for the life of the handle.
  const memo = new Memo(async () => {
    const key = await unwrapEpochKey({ epoch, keyAgreementKey })
    if (!key) {
      // The reader was named in this epoch (else no lazy key was built) but its
      // entry did not unwrap: a corrupt entry. The codec's `_decrypt` catches
      // this and tries the next candidate before surfacing its own typed
      // failure.
      throw new KeyUnwrapError(
        `This reader's recipient entry for epoch "${epoch.id}" did not ` +
          'unwrap (a corrupt entry).'
      )
    }
    return key
  })
  return {
    id: epochKeyIdFor(epoch.id),
    async deriveSecret(options: { publicKey: unknown }): Promise<Uint8Array> {
      const key = await memo.get()
      return key.deriveSecret(options)
    }
  }
}
