/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Resolves a reader's per-epoch keys from a Collection's `encryption` marker.
 * Given the marker (its `epochs` and `currentEpoch`) and the reader's own
 * key-agreement key, it unwraps every epoch key the reader is a recipient of and
 * reconstructs each as an X25519 key pair the EDV `documentCipher` can use --
 * the `currentEpoch` key for writes, and every unwrappable epoch key for reads
 * (so a resource written under an older epoch stays readable).
 *
 * This is the read axis: holding an epoch key lets a reader decrypt resources
 * written under it. A reader removed from a later epoch keeps the earlier epoch
 * keys and so keeps reading pre-rotation resources -- rotation is prospective,
 * never retroactive.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { KeyUnwrapError } from '../errors.js'
import type { CollectionEncryption } from '../types.js'
import { reconstructEpochKeyPair, unwrapEpochSecret } from './epochCrypto.js'

/**
 * The reader's resolved key-epoch material for a Collection.
 */
export interface ResolvedEpochKeys {
  /** the epoch id writes encrypt under and stamp (the marker's `currentEpoch`) */
  writeEpoch: string
  /** the key writes encrypt under */
  writeKey: IKeyAgreementKey
  /** every epoch key this reader can unwrap, for decrypting any epoch */
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
  const byEpochId = new Map<string, IKeyAgreementKey>()
  const readKeys: IKeyAgreementKey[] = []
  for (const epoch of epochs) {
    const entry = epoch.recipients.find(
      recipient => recipient.header.kid === keyAgreementKey.id
    )
    if (!entry) {
      continue
    }
    const secret = await unwrapEpochSecret({ entry, keyAgreementKey })
    if (!secret) {
      // A recipient entry named this reader but did not unwrap: a corrupt entry
      // (never a valid key), so skip it rather than treating null as a key.
      continue
    }
    const keyPair = reconstructEpochKeyPair({ epochId: epoch.id, secret })
    byEpochId.set(epoch.id, keyPair)
    readKeys.push(keyPair)
  }
  if (readKeys.length === 0) {
    throw new KeyUnwrapError(
      'This reader is not a recipient of any key epoch on this encrypted ' +
        "collection (none of the marker's recipient entries unwrap with this " +
        "reader's key-agreement key). Add this reader with addRecipient, or " +
        'supply the correct key-agreement key.'
    )
  }
  // Write under `currentEpoch` when this reader holds it; otherwise fall back to
  // the newest epoch it can unwrap (a removed reader that can still read history
  // but should not be writing -- the server also blocks its writes via the
  // revoked zcap).
  const currentEpoch = encryption.currentEpoch
  const writeKey: IKeyAgreementKey =
    (currentEpoch !== undefined && byEpochId.get(currentEpoch)) ||
    readKeys[readKeys.length - 1]!
  const writeEpoch =
    currentEpoch !== undefined && byEpochId.has(currentEpoch)
      ? currentEpoch
      : epochIdOf(writeKey, byEpochId)
  return { writeEpoch, writeKey, readKeys }
}

/**
 * Finds the epoch id a resolved read key belongs to (reverse lookup in the
 * epoch map), for the write-epoch fallback.
 *
 * @param key {IKeyAgreementKey}
 * @param byEpochId {Map<string, IKeyAgreementKey>}
 * @returns {string}
 */
function epochIdOf(
  key: IKeyAgreementKey,
  byEpochId: Map<string, IKeyAgreementKey>
): string {
  for (const [epochId, candidate] of byEpochId) {
    if (candidate === key) {
      return epochId
    }
  }
  // Unreachable: `key` is always one of the map's values.
  return key.id
}
