/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Crypto-free predicates over a Collection's `encryption` descriptor: whether it
 * carries a usable key-epoch roster, and whether two descriptors name the same
 * roster. Neither touches key material, so a caller deciding what to do with a
 * descriptor -- open it, refuse it fail-closed, rebuild a cipher for it -- does
 * not have to pull in the epoch crypto to ask.
 *
 * These exist because every consumer that holds descriptors (a local replica
 * deciding whether a collection is encrypted, a sync layer deciding whether a
 * freshly-read descriptor invalidates the cipher it opened with) otherwise
 * re-derives the same two checks, and the two definitions have to agree across
 * consumers to be worth anything.
 */
import type {
  CollectionEncryption,
  CollectionEncryptionEpoch
} from '../types.js'

/**
 * Whether a descriptor carries a usable key-epoch roster: it is present, its
 * `currentEpoch` is a string, and its `epochs` list is a non-empty array. Both
 * halves matter -- a roster with no `currentEpoch` names no epoch to write
 * under, and a `currentEpoch` with no epochs names an entry that does not
 * exist -- so only a descriptor passing both is one an epoch-aware cipher can
 * be opened from.
 *
 * @param [encryption] {CollectionEncryption}   the descriptor to test
 * @returns {boolean}
 */
export function hasKeyEpochs(
  encryption?: CollectionEncryption
): encryption is CollectionEncryption & {
  currentEpoch: string
  epochs: CollectionEncryptionEpoch[]
} {
  return (
    encryption !== undefined &&
    typeof encryption.currentEpoch === 'string' &&
    Array.isArray(encryption.epochs) &&
    encryption.epochs.length > 0
  )
}

/**
 * Whether two descriptors name the same key-epoch roster: their `currentEpoch`
 * values are equal AND their `epochs` lists carry the same epoch ids in the same
 * order. An `undefined` descriptor equals only another `undefined` one, so a
 * caller holding nothing yet reads a freshly-read descriptor as a change.
 *
 * This is roster IDENTITY, not descriptor equality: the recipients wrapped
 * inside each epoch are deliberately not compared. Adding or removing a reader
 * within an existing epoch changes which recipients an epoch wraps its key to,
 * but leaves every epoch id and the write epoch alone, so the keys this reader
 * already resolved stay correct and a cipher built from the older descriptor
 * stays valid. Only a rotation -- a new epoch appended and `currentEpoch` moved
 * onto it -- changes what a reader must resolve, and that is exactly what an
 * inequality here reports.
 *
 * @param [current] {CollectionEncryption}   the descriptor in hand
 * @param [next] {CollectionEncryption}   the descriptor to compare it against
 * @returns {boolean}
 */
export function epochRostersEqual(
  current?: CollectionEncryption,
  next?: CollectionEncryption
): boolean {
  if (current === undefined || next === undefined) {
    return current === undefined && next === undefined
  }
  if (current.currentEpoch !== next.currentEpoch) {
    return false
  }
  const currentIds = (current.epochs ?? []).map(epoch => epoch.id)
  const nextIds = (next.epochs ?? []).map(epoch => epoch.id)
  return (
    currentIds.length === nextIds.length &&
    currentIds.every((id, index) => id === nextIds[index])
  )
}
