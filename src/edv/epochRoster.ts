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
import { EncryptionError } from '../errors.js'
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

/**
 * Picks the current epoch out of a roster: the entry named by `currentEpoch`
 * when the list holds it, otherwise the LAST entry in the list's canonical
 * order.
 *
 * The fallback is defined against the list's own order rather than against the
 * incidental order in which secrets happened to unwrap, so the choice is
 * deterministic for every caller, instead of assuming the list is
 * append-ordered newest-last.
 *
 * This is the tolerant form, for callers holding the full roster during a
 * rotation, where `currentEpoch` naming an unlisted entry is not yet
 * actionable. A caller choosing the epoch to SEAL PLAINTEXT UNDER wants
 * {@link currentEpochOf} instead, which refuses that case rather than
 * selecting another entry.
 *
 * The list must be non-empty -- every caller has already established that it
 * holds at least one epoch, so an empty list is a programming error rather than
 * a state this can report on.
 *
 * @param epochs {CollectionEncryptionEpoch[]}   the non-empty list to pick from
 * @param [currentEpoch] {string}   the descriptor's declared write epoch
 * @returns {CollectionEncryptionEpoch}
 */
export function pickEpoch(
  epochs: CollectionEncryptionEpoch[],
  currentEpoch?: string
): CollectionEncryptionEpoch {
  return epochs.find(epoch => epoch.id === currentEpoch) ?? epochs.at(-1)!
}

/**
 * The epoch a descriptor seals new writes under: the entry `currentEpoch`
 * names, or the last listed entry when the descriptor declares none (the
 * roster is append-only, so the last entry is the newest).
 *
 * Always resolved against the FULL roster, never against the subset of epochs
 * one reader is named in, and fails closed when `currentEpoch` names an entry
 * the roster does not list. Both rules exist for the same reason: selecting
 * any other entry would seal new plaintext under a rotated-out epoch, whose
 * key every removed recipient of that epoch still holds. A descriptor whose
 * `currentEpoch` is unlisted violates the descriptor invariant -- it is stale,
 * partially synced, or tampered with -- and re-reading it is the only sound
 * recovery.
 *
 * @param options {object}
 * @param options.epochs {CollectionEncryptionEpoch[]}   the non-empty roster
 * @param [options.currentEpoch] {string}   the descriptor's declared write epoch
 * @param options.label {string}   names the collection in the error message
 * @returns {CollectionEncryptionEpoch}
 */
export function currentEpochOf({
  epochs,
  currentEpoch,
  label
}: {
  epochs: CollectionEncryptionEpoch[]
  currentEpoch?: string
  label: string
}): CollectionEncryptionEpoch {
  if (currentEpoch === undefined) {
    return epochs.at(-1)!
  }
  const entry = epochs.find(epoch => epoch.id === currentEpoch)
  if (entry === undefined) {
    throw new EncryptionError(
      `Collection ${label} declares currentEpoch "${currentEpoch}" but its ` +
        'epoch roster does not list it. A descriptor names its current ' +
        'epoch among the epochs it lists; re-read the descriptor before ' +
        'writing.'
    )
  }
  return entry
}
