/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Recipient and key-epoch management for multi-recipient encrypted Collections:
 * initializing the first epoch, adding a reader (escrow -- history included),
 * and removing a reader (the full revoke-and-rotate procedure). Each operation
 * mutates a `CollectionEncryption` descriptor through the descriptor-store seam
 * (see `descriptorStore.ts`) -- the Collection Description's `encryption`
 * member for the `collection` sugar, or any explicit `store`, such as a
 * descriptor hosted as a plain JSON Resource -- and writes it back with a
 * compare-and-swap (`If-Match`), retrying on a concurrent change so two racing
 * recipient edits cannot clobber one another.
 *
 * The two axes stay separate and are both required to actually remove a reader:
 *
 * - **pull** -- the reader's server-side access. For a Collection this is the
 *   zcap the server checks at request time: revoking it stops the server
 *   serving that reader ciphertext. Immediate and total. A descriptor whose pull
 *   axis lives elsewhere (e.g. a DID document naming the readers) supplies a
 *   `pull` action instead of the default zcap revocation.
 * - **read** -- possession of an epoch key. Rotating the epoch means resources
 *   written afterward are encrypted under a key the removed reader does not
 *   hold. Prospective only.
 *
 * Important: Rotation protects post-rotation writes only. It never claws
 * back data a reader already downloaded, and a removed reader keeps every
 * earlier epoch's key, so any pre-rotation resource whose ciphertext it obtains
 * stays readable to it. {@link removeRecipient} does both halves so a caller
 * cannot accidentally do one; callers who truly want half can call
 * `space.revoke()` or nothing, respectively, themselves.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { Collection } from '../Collection.js'
import type { Space } from '../Space.js'
import { PreconditionFailedError, ValidationError } from '../errors.js'
import { collectionDescriptorStore } from './descriptorStore.js'
import type { EncryptionDescriptorStore } from './descriptorStore.js'
import type {
  CollectionEncryption,
  CollectionEncryptionEpoch,
  IDelegatedZcap
} from '../types.js'
import {
  didKeyResolver,
  mintEpoch,
  unwrapEpochSecret,
  wrapEpochSecret
} from './epochCrypto.js'
import { computeEpochsMac, epochsSigPayload } from './epochMac.js'
import type { EpochsSigner } from './epochMac.js'
import type { RecipientPublicKey } from './epochCrypto.js'

export type { RecipientPublicKey } from './epochCrypto.js'

/**
 * The caller's own key material, used to unwrap existing epoch keys so they can
 * be re-wrapped to a newly added reader (escrow).
 */
export interface OwnerKey {
  keyAgreementKey: IKeyAgreementKey
}

/**
 * How many times a recipient CAS write retries a stale (`412`) description
 * before surfacing {@link PreconditionFailedError}.
 */
const MAX_CAS_ATTEMPTS = 3

/**
 * Stamps the epoch-configuration authenticators onto a descriptor about to be
 * written: the `epochsMac` under the current epoch's secret always, and the
 * detached `epochsSig` when the caller supplied a signer. Without a signer any
 * prior `epochsSig` is dropped rather than carried forward -- the epoch
 * configuration just changed, so a stale signature over the old configuration
 * would only ever fail verification.
 *
 * @param options {object}
 * @param options.descriptor {CollectionEncryption}   the exact descriptor
 *   state being written (epochs / currentEpoch already updated)
 * @param options.epochSecret {Uint8Array}   the current epoch's 32-byte secret
 * @param [options.signEpochs] {EpochsSigner}   the caller's epoch-config signer
 * @returns {Promise<CollectionEncryption>}   the descriptor with `epochsMac`
 *   (and `epochsSig`, when signed) stamped
 */
async function stampEpochsAuth({
  descriptor,
  epochSecret,
  signEpochs
}: {
  descriptor: CollectionEncryption
  epochSecret: Uint8Array
  signEpochs?: EpochsSigner
}): Promise<CollectionEncryption> {
  const epochsMac = await computeEpochsMac({ descriptor, epochSecret })
  const stamped: CollectionEncryption = { ...descriptor, epochsMac }
  if (signEpochs) {
    stamped.epochsSig = await signEpochs({
      payload: epochsSigPayload(stamped)
    })
  } else {
    delete stamped.epochsSig
  }
  return stamped
}

/**
 * Escrows a recipient into every epoch it is not already a recipient of: for
 * each such epoch the caller unwraps the epoch key with its own key-agreement
 * key and re-wraps it to the incoming reader. Shared by {@link addRecipient}
 * (whose whole job this is) and {@link replaceRecipient} (which does it in the
 * same write as its rotation), so the two cannot drift.
 *
 * Each epoch's unwrap + re-wrap is independent of the others', so they run
 * concurrently (order-preserving), like `initRecipients` and `removeRecipient`
 * wrap their recipients.
 *
 * @param options {object}
 * @param options.epochs {CollectionEncryptionEpoch[]}   the descriptor's epochs
 * @param options.recipient {RecipientPublicKey}   the reader being escrowed
 * @param options.owner {OwnerKey}   the caller's own key-agreement key, to
 *   unwrap each epoch key for re-wrapping
 * @param options.operation {string}   the calling operation's name, as the error
 *   messages name it (`addRecipient` / `replaceRecipient`)
 * @param options.reader {string}   how those messages name the incoming reader
 *   (`new` / `incoming`)
 * @returns {Promise<{ epochs: CollectionEncryptionEpoch[], changed: boolean }>}
 *   the epochs with the escrow wraps applied, and whether any epoch changed
 */
async function escrowIntoEpochs({
  epochs,
  recipient,
  owner,
  operation,
  reader
}: {
  epochs: CollectionEncryptionEpoch[]
  recipient: RecipientPublicKey
  owner: OwnerKey
  operation: string
  reader: string
}): Promise<{ epochs: CollectionEncryptionEpoch[]; changed: boolean }> {
  let changed = false
  const escrowed = await Promise.all(
    epochs.map(async (epoch): Promise<CollectionEncryptionEpoch> => {
      // Already a recipient of this epoch? Leave it untouched (idempotent).
      if (epoch.recipients.some(entry => entry.header.kid === recipient.id)) {
        return epoch
      }
      const ownEntry = epoch.recipients.find(
        entry => entry.header.kid === owner.keyAgreementKey.id
      )
      if (!ownEntry) {
        throw new ValidationError(
          `Cannot ${operation}: the caller is not a recipient of epoch ` +
            `"${epoch.id}", so it cannot unwrap that epoch key to escrow it ` +
            `to the ${reader} reader.`
        )
      }
      const epochSecret = await unwrapEpochSecret({
        entry: ownEntry,
        keyAgreementKey: owner.keyAgreementKey
      })
      if (!epochSecret) {
        throw new ValidationError(
          `Cannot ${operation}: unwrapping epoch "${epoch.id}" with the ` +
            "caller's key-agreement key failed."
        )
      }
      changed = true
      return {
        ...epoch,
        recipients: [
          ...epoch.recipients,
          await wrapEpochSecret({ epochSecret, recipient })
        ]
      }
    })
  )
  return { epochs: escrowed, changed }
}

/**
 * Wraps a freshly minted epoch key to each remaining recipient kid, building the
 * epoch to append. The resolver may signal drop-this-kid by resolving `null`
 * (e.g. a roster entry whose key material is no longer resolvable), so the
 * rotation excludes that entry instead of throwing; the caller applies its own
 * rule to an epoch that ends up with no recipients at all.
 *
 * @param options {object}
 * @param options.epochId {string}   the fresh epoch's id (its `did:key`)
 * @param options.secret {Uint8Array}   the fresh epoch's 32-byte secret
 * @param options.remaining {Set<string>}   the surviving recipients' kids
 * @param options.resolveRecipientKey {function}   resolves a kid to its public
 *   key-agreement key, or `null` to drop it
 * @returns {Promise<CollectionEncryptionEpoch>}   the fresh epoch
 */
async function rotateEpoch({
  epochId,
  secret,
  remaining,
  resolveRecipientKey
}: {
  epochId: string
  secret: Uint8Array
  remaining: Set<string>
  resolveRecipientKey: (kid: string) => Promise<RecipientPublicKey | null>
}): Promise<CollectionEncryptionEpoch> {
  const wrapped = await Promise.all(
    [...remaining].map(async kid => {
      const recipient = await resolveRecipientKey(kid)
      return recipient === null
        ? null
        : wrapEpochSecret({ epochSecret: secret, recipient })
    })
  )
  return { id: epochId, recipients: wrapped.filter(entry => entry !== null) }
}

/**
 * Initializes the first key epoch on a descriptor that has no epochs yet: mints
 * a fresh epoch key, wraps it to each initial recipient, and writes `epochs:
 * [epoch]` / `currentEpoch` back with a compare-and-swap. After this, resources
 * written by any recipient are encrypted under the epoch, and readers unwrap it
 * with their own key-agreement key.
 *
 * On the `collection` host the collection must already be declared encrypted
 * (its descriptor exists; this fills in the first epochs). On a store whose
 * descriptor host starts absent (e.g. `resourceDescriptorStore`, whose roster
 * resource does not exist before the first init), the descriptor itself is
 * created from scratch with a create-if-absent guard (`If-None-Match: *`), so
 * two racing first inits cannot clobber one another.
 *
 * @param options {object}
 * @param [options.collection] {Collection}   the (already encrypted) collection
 *   whose Description hosts the descriptor; exactly one of `collection` /
 *   `store`
 * @param [options.store] {EncryptionDescriptorStore}   an explicit descriptor store
 * @param options.recipients {RecipientPublicKey[]}   the initial readers' public
 *   key-agreement keys (each `id` is the reader's `kid`)
 * @param [options.epoch] {{ epochId: string, secret: Uint8Array }}   a
 *   pre-minted first epoch to install instead of minting one -- for a caller
 *   whose epoch key already exists (e.g. a per-user key being enrolled into
 *   its wrap-set roster). The `epochId` must be the key's did:key and `secret`
 *   its raw 32-byte private key, exactly what {@link mintEpoch} returns.
 * @param [options.signEpochs] {EpochsSigner}   signs the epoch configuration
 *   being written, stamping the descriptor's `epochsSig` beside its
 *   `epochsMac`
 * @returns {Promise<CollectionEncryption>}   the new descriptor
 */
export async function initRecipients({
  collection,
  store,
  recipients,
  epoch: premintedEpoch,
  signEpochs
}: {
  collection?: Collection
  store?: EncryptionDescriptorStore
  recipients: RecipientPublicKey[]
  epoch?: { epochId: string; secret: Uint8Array }
  signEpochs?: EpochsSigner
}): Promise<CollectionEncryption> {
  if (recipients.length === 0) {
    throw new ValidationError(
      'initRecipients needs at least one recipient to wrap the epoch key to.'
    )
  }
  const { epochId, secret } = premintedEpoch ?? (await mintEpoch())
  const epoch: CollectionEncryptionEpoch = {
    id: epochId,
    recipients: await Promise.all(
      recipients.map(recipient =>
        wrapEpochSecret({ epochSecret: secret, recipient })
      )
    )
  }
  return casUpdateDescriptor({
    store: descriptorStoreFor({ collection, store }),
    // A store whose descriptor starts absent initializes from a bare `edv`
    // descriptor (the create-if-absent branch); a Collection Description's
    // descriptor always exists, so its adapter never reaches the seed.
    seed: { scheme: 'edv' },
    mutate: async descriptor => {
      if (descriptor.epochs && descriptor.epochs.length > 0) {
        throw new ValidationError(
          'This collection already has key epochs; use addRecipient to add a ' +
            'reader instead of initRecipients.'
        )
      }
      // Declaring the first epochs, so stamp scheme version 1 when the
      // descriptor does not already carry one, and authenticate the epoch
      // configuration with a MAC keyed from this first epoch's secret (computed
      // over the exact descriptor being written, since a CAS retry re-reads the
      // descriptor).
      const next: CollectionEncryption = {
        ...descriptor,
        version: descriptor.version ?? 1,
        epochs: [epoch],
        currentEpoch: epochId
      }
      return stampEpochsAuth({
        descriptor: next,
        epochSecret: secret,
        signEpochs
      })
    }
  })
}

/**
 * Adds a reader to a multi-recipient encrypted Collection. Escrow semantics: the
 * new reader receives EVERY epoch's key (the current one and all prior), because
 * "add a reader to a collection" means it can read the Collection, history
 * included. No rotation happens -- **adds are cheap, removals rotate.**
 *
 * The caller must itself be a recipient of every epoch (its `owner` key unwraps
 * each epoch key, which is then re-wrapped to the new reader). Written back with
 * a compare-and-swap, retried on a concurrent change.
 *
 * @param options {object}
 * @param [options.collection] {Collection}   the collection whose Description
 *   hosts the descriptor; exactly one of `collection` / `store`
 * @param [options.store] {EncryptionDescriptorStore}   an explicit descriptor store
 * @param options.recipient {RecipientPublicKey}   the new reader's public KAK
 * @param options.owner {OwnerKey}   the caller's own key-agreement key, to
 *   unwrap each epoch key for re-wrapping to the new reader
 * @returns {Promise<CollectionEncryption>}   the new descriptor
 */
export async function addRecipient({
  collection,
  store,
  recipient,
  owner
}: {
  collection?: Collection
  store?: EncryptionDescriptorStore
  recipient: RecipientPublicKey
  owner: OwnerKey
}): Promise<CollectionEncryption> {
  return casUpdateDescriptor({
    store: descriptorStoreFor({ collection, store }),
    mutate: async descriptor => {
      const epochs = descriptor.epochs
      if (!epochs || epochs.length === 0) {
        throw new ValidationError(
          'Cannot addRecipient: this collection has no key epochs. Call ' +
            'initRecipients first.'
        )
      }
      const { epochs: nextEpochs } = await escrowIntoEpochs({
        epochs,
        recipient,
        owner,
        operation: 'addRecipient',
        reader: 'new'
      })
      return { ...descriptor, epochs: nextEpochs }
    }
  })
}

/**
 * Removes a reader from a multi-recipient encrypted Collection -- one
 * indivisible operation doing BOTH halves of a removal:
 *
 * 1. **Rotate the epoch**: mint a fresh epoch key, wrap it to each REMAINING
 *    recipient (the current epoch's roster minus the removed reader), append it
 *    as a new epoch, and repoint `currentEpoch`, with a compare-and-swap.
 *    Resources written afterward are unreadable to the removed reader (the read
 *    axis; prospective).
 * 2. **Pull the reader's server-side access** (the pull axis; immediate). By
 *    default that revokes the reader's zcap(s) via `space.revoke()`, so the
 *    server stops serving it ciphertext; a caller whose pull axis lives
 *    elsewhere (e.g. a DID document naming the readers) supplies its own
 *    `pull` action instead.
 *
 * The rotation runs first so it is durable before the irreversible pull:
 * a rotation that keeps losing the compare-and-swap throws with nothing pulled,
 * leaving the operation safely retryable rather than half-applied. The default
 * revoke step tolerates an already-revoked capability (a retry re-revokes) so
 * the operation converges; a custom `pull` should likewise tolerate a retry.
 * The rotation itself is likewise idempotent with respect
 * to retries: when the current epoch already excludes the departing reader
 * (a prior attempt's rotation landed but its pull failed transiently), no
 * fresh epoch is minted or appended -- the retry skips straight to the pull
 * step instead of accumulating a redundant epoch per attempt.
 *
 * Important: this does not re-encrypt existing resources, so the removed
 * reader keeps every earlier epoch's key and can still decrypt any pre-rotation
 * resource whose ciphertext it gets. Neither half alone removes a reader.
 *
 * @param options {object}
 * @param [options.collection] {Collection}   the collection whose Description
 *   hosts the descriptor; exactly one of `collection` / `store`
 * @param [options.store] {EncryptionDescriptorStore}   an explicit descriptor store
 * @param [options.space] {Space}   the collection's Space, for the default
 *   pull axis (zcap revocation); required together with `revoke` unless a
 *   custom `pull` is supplied
 * @param options.recipientId {string}   the removed reader's key-agreement key
 *   id (`kid`), dropped from the new epoch's recipients
 * @param [options.revoke] {IDelegatedZcap | IDelegatedZcap[]}   the reader's
 *   delegated capability/capabilities to revoke (the default pull axis);
 *   required together with `space` unless a custom `pull` is supplied
 * @param [options.pull] {function}   a caller-supplied pull action replacing
 *   the default zcap revocation. Runs only after the rotation is durable, and
 *   should tolerate being re-run (removeRecipient is retried to convergence).
 *   Mutually exclusive with `space` / `revoke`.
 * @param [options.resolveRecipientKey] {function}   resolves a remaining
 *   recipient's `kid` to its public key-agreement key, so the fresh epoch key
 *   can be wrapped to it. Defaults to a `did:key` resolver (the `kid` fragment
 *   is the X25519 public key); override for recipients whose `kid` is not a
 *   self-describing `did:key`. May resolve `null` to signal drop-this-kid:
 *   the rotation then excludes that entry from the fresh epoch instead of
 *   throwing (subject to the no-recipients-remaining guard).
 * @param [options.signEpochs] {EpochsSigner}   signs the rotated epoch
 *   configuration, stamping the descriptor's `epochsSig` beside its
 *   `epochsMac`
 * @returns {Promise<CollectionEncryption>}   the new descriptor
 */
export async function removeRecipient({
  collection,
  store,
  space,
  recipientId,
  revoke,
  pull,
  resolveRecipientKey = defaultResolveRecipientKey,
  signEpochs
}: {
  collection?: Collection
  store?: EncryptionDescriptorStore
  space?: Space
  recipientId: string
  revoke?: IDelegatedZcap | IDelegatedZcap[]
  pull?: () => Promise<void>
  resolveRecipientKey?: (kid: string) => Promise<RecipientPublicKey | null>
  signEpochs?: EpochsSigner
}): Promise<CollectionEncryption> {
  const descriptorStore = descriptorStoreFor({ collection, store })
  // Resolve the pull axis up front, before any rotation, so a malformed call
  // fails before the descriptor is mutated.
  const pullAxis = resolvePullAxis({ space, revoke, pull })
  // 1. Read axis: mint a fresh epoch, wrap it to every remaining recipient,
  // append it, and repoint `currentEpoch` (compare-and-swap, retried on race).
  // Rotate FIRST so the rotation is durable before any irreversible pull:
  // if the CAS keeps losing the race and throws, the reader is neither pulled
  // nor rotated, so `removeRecipient` is safely retryable to convergence.
  const { epochId, secret } = await mintEpoch()
  const rotatedDescriptor = await casUpdateDescriptor({
    store: descriptorStore,
    mutate: async descriptor => {
      const epochs = descriptor.epochs
      if (!epochs || epochs.length === 0) {
        throw new ValidationError(
          'Cannot removeRecipient: this collection has no key epochs.'
        )
      }
      // Remaining recipients: the CURRENT epoch's recipients (the authoritative
      // roster by construction), minus the removed reader. Deliberately NOT the
      // union across all epochs -- a reader dropped in an earlier rotation is
      // still present in that older epoch, so unioning would silently re-escrow
      // it into the fresh epoch and hand it back read access. Older epochs exist
      // only so existing readers can decrypt history.
      const currentEpoch =
        epochs.find(epoch => epoch.id === descriptor.currentEpoch) ??
        epochs[epochs.length - 1]!
      // Already excluded from the current epoch? A prior attempt's rotation
      // landed (its revoke step then failed transiently and the caller
      // retried), or the reader never held the current epoch. Nothing to
      // rotate -- signal no-op so the retry proceeds to the revoke step
      // instead of appending a redundant epoch per attempt.
      if (
        !currentEpoch.recipients.some(entry => entry.header.kid === recipientId)
      ) {
        return null
      }
      const remaining = new Set<string>()
      for (const entry of currentEpoch.recipients) {
        if (entry.header.kid !== recipientId) {
          remaining.add(entry.header.kid)
        }
      }
      if (remaining.size === 0) {
        throw new ValidationError(
          'Cannot removeRecipient: no recipients would remain after the ' +
            'removal (a collection with no readers cannot be rotated to).'
        )
      }
      // Wrap the fresh epoch key to each remaining recipient. The resolver may
      // signal drop-this-kid by resolving `null` (e.g. a roster entry whose
      // key material is no longer resolvable), so the rotation excludes that
      // entry instead of throwing.
      const newEpoch = await rotateEpoch({
        epochId,
        secret,
        remaining,
        resolveRecipientKey
      })
      if (newEpoch.recipients.length === 0) {
        throw new ValidationError(
          'Cannot removeRecipient: no recipients would remain after the ' +
            'removal (resolveRecipientKey dropped every remaining entry, ' +
            'and a collection with no readers cannot be rotated to).'
        )
      }
      // Re-authenticate the epoch configuration under the NEW epoch's secret
      // (the rotating caller just minted it), computed over the exact descriptor
      // being written so a CAS retry re-MACs the re-read descriptor state.
      const next: CollectionEncryption = {
        ...descriptor,
        epochs: [...epochs, newEpoch],
        currentEpoch: epochId
      }
      return stampEpochsAuth({
        descriptor: next,
        epochSecret: secret,
        signEpochs
      })
    }
  })

  // 2. Pull axis: withdraw the reader's server-side access AFTER the rotation
  // is durable -- the default zcap revocation, or the caller-supplied `pull`.
  await pullAxis()

  return rotatedDescriptor
}

/**
 * Replaces one reader (or several) with another in ONE descriptor write -- the
 * shape of a key rotation cascading over a collection (e.g. a per-user key
 * replaced by its successor): the incoming recipient is escrowed into EVERY
 * epoch (history included, {@link addRecipient}'s semantics) and the current
 * epoch is rotated off the retiring recipient(s) ({@link removeRecipient}'s
 * semantics), in a single compare-and-swap. Two requests total (the read and
 * the CAS write) against the four a compose of addRecipient + removeRecipient
 * would cost, and no intermediate state in which both keys are current.
 *
 * Idempotent to convergence like its two halves: an epoch already carrying the
 * incoming recipient is left untouched; when additionally no retiring
 * recipient remains in the current epoch, nothing is written at all -- a naive
 * re-run after a crash appends zero redundant epochs. An escrow-only state
 * (the incoming recipient missing from some epoch but no retiring recipient
 * current) writes the escrow wraps without minting an epoch; the `epochsMac`
 * is untouched then, since it binds the epoch configuration, not the
 * recipient wraps.
 *
 * The pull-axis contract is {@link removeRecipient}'s verbatim: the default
 * zcap revocation (`space` + `revoke`) or a caller-supplied `pull` action,
 * run only after the rotation is durable. A caller whose pull axis has
 * already run elsewhere (e.g. a DID-document edit under a current-key-set
 * rule) passes a no-op `pull`.
 *
 * The rotation ceiling is unchanged: nothing is re-encrypted, so a retired
 * key still opens every pre-rotation epoch it was a recipient of.
 *
 * @param options {object}
 * @param [options.collection] {Collection}   the collection whose Description
 *   hosts the descriptor; exactly one of `collection` / `store`
 * @param [options.store] {EncryptionDescriptorStore}   an explicit descriptor store
 * @param [options.space] {Space}   the default pull axis, with `revoke`
 * @param options.retire {string | string[]}   the retiring recipient kid(s),
 *   dropped from the fresh epoch's roster
 * @param options.recipient {RecipientPublicKey}   the incoming reader's public
 *   key-agreement key, escrowed into every epoch and wrapped into the fresh one
 * @param options.owner {OwnerKey}   the caller's own key-agreement key,
 *   unwrapping each epoch key for the escrow -- it must be a recipient of
 *   every epoch (a retiring key that was escrowed everywhere qualifies)
 * @param [options.revoke] {IDelegatedZcap | IDelegatedZcap[]}   the default
 *   pull axis, with `space`
 * @param [options.pull] {function}   a caller-supplied pull action; mutually
 *   exclusive with `space` / `revoke`
 * @param [options.resolveRecipientKey] {function}   resolves a remaining
 *   recipient's kid for the fresh epoch, `null` to drop it -- the
 *   {@link removeRecipient} contract (the incoming recipient never routes
 *   through it)
 * @param [options.signEpochs] {EpochsSigner}   signs the rotated epoch
 *   configuration, stamping the descriptor's `epochsSig` beside its
 *   `epochsMac` (an escrow-only write leaves both untouched)
 * @returns {Promise<CollectionEncryption>}   the new descriptor
 */
export async function replaceRecipient({
  collection,
  store,
  space,
  retire,
  recipient,
  owner,
  revoke,
  pull,
  resolveRecipientKey = defaultResolveRecipientKey,
  signEpochs
}: {
  collection?: Collection
  store?: EncryptionDescriptorStore
  space?: Space
  retire: string | string[]
  recipient: RecipientPublicKey
  owner: OwnerKey
  revoke?: IDelegatedZcap | IDelegatedZcap[]
  pull?: () => Promise<void>
  resolveRecipientKey?: (kid: string) => Promise<RecipientPublicKey | null>
  signEpochs?: EpochsSigner
}): Promise<CollectionEncryption> {
  const descriptorStore = descriptorStoreFor({ collection, store })
  const pullAxis = resolvePullAxis({ space, revoke, pull })
  const retiring = Array.isArray(retire) ? retire : [retire]
  if (retiring.length === 0) {
    throw new ValidationError(
      'replaceRecipient needs at least one retiring recipient kid; use ' +
        'addRecipient for a pure escrow.'
    )
  }
  if (retiring.includes(recipient.id)) {
    throw new ValidationError(
      'replaceRecipient cannot retire the incoming recipient itself.'
    )
  }
  const { epochId, secret } = await mintEpoch()
  const rotatedDescriptor = await casUpdateDescriptor({
    store: descriptorStore,
    mutate: async descriptor => {
      const epochs = descriptor.epochs
      if (!epochs || epochs.length === 0) {
        throw new ValidationError(
          'Cannot replaceRecipient: this collection has no key epochs.'
        )
      }
      // Escrow the incoming recipient into every epoch it is missing from
      // (addRecipient's escrow, so the whole replacement is one write).
      const { epochs: escrowed, changed: escrowChanged } =
        await escrowIntoEpochs({
          epochs,
          recipient,
          owner,
          operation: 'replaceRecipient',
          reader: 'incoming'
        })
      // Rotate only when a retiring kid is still current (the removeRecipient
      // no-op rule, so a naive re-run appends zero redundant epochs).
      const currentEpoch =
        escrowed.find(epoch => epoch.id === descriptor.currentEpoch) ??
        escrowed[escrowed.length - 1]!
      const rotating = currentEpoch.recipients.some(entry =>
        retiring.includes(entry.header.kid)
      )
      if (!rotating) {
        return escrowChanged ? { ...descriptor, epochs: escrowed } : null
      }
      const remaining = new Set<string>()
      for (const entry of currentEpoch.recipients) {
        if (!retiring.includes(entry.header.kid)) {
          remaining.add(entry.header.kid)
        }
      }
      // The escrow above already placed the incoming recipient in the current
      // epoch, so it is in `remaining`; short-circuit the resolver for it (its
      // public key is in hand) and route only the other survivors through the
      // caller's resolver.
      const newEpoch = await rotateEpoch({
        epochId,
        secret,
        remaining,
        resolveRecipientKey: async kid =>
          kid === recipient.id ? recipient : resolveRecipientKey(kid)
      })
      const next: CollectionEncryption = {
        ...descriptor,
        epochs: [...escrowed, newEpoch],
        currentEpoch: epochId
      }
      return stampEpochsAuth({
        descriptor: next,
        epochSecret: secret,
        signEpochs
      })
    }
  })

  await pullAxis()

  return rotatedDescriptor
}

/**
 * Resolves the pull axis of {@link removeRecipient} -- exactly one of the
 * default zcap revocation (`space` + `revoke`) or a caller-supplied `pull`
 * action -- into the single action run after the rotation is durable.
 *
 * @param options {object}
 * @param [options.space] {Space}
 * @param [options.revoke] {IDelegatedZcap | IDelegatedZcap[]}
 * @param [options.pull] {function}
 * @returns {function}   the pull action
 */
function resolvePullAxis({
  space,
  revoke,
  pull
}: {
  space?: Space
  revoke?: IDelegatedZcap | IDelegatedZcap[]
  pull?: () => Promise<void>
}): () => Promise<void> {
  if (pull !== undefined) {
    if (space !== undefined || revoke !== undefined) {
      throw new ValidationError(
        'removeRecipient takes either the default pull axis (`space` + ' +
          '`revoke`, the zcap revocation) or a custom `pull` action, not both.'
      )
    }
    return pull
  }
  if (space === undefined || revoke === undefined) {
    throw new ValidationError(
      'removeRecipient needs its pull axis: pass `space` and `revoke` (the ' +
        'default zcap revocation), or a custom `pull` action.'
    )
  }
  // The default pull: revoke the reader's capability/capabilities. Tolerate an
  // already-revoked capability so a retry (after a transient revoke failure)
  // converges rather than throwing in the loop: `space.revoke` is not
  // idempotent and reports an already-revoked capability as ValidationError.
  // That same status also covers tampered/expired/foreign capabilities, which
  // the client cannot distinguish here, so this swallows only ValidationError
  // and re-throws anything else.
  const toRevoke = Array.isArray(revoke) ? revoke : [revoke]
  return async function revokeZcaps(): Promise<void> {
    for (const zcap of toRevoke) {
      try {
        await space.revoke(zcap)
      } catch (err) {
        if (err instanceof ValidationError) {
          continue
        }
        throw err
      }
    }
  }
}

/**
 * The default recipient-key resolver: treats a `kid` as a self-describing
 * `did:key` X25519 key-agreement key (`did:key:z...#z...`), so the public key is
 * the fragment.
 *
 * @param kid {string}
 * @returns {Promise<RecipientPublicKey>}
 */
async function defaultResolveRecipientKey(
  kid: string
): Promise<RecipientPublicKey> {
  const resolved = await didKeyResolver({ id: kid })
  return { id: resolved.id, publicKeyMultibase: resolved.publicKeyMultibase }
}

/**
 * Resolves the descriptor store a recipient operation targets: the explicit
 * `store`, or the Collection Description adapter over the `collection` sugar.
 * Exactly one of the two must be supplied.
 *
 * @param options {object}
 * @param [options.collection] {Collection}
 * @param [options.store] {EncryptionDescriptorStore}
 * @returns {EncryptionDescriptorStore}
 */
function descriptorStoreFor({
  collection,
  store
}: {
  collection?: Collection
  store?: EncryptionDescriptorStore
}): EncryptionDescriptorStore {
  if (collection !== undefined && store !== undefined) {
    throw new ValidationError(
      'Pass either `collection` (the Collection Description hosts the ' +
        'descriptor) or `store` (an explicit descriptor store), not both.'
    )
  }
  if (store !== undefined) {
    return store
  }
  if (collection !== undefined) {
    return collectionDescriptorStore({ collection })
  }
  throw new ValidationError(
    'A recipient operation needs its descriptor host: pass `collection` or ' +
      '`store`.'
  )
}

/**
 * Reads the store's descriptor, applies `mutate`, and writes the result back
 * with a compare-and-swap (`If-Match`). Retries on a stale (`412`) validator,
 * re-reading the fresh descriptor each time, up to {@link MAX_CAS_ATTEMPTS};
 * surfaces {@link PreconditionFailedError} if it keeps losing the race. A
 * `mutate` that resolves `null` signals "no change needed" (the descriptor
 * already reflects the desired state, e.g. an idempotent retry): nothing is
 * written and the current descriptor is returned as-is.
 *
 * When the store reports no descriptor yet (`read()` resolves `null`, e.g. the
 * resource adapter before the first `initRecipients`), the optional `seed` is
 * mutated instead and the result written with the store's create-if-absent
 * guard (`If-None-Match: *`). Only `initRecipients` passes a seed; without
 * one an absent descriptor is refused. Losing the create race (a concurrent
 * writer created the first descriptor) re-enters the loop and re-reads, like a
 * stale CAS.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}
 * @param options.mutate {function}   descriptor to the next descriptor (may be async),
 *   or `null` to skip the write
 * @param [options.seed] {CollectionEncryption}   the descriptor to mutate when the
 *   store holds none yet
 * @returns {Promise<CollectionEncryption>}   the written (or current) descriptor
 */
async function casUpdateDescriptor({
  store,
  mutate,
  seed
}: {
  store: EncryptionDescriptorStore
  mutate: (
    descriptor: CollectionEncryption
  ) => CollectionEncryption | null | Promise<CollectionEncryption | null>
  seed?: CollectionEncryption
}): Promise<CollectionEncryption> {
  let lastError: unknown
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
    const current = await store.read()
    if (current === null) {
      if (seed === undefined) {
        throw new ValidationError(
          'Cannot manage recipients: this descriptor store holds no encryption ' +
            'descriptor yet. Call initRecipients first.'
        )
      }
      if (store.create === undefined) {
        throw new ValidationError(
          'Cannot initialize recipients: this descriptor store holds no descriptor ' +
            'and does not support creating one.'
        )
      }
      const created = await mutate(seed)
      if (created === null) {
        return seed
      }
      try {
        await store.create(created)
        return created
      } catch (err) {
        if (err instanceof PreconditionFailedError) {
          // A concurrent writer created the first descriptor: re-read and
          // re-apply.
          lastError = err
          continue
        }
        throw err
      }
    }
    const next = await mutate(current.descriptor)
    if (next === null) {
      // The descriptor already reflects the desired state: nothing to write.
      return current.descriptor
    }
    try {
      await store.replace(next, { ifMatch: current.etag })
      return next
    } catch (err) {
      if (err instanceof PreconditionFailedError) {
        // A concurrent recipient change landed first: re-read and re-apply.
        lastError = err
        continue
      }
      throw err
    }
  }
  throw new PreconditionFailedError(
    `Recipient change lost the compare-and-swap race after ${MAX_CAS_ATTEMPTS} ` +
      'attempts (another writer kept updating the stored descriptor). ' +
      'Retry the operation.',
    { cause: lastError as Error }
  )
}
