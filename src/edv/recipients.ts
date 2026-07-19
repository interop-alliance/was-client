/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Recipient and key-epoch management for multi-recipient encrypted Collections:
 * initializing the first epoch, adding a reader (escrow -- history included),
 * and removing a reader (the full revoke-and-rotate procedure). Each operation
 * mutates the Collection's `encryption` marker and writes it back with a
 * compare-and-swap (`If-Match`), retrying on a concurrent change so two racing
 * recipient edits cannot clobber one another.
 *
 * The two axes stay separate and are both required to actually remove a reader:
 *
 * - **pull** -- the zcap the server checks at request time. Revoking it stops
 *   the server serving that reader ciphertext. Immediate and total.
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
import { unreadableDescriptionError } from '../internal/describe.js'
import { PreconditionFailedError, ValidationError } from '../errors.js'
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
 * Initializes the first key epoch on a Collection that is declared encrypted
 * but has no epochs yet: mints a fresh epoch key, wraps it to each initial
 * recipient, and writes `epochs: [epoch]` / `currentEpoch` back with a
 * compare-and-swap. After this, resources written by any recipient are encrypted
 * under the epoch, and readers unwrap it with their own key-agreement key.
 *
 * @param options {object}
 * @param options.collection {Collection}   the (already encrypted) collection
 * @param options.recipients {RecipientPublicKey[]}   the initial readers' public
 *   key-agreement keys (each `id` is the reader's `kid`)
 * @returns {Promise<CollectionEncryption>}   the new marker
 */
export async function initRecipients({
  collection,
  recipients
}: {
  collection: Collection
  recipients: RecipientPublicKey[]
}): Promise<CollectionEncryption> {
  if (recipients.length === 0) {
    throw new ValidationError(
      'initRecipients needs at least one recipient to wrap the epoch key to.'
    )
  }
  const { epochId, secret } = await mintEpoch()
  const epoch: CollectionEncryptionEpoch = {
    id: epochId,
    recipients: await Promise.all(
      recipients.map(recipient =>
        wrapEpochSecret({ epochSecret: secret, recipient })
      )
    )
  }
  return casUpdateMarker({
    collection,
    mutate: marker => {
      if (marker.epochs && marker.epochs.length > 0) {
        throw new ValidationError(
          'This collection already has key epochs; use addRecipient to add a ' +
            'reader instead of initRecipients.'
        )
      }
      return { ...marker, epochs: [epoch], currentEpoch: epochId }
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
 * @param options.collection {Collection}   the collection
 * @param options.recipient {RecipientPublicKey}   the new reader's public KAK
 * @param options.owner {OwnerKey}   the caller's own key-agreement key, to
 *   unwrap each epoch key for re-wrapping to the new reader
 * @returns {Promise<CollectionEncryption>}   the new marker
 */
export async function addRecipient({
  collection,
  recipient,
  owner
}: {
  collection: Collection
  recipient: RecipientPublicKey
  owner: OwnerKey
}): Promise<CollectionEncryption> {
  return casUpdateMarker({
    collection,
    mutate: async marker => {
      const epochs = marker.epochs
      if (!epochs || epochs.length === 0) {
        throw new ValidationError(
          'Cannot addRecipient: this collection has no key epochs. Call ' +
            'initRecipients first.'
        )
      }
      // Each epoch's unwrap + re-wrap is independent of the others', so run
      // them concurrently (order-preserving), like `initRecipients` and
      // `removeRecipient` wrap their recipients.
      const nextEpochs = await Promise.all(
        epochs.map(async (epoch): Promise<CollectionEncryptionEpoch> => {
          // Already a recipient of this epoch? Leave it untouched (idempotent).
          if (
            epoch.recipients.some(entry => entry.header.kid === recipient.id)
          ) {
            return epoch
          }
          const ownEntry = epoch.recipients.find(
            entry => entry.header.kid === owner.keyAgreementKey.id
          )
          if (!ownEntry) {
            throw new ValidationError(
              `Cannot addRecipient: the caller is not a recipient of epoch ` +
                `"${epoch.id}", so it cannot unwrap that epoch key to escrow ` +
                'it to the new reader.'
            )
          }
          const secret = await unwrapEpochSecret({
            entry: ownEntry,
            keyAgreementKey: owner.keyAgreementKey
          })
          if (!secret) {
            throw new ValidationError(
              `Cannot addRecipient: unwrapping epoch "${epoch.id}" with the ` +
                "caller's key-agreement key failed."
            )
          }
          const wrapped = await wrapEpochSecret({
            epochSecret: secret,
            recipient
          })
          return {
            ...epoch,
            recipients: [...epoch.recipients, wrapped]
          }
        })
      )
      return { ...marker, epochs: nextEpochs }
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
 * 2. **Revoke the reader's zcap(s)** via `space.revoke()`, so the server stops
 *    serving it ciphertext (the pull axis; immediate).
 *
 * The rotation runs first so it is durable before the irreversible revocation:
 * a rotation that keeps losing the compare-and-swap throws with nothing revoked,
 * leaving the operation safely retryable rather than half-applied. The revoke
 * step tolerates an already-revoked capability (a retry re-revokes) so the
 * operation converges. The rotation itself is likewise idempotent with respect
 * to retries: when the current epoch already excludes the departing reader
 * (a prior attempt's rotation landed but its revoke failed transiently), no
 * fresh epoch is minted or appended -- the retry skips straight to the revoke
 * step instead of accumulating a redundant epoch per attempt.
 *
 * Important: this does not re-encrypt existing resources, so the removed
 * reader keeps every earlier epoch's key and can still decrypt any pre-rotation
 * resource whose ciphertext it gets. Neither half alone removes a reader.
 *
 * @param options {object}
 * @param options.collection {Collection}   the collection
 * @param options.space {Space}   the collection's Space, for the zcap revocation
 * @param options.recipientId {string}   the removed reader's key-agreement key
 *   id (`kid`), dropped from the new epoch's recipients
 * @param options.revoke {IDelegatedZcap | IDelegatedZcap[]}   the reader's
 *   delegated capability/capabilities to revoke (the pull axis)
 * @param [options.resolveRecipientKey] {function}   resolves a remaining
 *   recipient's `kid` to its public key-agreement key, so the fresh epoch key
 *   can be wrapped to it. Defaults to a `did:key` resolver (the `kid` fragment
 *   is the X25519 public key); override for recipients whose `kid` is not a
 *   self-describing `did:key`.
 * @returns {Promise<CollectionEncryption>}   the new marker
 */
export async function removeRecipient({
  collection,
  space,
  recipientId,
  revoke,
  resolveRecipientKey = defaultResolveRecipientKey
}: {
  collection: Collection
  space: Space
  recipientId: string
  revoke: IDelegatedZcap | IDelegatedZcap[]
  resolveRecipientKey?: (kid: string) => Promise<RecipientPublicKey>
}): Promise<CollectionEncryption> {
  // 1. Read axis: mint a fresh epoch, wrap it to every remaining recipient,
  // append it, and repoint `currentEpoch` (compare-and-swap, retried on race).
  // Rotate FIRST so the rotation is durable before any irreversible revocation:
  // if the CAS keeps losing the race and throws, the reader is neither revoked
  // nor rotated, so `removeRecipient` is safely retryable to convergence.
  const { epochId, secret } = await mintEpoch()
  const rotatedMarker = await casUpdateMarker({
    collection,
    mutate: async marker => {
      const epochs = marker.epochs
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
        epochs.find(epoch => epoch.id === marker.currentEpoch) ??
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
      const newRecipients = await Promise.all(
        [...remaining].map(async kid =>
          wrapEpochSecret({
            epochSecret: secret,
            recipient: await resolveRecipientKey(kid)
          })
        )
      )
      const newEpoch: CollectionEncryptionEpoch = {
        id: epochId,
        recipients: newRecipients
      }
      return {
        ...marker,
        epochs: [...epochs, newEpoch],
        currentEpoch: epochId
      }
    }
  })

  // 2. Pull axis: revoke the reader's capability/capabilities AFTER the rotation
  // is durable. Tolerate an already-revoked capability so a retry (after a
  // transient revoke failure) converges rather than throwing in the loop:
  // `space.revoke` is not idempotent and reports an already-revoked capability
  // as ValidationError. That same status also covers tampered/expired/foreign
  // capabilities, which the client cannot distinguish here, so this swallows
  // only ValidationError and re-throws anything else.
  const toRevoke = Array.isArray(revoke) ? revoke : [revoke]
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

  return rotatedMarker
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
 * Reads the Collection Description, applies `mutate` to its `encryption` marker,
 * and writes it back with a compare-and-swap (`If-Match`). Retries on a stale
 * (`412`) validator, re-reading the fresh marker each time, up to
 * {@link MAX_CAS_ATTEMPTS}; surfaces {@link PreconditionFailedError} if it keeps
 * losing the race. A `mutate` that resolves `null` signals "no change needed"
 * (the marker already reflects the desired state, e.g. an idempotent retry):
 * nothing is written and the current marker is returned as-is.
 *
 * @param options {object}
 * @param options.collection {Collection}
 * @param options.mutate {function}   marker to the next marker (may be async),
 *   or `null` to skip the write
 * @returns {Promise<CollectionEncryption>}   the written (or current) marker
 */
async function casUpdateMarker({
  collection,
  mutate
}: {
  collection: Collection
  mutate: (
    marker: CollectionEncryption
  ) => CollectionEncryption | null | Promise<CollectionEncryption | null>
}): Promise<CollectionEncryption> {
  let lastError: unknown
  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
    const current = await collection.describeWithEtag()
    if (current === null) {
      throw unreadableDescriptionError({
        operation: 'manage recipients',
        advice: 'Use a capability that can read the Collection Description.'
      })
    }
    const marker = current.description.encryption
    if (!marker || marker.scheme !== 'edv') {
      throw new ValidationError(
        'Cannot manage recipients: this collection is not declared encrypted ' +
          "with the 'edv' scheme."
      )
    }
    const next = await mutate(marker)
    if (next === null) {
      // The marker already reflects the desired state: nothing to write.
      return marker
    }
    try {
      await collection.replaceDescription(
        {
          name: current.description.name,
          backend: current.description.backend,
          encryption: next
        },
        { ifMatch: current.etag }
      )
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
      'attempts (another writer kept updating the Collection Description). ' +
      'Retry the operation.',
    { cause: lastError as Error }
  )
}
