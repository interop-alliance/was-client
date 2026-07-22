/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `createEdvDocCipher`: a per-collection encrypt/decrypt seam for an end-to-end
 * encrypted collection, wrapping the same EDV codec the `WasClient` handles use
 * but pointed at a local replica. A write encrypts the document into an EDV
 * envelope (`{ id, sequence, jwe }`) whose id is content-derived (a hash of the
 * JWE ciphertext, `idDerivation: 'content'`) or a stable random id
 * (`'random'`); a read decrypts the stored envelope back. The envelope is what a
 * replica holds and what replication ships verbatim, so the same bytes -- and
 * the same content-derived id -- appear on every replica. The port never touches
 * these keys.
 *
 * A collection may be single-recipient (only the wallet's own key-agreement key
 * reads it) or multi-recipient. Multi-recipient collections carry a
 * `CollectionEncryption` marker with key epochs: each epoch wraps one collection
 * key to every reader, writes encrypt under the marker's `currentEpoch`, and
 * removing a reader appends a fresh epoch that excludes it. This module is the
 * **read** axis only: it turns a reader's own key-agreement key plus the marker
 * into a cipher that encrypts under the current epoch and decrypts any epoch that
 * reader still holds a key for.
 *
 * Rotation is prospective, never retroactive: appending an epoch does not rewrite
 * existing resources, and because resource ids are content-derived they stay
 * stable across a rotation. Reads stay tolerant of unstamped pre-epoch resources
 * indefinitely -- an envelope encrypted straight to the key-agreement key (before
 * any epoch existed) always decrypts through the single-key path.
 *
 * Runtime note (React Native): this exercises the cipher's AES-KW (with a pure-JS
 * Hermes fallback) and `TextDecoder`; both must be present on the device.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { KeyUnwrapError } from '../errors.js'
import type { CollectionEncryption } from '../types.js'
import type { DocCipher, Json } from '../sync/types.js'
import { createEdvEncryption } from './EdvCodec.js'
import { epochKeyIdFor } from './epochCrypto.js'
import type { RecipientPublicKey } from './recipients.js'

// `isEncryptedEnvelope` and the `DocCipher` interface live in the crypto-free
// `../sync` module; re-exported here so an encrypted-collection consumer that
// imports this subpath gets both without a second import.
export { isEncryptedEnvelope } from '../sync/envelope.js'
export type { DocCipher } from '../sync/types.js'

/**
 * Thrown by a {@link DocCipher.decrypt} when a stored envelope names a JWE
 * recipient (`kid`) this cipher cannot route: neither the key-agreement key nor
 * -- on an epoch-aware cipher -- any epoch this cipher knows about. It signals
 * that the caller's cached Collection Description may be stale and should be
 * re-read before retrying: an epoch rotation emits no change-feed entry, so a
 * cipher built from a pre-rotation marker meets envelopes stamped with a newer
 * epoch it has never seen. It also fires on a single-key cipher that meets an
 * envelope encrypted to a different key-agreement key entirely.
 */
export class UnknownEpochError extends Error {
  constructor({
    collectionId,
    kids
  }: {
    collectionId: string
    kids: string[]
  }) {
    super(
      `Cannot decrypt a resource in collection "${collectionId}": its ` +
        `envelope names recipient key id(s) [${kids.join(', ')}] that match ` +
        'neither the key-agreement key nor any known key epoch. The cached ' +
        'Collection Description may be stale (an epoch rotation emits no ' +
        'change-feed entry); re-read it and rebuild the cipher.'
    )
    this.name = 'UnknownEpochError'
  }
}

/**
 * A wallet's own key-agreement key as a `RecipientPublicKey` -- the "recipient
 * zero" entry a caller passes to `initRecipients` when it first makes a
 * collection multi-recipient (the owner must be a recipient of every epoch, or it
 * could write envelopes it cannot itself read). An `X25519KeyAgreementKey2020`
 * carries a did:key-shaped `id` and a `publicKeyMultibase`, so its `kid`'s
 * fragment resolves through the default did:key recipient resolver.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}
 * @returns {RecipientPublicKey}
 */
export function ownerRecipient({
  keyAgreementKey
}: {
  keyAgreementKey: IKeyAgreementKey
}): RecipientPublicKey {
  const { id } = keyAgreementKey
  const { publicKeyMultibase, type } = keyAgreementKey as {
    publicKeyMultibase?: string
    type?: string
  }
  if (typeof id !== 'string' || typeof publicKeyMultibase !== 'string') {
    throw new Error(
      'Cannot build an owner recipient: the key-agreement key lacks an id or ' +
        'publicKeyMultibase (a public X25519 key is required to wrap an epoch ' +
        'key to it).'
    )
  }
  return { id, publicKeyMultibase, type }
}

/**
 * Extracts the JWE recipient key ids (`kid`) an EDV envelope names. An epoch
 * envelope carries one kid (the epoch key id); a single-recipient envelope
 * carries the key-agreement key id. Returns `[]` for a malformed envelope, so
 * routing falls through to letting a codec surface its own error.
 */
function envelopeRecipientKids(envelope: Json): string[] {
  if (envelope === null || typeof envelope !== 'object') {
    return []
  }
  const jwe = (envelope as { jwe?: unknown }).jwe
  if (jwe === null || typeof jwe !== 'object') {
    return []
  }
  const recipients = (jwe as { recipients?: unknown }).recipients
  if (!Array.isArray(recipients)) {
    return []
  }
  const kids: string[] = []
  for (const recipient of recipients) {
    const kid = (recipient as { header?: { kid?: unknown } })?.header?.kid
    if (typeof kid === 'string') {
      kids.push(kid)
    }
  }
  return kids
}

/**
 * Builds a {@link DocCipher} for one encrypted collection from a reader's key
 * material (the key-agreement key + resolver). Keys are supplied directly (no
 * keystore lookup).
 *
 * `idDerivation` selects the id model: `'content'` (default) makes every id a
 * hash of the JWE ciphertext -- the stable, replica-independent primary key an
 * immutable content-addressed collection needs; `'random'` mints a stable random
 * id updated in place via `sequence` (the mutable head-document model, driven by
 * `encryptUpdate`).
 *
 * With no `encryption` marker (or a marker with no epochs) the cipher is single-
 * recipient: the key-agreement key encrypts and decrypts directly. With epochs on
 * the marker the cipher becomes multi-recipient: it ALSO builds an epoch codec
 * that encrypts every write under the marker's `currentEpoch` and decrypts any
 * epoch this reader still holds a key for. The single-key codec stays built
 * either way, so a pre-epoch envelope keeps decrypting -- a permanent tolerance,
 * not a migration shim.
 *
 * The reader must be a recipient of every epoch on the marker (the owner is
 * "recipient zero"). If it is a recipient of none, building the epoch codec
 * throws {@link KeyUnwrapError}; this surfaces it with a clearer error rather
 * than silently writing envelopes other recipients cannot read.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}
 * @param options.keyResolver {IKeyResolver}
 * @param options.collectionId {string}   labels errors; the codec is agnostic
 * @param [options.idDerivation] {'content' | 'random'}   defaults to `'content'`
 * @param [options.encryption] {CollectionEncryption}   the collection's
 *   encryption marker; when it carries key epochs, the cipher becomes
 *   multi-recipient
 * @returns {Promise<DocCipher>}
 */
export async function createEdvDocCipher({
  keyAgreementKey,
  keyResolver,
  collectionId,
  idDerivation = 'content',
  encryption
}: {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  collectionId: string
  idDerivation?: 'content' | 'random'
  encryption?: CollectionEncryption
}): Promise<DocCipher> {
  const provider = createEdvEncryption({
    resolveKeys: async () => null,
    idDerivation
  })
  // The direct (single-key) codec is always built: it decrypts pre-epoch
  // envelopes and is the whole cipher for a single-recipient collection.
  const directCodec = await provider.codecFor({
    spaceId: 'local',
    collectionId,
    scheme: 'edv',
    keys: { keyAgreementKey, keyResolver }
  })
  if (!directCodec) {
    throw new Error(
      `Could not build the EDV cipher for collection "${collectionId}".`
    )
  }

  // On a multi-recipient collection, ALSO build the epoch codec: same provider
  // and keys, but with the marker so `codecFor` resolves this reader's per-epoch
  // keys. Writes go under the marker's `currentEpoch`; reads pick the epoch key
  // matching the envelope's recipient kid.
  const hasEpochs =
    encryption?.epochs !== undefined && encryption.epochs.length > 0
  let epochCodec: Awaited<ReturnType<typeof provider.codecFor>> | undefined
  if (hasEpochs) {
    try {
      epochCodec = await provider.codecFor({
        spaceId: 'local',
        collectionId,
        scheme: 'edv',
        encryption,
        keys: { keyAgreementKey, keyResolver }
      })
    } catch (err) {
      if (err instanceof KeyUnwrapError) {
        throw new Error(
          `Cannot build the multi-recipient EDV cipher for collection ` +
            `"${collectionId}": the key-agreement key is not a recipient of any ` +
            'key epoch on this collection. The owner must be a recipient of ' +
            'every epoch (recipient zero) before writing, or it would encrypt ' +
            'envelopes it cannot itself read.',
          { cause: err }
        )
      }
      throw err
    }
    if (!epochCodec) {
      throw new Error(
        `Could not build the multi-recipient EDV cipher for collection ` +
          `"${collectionId}".`
      )
    }
  }

  const vaultKid = keyAgreementKey.id
  const knownEpochKids = new Set<string>(
    (encryption?.epochs ?? []).map(epoch => epochKeyIdFor(epoch.id))
  )

  // Parses the codec's `EncodedWrite` (id + envelope body bytes) to the stored
  // `{ id, envelope, epoch? }` shape. Shared by the create and update paths.
  const readEncoded = (encoded: {
    id?: string
    body?: Uint8Array | Blob
    epoch?: string
  }): { id: string; envelope: Json; epoch?: string } => {
    if (
      typeof encoded.id !== 'string' ||
      !(encoded.body instanceof Uint8Array)
    ) {
      throw new Error(
        `EDV encrypt for collection "${collectionId}" returned no id/envelope body.`
      )
    }
    const envelope = JSON.parse(new TextDecoder().decode(encoded.body)) as Json
    return {
      id: encoded.id,
      envelope,
      ...(typeof encoded.epoch === 'string' && { epoch: encoded.epoch })
    }
  }

  return {
    async encrypt({ data }: { data: Json }) {
      // `encode` with no caller id is the add() path: encrypt, then either derive
      // and stamp the content-hash id (`'content'`) or use the minted random id.
      // Writes go under the current epoch on a multi-recipient cipher.
      const codec = epochCodec ?? directCodec
      const encoded = await codec.encode({
        data: data as Extract<Json, object>
      })
      return readEncoded(encoded)
    },

    async encryptUpdate({
      id,
      data,
      current
    }: {
      id: string
      data: Json
      current: Json
    }) {
      // The update path (mutable random-id head document): hand the codec the
      // prior stored envelope so it advances `sequence` from it and re-encrypts
      // under the same id.
      const codec = epochCodec ?? directCodec
      const priorResponse = {
        data: current,
        json: async () => current,
        headers: { get: () => null }
      } as unknown as Parameters<typeof codec.encode>[0]['current']
      const encoded = await codec.encode({
        id,
        data: data as Extract<Json, object>,
        current: priorResponse
      })
      const { id: encodedId, envelope } = readEncoded(encoded)
      return { id: encodedId, envelope }
    },

    async decrypt({ envelope }: { envelope: Json }) {
      // Route by the envelope's JWE recipient kids:
      //   1. any kid is the key-agreement key id -- a pre-epoch envelope, so the
      //      direct codec (permanent tolerance, not a migration shim);
      //   2. else, on an epoch cipher, any kid names a known epoch -- the epoch
      //      codec;
      //   3. else UnknownEpochError: the marker is likely stale, or a single-key
      //      cipher met an envelope encrypted to a different key entirely.
      const kids = envelopeRecipientKids(envelope)
      const codec = selectCodec()
      const response = {
        data: envelope,
        json: async () => envelope
      } as unknown as Parameters<typeof codec.decode>[0]
      return (await codec.decode(response)) as Json

      function selectCodec() {
        if (kids.some(kid => kid === vaultKid)) {
          return directCodec!
        }
        if (epochCodec && kids.some(kid => knownEpochKids.has(kid))) {
          return epochCodec
        }
        // A malformed/empty-kid envelope falls through to the direct codec so it
        // can surface its own decrypt error; a non-empty set of unroutable kids
        // is the stale-marker signal.
        if (kids.length === 0) {
          return directCodec!
        }
        throw new UnknownEpochError({ collectionId, kids })
      }
    }
  }
}
