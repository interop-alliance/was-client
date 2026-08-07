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
 * `CollectionEncryption` descriptor with key epochs: each epoch wraps one
 * collection key to every reader, writes encrypt under the descriptor's
 * `currentEpoch`, and removing a reader appends a fresh epoch that excludes it.
 * This module is the **read** axis only: it turns a reader's own key-agreement
 * key plus the descriptor into a cipher that encrypts under the current epoch
 * and decrypts any epoch that reader still holds a key for.
 *
 * Rotation is prospective, never retroactive: appending an epoch does not
 * rewrite existing resources, and because resource ids are content-derived they
 * stay stable across a rotation.
 *
 * Runtime note (React Native): this exercises the cipher's AES-KW (with a
 * pure-JS Hermes fallback) and `TextDecoder`; both must be present on the
 * device.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { ResponseLike } from '../codec.js'
import { KeyUnwrapError } from '../errors.js'
import type { CollectionEncryption } from '../types.js'
import type { DocCipher, Json } from '../sync/types.js'
import { createEdvEncryption } from './EdvCodec.js'
import type { RecipientPublicKey } from './recipients.js'

// `isEncryptedEnvelope` and the `DocCipher` interface live in the crypto-free
// `../sync` module, and `UnknownEpochError` (thrown by the codec's decrypt
// routing) in the errors module; re-exported here so an encrypted-collection
// consumer that imports this subpath gets all three without a second import.
export { isEncryptedEnvelope } from '../sync/envelope.js'
export type { DocCipher } from '../sync/types.js'
export { UnknownEpochError } from '../errors.js'

/**
 * A wallet's own key-agreement key as a `RecipientPublicKey` -- the "recipient
 * zero" entry a caller passes to `initRecipients` when it first makes a
 * collection multi-recipient (the owner must be a recipient of every epoch, or
 * it could write envelopes it cannot itself read). An
 * `X25519KeyAgreementKey2020` carries a did:key-shaped `id` and a
 * `publicKeyMultibase`, so its `kid`'s fragment resolves through the default
 * did:key recipient resolver.
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
 * Presents a locally-held envelope to the codec seam as the {@link
 * ResponseLike} the seam is typed against. A replica's envelope never came
 * from HTTP: the pre-parsed body, the `json()` fallback, and a headers stub
 * (so an ETag lookup resolves to "no validator") are the whole surface.
 *
 * @param envelope {Json}   the stored envelope
 * @returns {ResponseLike}
 */
function envelopeResponse(envelope: Json): ResponseLike {
  return {
    data: envelope,
    json: async () => envelope,
    headers: { get: () => null }
  }
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
 * With no `encryption` descriptor (or a descriptor with no epochs) the cipher
 * is single-recipient: the key-agreement key encrypts and decrypts directly.
 * With epochs on the descriptor the cipher is multi-recipient: it encrypts
 * every write under the descriptor's `currentEpoch` and decrypts any epoch
 * this reader still holds a key for. Either way one codec owns both axes --
 * decrypt routing (matching an envelope's JWE recipient `kid`s against the
 * reader's candidate keys, raising `UnknownEpochError` for an envelope no
 * candidate can route) lives in the codec, not here.
 *
 * The reader must be a recipient of every epoch on the descriptor (the owner is
 * "recipient zero"). If it is a recipient of none, building the cipher
 * throws {@link KeyUnwrapError}; this surfaces it with a clearer error rather
 * than silently writing envelopes other recipients cannot read.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}
 * @param options.keyResolver {IKeyResolver}
 * @param options.collectionId {string}   labels errors; the codec is agnostic
 * @param [options.idDerivation] {'content' | 'random'}   defaults to `'content'`
 * @param [options.encryption] {CollectionEncryption}   the collection's
 *   encryption descriptor; when it carries key epochs, the cipher becomes
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
  // One codec owns both axes. With epochs on the descriptor, `codecFor`
  // resolves this reader's per-epoch keys: writes go under the descriptor's
  // `currentEpoch`, and reads pick the epoch key matching the envelope's
  // recipient kid. Without epochs it is the single-recipient cipher keyed
  // straight to the key-agreement key.
  let resolved: Awaited<ReturnType<typeof provider.codecFor>>
  try {
    resolved = await provider.codecFor({
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
  if (!resolved) {
    throw new Error(
      `Could not build the EDV cipher for collection "${collectionId}".`
    )
  }
  const codec = resolved

  // Parses the codec's `EncodedWrite` (id + envelope body bytes) to the stored
  // `{ id, envelope, epoch? }` shape. Shared by the create and update paths.
  const readEncoded = (encoded: {
    id?: string
    body?: Uint8Array | Blob
    envelope?: unknown
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
    // Prefer the object form the codec already holds; parse the wire bytes only
    // when a codec does not surface it.
    const envelope =
      encoded.envelope !== undefined
        ? (encoded.envelope as Json)
        : (JSON.parse(new TextDecoder().decode(encoded.body)) as Json)
    return {
      id: encoded.id,
      envelope,
      ...(typeof encoded.epoch === 'string' && { epoch: encoded.epoch })
    }
  }

  return {
    async encrypt({ data }: { data: Json }) {
      // `encode` with no caller id is the add() path: encrypt, then either
      // derive and stamp the content-hash id (`'content'`) or use the minted
      // random id.
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
      const encoded = await codec.encode({
        id,
        data: data as Extract<Json, object>,
        current: envelopeResponse(current)
      })
      return readEncoded(encoded)
    },

    async decrypt({ envelope }: { envelope: Json }) {
      // Routing by the envelope's JWE recipient kids -- including the
      // stale-descriptor `UnknownEpochError` for an envelope no candidate key
      // routes -- is owned by the codec's decrypt.
      return (await codec.decode(envelopeResponse(envelope))) as Json
    }
  }
}
