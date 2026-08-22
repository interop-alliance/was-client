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
 * Every encrypted collection carries a `CollectionEncryption` descriptor with
 * key epochs, from birth: each epoch wraps one collection key to every reader,
 * writes encrypt under the descriptor's `currentEpoch`, and removing a reader
 * appends a fresh epoch that excludes it. This module is the **read** axis
 * only: it turns a reader's own key-agreement key plus the descriptor into a
 * cipher that encrypts under the current epoch and decrypts any epoch that
 * reader still holds a key for.
 *
 * Alongside the reader's build sits `createEdvEncryptOnlyDocCipher`, the
 * write-only counterpart built from the descriptor alone: encryption seals to
 * the write epoch's public key (the epoch id IS that key's did:key), so it
 * needs no key-agreement secret, and decrypt on that cipher refuses with the
 * typed `EncryptOnlyCipherError`. It is the build for a writer that holds only
 * a recipient's public half -- e.g. re-sealing a record to a recovery code's
 * unlock key the writer can never open.
 *
 * Rotation is prospective, never retroactive: appending an epoch does not
 * rewrite existing resources, and because resource ids are content-derived they
 * stay stable across a rotation.
 *
 * On a collection whose descriptor also declares a blinded-index key, the
 * cipher can install the collection's persisted index schema (`applyMeta`, or
 * the `meta` build input), so envelopes written here carry the same blinded
 * `indexed` entries as a write through a Collection handle -- which is what
 * makes a pushed document findable by `collection.find()`.
 *
 * Runtime note (React Native): this exercises the cipher's AES-KW (with a
 * pure-JS Hermes fallback) and `TextDecoder`; both must be present on the
 * device.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { CodecWrite, IndexSchema, ResourceCodec } from '../codec.js'
import { isChunkedWrite } from '../codec.js'
import { DECODER, storedResponse } from '../internal/content.js'
import { EMPTY_INDEX_SCHEMA, readIndexSchema } from '../internal/indexSchema.js'
import {
  EncryptOnlyCipherError,
  KeyUnwrapError,
  ValidationError
} from '../errors.js'
import type { CollectionEncryption } from '../types.js'
import type { DocCipher, Json } from '../sync/types.js'
import { buildEdvCodec, encryptOnlyEdvCodec } from './EdvCodec.js'
import type { EdvCodec } from './EdvCodec.js'
import type { RecipientPublicKey } from './recipients.js'

// `isEncryptedEnvelope` and the `DocCipher` interface live in the crypto-free
// `../sync` module, and the decrypt-routing signals (`UnknownEpochError` for a
// stale descriptor, `KeyUnwrapError` for a reader that is not a recipient of
// the envelope's epoch) in the errors module; re-exported here so an
// encrypted-collection consumer that imports this subpath gets them without a
// second import.
export { isEncryptedEnvelope } from '../sync/envelope.js'
export type { DocCipher } from '../sync/types.js'
export {
  EncryptOnlyCipherError,
  KeyUnwrapError,
  UnknownEpochError
} from '../errors.js'

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
 * A {@link DocCipher} for an encrypted collection, plus the blinded-index
 * schema install the sync path needs.
 */
export interface EdvDocCipher extends DocCipher {
  /**
   * Installs the collection's persisted index schema, read out of the stored
   * `/meta` value, onto this cipher -- so subsequent writes emit blinded
   * `indexed` entries and a document pushed through the sync path is findable
   * by `collection.find()`. Call it again whenever the replica's copy of the
   * collection metadata changes (an index declared mid-session, say): it is the
   * sync-path analogue of the direct path re-reading the schema whenever a
   * handle's codec is re-resolved.
   *
   * On a collection whose descriptor declares no blinded-index key this is a
   * no-op resolving the empty schema, so a caller may invoke it
   * unconditionally.
   *
   * @param options {object}
   * @param [options.custom] {unknown}   the stored `custom` value from the
   *   collection's `/meta` (an opaque envelope on an encrypted collection)
   * @returns {Promise<IndexSchema>}   the installed schema (the empty schema
   *   when the collection declares no blinded-index key, or the metadata
   *   carries no schema)
   */
  applyMeta(options: { custom?: unknown }): Promise<IndexSchema>
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
 * The `encryption` descriptor must carry key epochs (a descriptor without them
 * is refused fail-closed by the codec): the cipher encrypts every write under
 * the descriptor's `currentEpoch` and decrypts any epoch this reader still
 * holds a key for. One codec owns both axes -- decrypt routing (matching an
 * envelope's JWE recipient `kid`s against the reader's candidate keys, raising
 * `UnknownEpochError` for an envelope stamped with an epoch the descriptor
 * does not list, and `KeyUnwrapError` for one whose listed epoch this reader
 * is not a recipient of) lives in the codec, not here.
 *
 * The reader must be a recipient of every epoch on the descriptor (the owner is
 * "recipient zero"). If it is a recipient of none, building the cipher
 * throws {@link KeyUnwrapError}; this surfaces it with a clearer error rather
 * than silently writing envelopes other recipients cannot read.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}
 * @param options.keyResolver {IKeyResolver}
 * @param options.collectionId {string}   the collection's WAS id. It must be
 *   the real id, not a label: the collection's metadata envelope is
 *   AEAD-bound to it (`was.collection`), so `applyMeta` refuses an envelope
 *   bound elsewhere.
 * @param [options.idDerivation] {'content' | 'random'}   defaults to `'content'`
 * @param options.encryption {CollectionEncryption}   the collection's
 *   encryption descriptor; must carry the key-epoch roster (every encrypted
 *   collection has one from birth)
 * @param [options.meta] {object}   the collection's stored `/meta` value as the
 *   replica holds it; on an encrypted collection its `custom` is the opaque
 *   encrypted metadata envelope, decrypted here with the collection keys. When
 *   supplied and the descriptor declares a blinded-index `hmac` key, the
 *   persisted index schema is installed so writes emit blinded `indexed`
 *   entries matching direct-path writes. Without it (or without an `hmac`)
 *   writes emit no `indexed` entries, and are invisible to `collection.find()`
 *   until rewritten -- an offline replica that holds no metadata works exactly
 *   as before.
 * @returns {Promise<EdvDocCipher>}
 */
export async function createEdvDocCipher({
  keyAgreementKey,
  keyResolver,
  collectionId,
  idDerivation = 'content',
  encryption,
  meta
}: {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  collectionId: string
  idDerivation?: 'content' | 'random'
  encryption: CollectionEncryption
  meta?: { custom?: unknown }
}): Promise<EdvDocCipher> {
  // One codec owns both axes. `buildEdvCodec` resolves this reader's per-epoch
  // keys from the descriptor: writes go under the descriptor's
  // `currentEpoch`, and reads pick the epoch key matching the envelope's
  // recipient kid. A descriptor without epochs is refused fail-closed there.
  let codec: EdvCodec
  try {
    codec = await buildEdvCodec({
      collectionId,
      encryption,
      keys: { keyAgreementKey, keyResolver },
      idDerivation
    })
  } catch (err) {
    if (err instanceof KeyUnwrapError) {
      throw new KeyUnwrapError(
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

  // Decodes the collection's stored metadata and installs the index schema it
  // carries. A codec with no search capability (no blinding key on the
  // descriptor) has nothing to install, so it never decrypts anything. A
  // decode failure -- garbage, an envelope bound to another collection, an
  // epoch this reader cannot unwrap -- propagates: a caller-supplied metadata
  // value that cannot be read is a wiring bug, and must be loud.
  const applyMeta = async (stored: {
    custom?: unknown
  }): Promise<IndexSchema> => {
    const { indexing } = codec
    if (!indexing) {
      return EMPTY_INDEX_SCHEMA
    }
    const schema = readIndexSchema(await codec.decodeMeta(stored))
    indexing.applySchema(schema)
    return schema
  }

  if (meta !== undefined) {
    await applyMeta(meta)
  }

  return {
    applyMeta,
    ...docCipherOverCodec({ codec, collectionId })
  }
}

/**
 * The {@link DocCipher} surface over a resolved EDV codec: parse the codec's
 * `EncodedWrite` to the stored `{ id, envelope, epoch? }` shape and route
 * encrypt/decrypt through it. Shared by the multi-recipient build and the
 * encrypt-only build (whose returned cipher overrides `decrypt` with a typed
 * refusal, since its codec holds no read keys).
 *
 * @param options {object}
 * @param options.codec {ResourceCodec}   the resolved EDV codec
 * @param options.collectionId {string}   labels errors
 * @returns {DocCipher}
 */
function docCipherOverCodec({
  codec,
  collectionId
}: {
  codec: ResourceCodec
  collectionId: string
}): DocCipher {
  // Parses the codec's `EncodedWrite` (id + envelope body bytes) to the stored
  // `{ id, envelope, epoch? }` shape. Shared by the create and update paths.
  const readEncoded = (
    write: CodecWrite
  ): { id: string; envelope: Json; epoch?: string } => {
    // A payload over the codec's single-document threshold answers with a
    // multi-request plan (a document plus chunk resources on a live server),
    // which has no one envelope to hand a replica. This seam is
    // envelope-in/envelope-out, so it refuses the payload instead.
    if (isChunkedWrite(write)) {
      throw new ValidationError(
        `Cannot encrypt this value for collection "${collectionId}": the ` +
          'binary payload exceeds the single-document threshold, so it can ' +
          'only be stored as a document plus chunk resources -- a ' +
          'multi-request server write with no single envelope, which this ' +
          'local-replica cipher does not support. Store a large blob through ' +
          'a Collection handle, or split it before encrypting.'
      )
    }
    const encoded = write
    // Read `envelope` first and never touch `body` when it is there: the EDV
    // codec exposes `body` as a lazy getter, so testing it would serialize the
    // wire bytes this path has no use for.
    const envelope =
      encoded.envelope !== undefined
        ? (encoded.envelope as Json)
        : // A codec that surfaces no object form: parse the wire bytes.
          encoded.body instanceof Uint8Array
          ? (JSON.parse(DECODER.decode(encoded.body)) as Json)
          : undefined
    if (typeof encoded.id !== 'string' || envelope === undefined) {
      throw new Error(
        `EDV encrypt for collection "${collectionId}" returned no id/envelope body.`
      )
    }
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
        current: storedResponse(current)
      })
      return readEncoded(encoded)
    },

    async decrypt({ envelope }: { envelope: Json }) {
      // Routing by the envelope's JWE recipient kids -- including the
      // stale-descriptor `UnknownEpochError` (epoch not on the descriptor)
      // and the membership `KeyUnwrapError` (listed epoch this reader is not
      // a recipient of) -- is owned by the codec's decrypt.
      return (await codec.decode(storedResponse(envelope))) as Json
    }
  }
}

/**
 * Builds the encrypt-only {@link DocCipher} for one encrypted collection from
 * its descriptor alone -- no key-agreement secret anywhere. Encryption in this
 * scheme needs none: every write seals a fresh content-encryption key to the
 * write epoch's public key, reconstructed from the descriptor's `currentEpoch`
 * (the epoch id IS the epoch key's did:key). `decrypt` refuses with
 * {@link EncryptOnlyCipherError} -- the cipher holds no epoch keys, so wiring
 * it into a read path is a bug this surfaces typed rather than as a key miss.
 *
 * The envelope shape is exactly the multi-recipient build's (same recipient
 * template, same epoch stamp and `was` binding), so a reader that IS a
 * recipient opens the result with an ordinary `createEdvDocCipher`. This is
 * the build for a writer holding only a recipient's public half -- e.g.
 * re-sealing a keyring-style record to a recovery code's unlock key the
 * writer can never open.
 *
 * The descriptor is guarded exactly as the reader's build guards it: a
 * future-scheme version and a missing epoch roster are refused fail-closed.
 * No blinded-index schema applies (unwrapping a descriptor's `hmac` key needs
 * a recipient secret), so writes emit no `indexed` entries.
 *
 * @param options {object}
 * @param options.collectionId {string}   the collection id errors are labeled
 *   with
 * @param [options.idDerivation] {'content' | 'random'}   defaults to
 *   `'content'`
 * @param options.encryption {CollectionEncryption}   the collection's
 *   encryption descriptor; must carry the key-epoch roster
 * @returns {Promise<DocCipher>}
 */
export async function createEdvEncryptOnlyDocCipher({
  collectionId,
  idDerivation = 'content',
  encryption
}: {
  collectionId: string
  idDerivation?: 'content' | 'random'
  encryption: CollectionEncryption
}): Promise<DocCipher> {
  const codec = await encryptOnlyEdvCodec({
    collectionId,
    idDerivation,
    encryption
  })
  const { encrypt, encryptUpdate } = docCipherOverCodec({
    codec,
    collectionId
  })
  return {
    encrypt,
    encryptUpdate,
    async decrypt(): Promise<Json> {
      throw new EncryptOnlyCipherError(
        `Cannot decrypt a resource of collection "${collectionId}" with an ` +
          'encrypt-only cipher: it was built from the descriptor alone and ' +
          'holds no epoch keys. Build a reading cipher with ' +
          "createEdvDocCipher and the reader's key-agreement key."
      )
    }
  }
}
