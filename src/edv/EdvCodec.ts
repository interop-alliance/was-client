/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The EDV (Encrypted Data Vault) resource codec and its `EncryptionProvider`
 * factory -- the encrypting half of the codec seam. Bound to an
 * encrypted collection, it encrypts a caller's value into an EDV envelope
 * (`{ id, sequence, indexed, jwe }`) on write and decrypts it on read, so
 * `collection.put(id, obj)` / `collection.get(id)` transparently round-trip
 * ciphertext. Keys live in the wallet and are supplied per-collection by the
 * app's `resolveKeys`; they never reach the server, which stores only opaque
 * JWE envelopes.
 *
 * This reuses `EdvClientCore`'s transport-free `documentCipher` (its public
 * `EdvDocumentCipher` -- the same JWE machinery as the standalone
 * `WasTransport`), but here the WAS Resource CRUD -- the transport role -- is
 * played by core was-client's `Collection`/`Resource` I/O, so the codec is a
 * pure encode/decode transform and needs no transport of its own.
 *
 * Scope (documents-only):
 *
 * - **Restrict-mode ids.** `add()` mints a 128-bit multibase EDV id; the WAS
 *   resource id IS that EDV id. A *create* by `put(id, ...)` accepts only an
 *   EDV-format id -- a human-readable id is rejected (it would leak onto the
 *   URL). Carry a human-readable label inside the encrypted content instead.
 *   An *update* (the write path pre-read a current envelope) accepts the
 *   pre-existing resource id verbatim, whatever its format: the id is already
 *   on the server, so rejecting it prevents no leak -- it would only strand
 *   documents authored by clients with their own id scheme. By default the
 *   minted id is random (`generateId()`, the classic mutable-document model);
 *   with `idDerivation: 'content'` it is content-derived instead -- encrypt
 *   first, then `deriveId()` a truncated SHA-256 of the JWE ciphertext and
 *   stamp it on the envelope -- making the document content-addressed (and so
 *   immutable: an "update" is delete-old + add-new). Both formats pass the same
 *   EDV id check and are indistinguishable on the wire.
 * - **Inline non-JSON as a single JWE.** A `Blob`/`Uint8Array` under the size cap
 *   is encrypted as one document -- stored as a legible UTF-8 string for a
 *   text-family type (else base64) -- with the plaintext content type and the
 *   encoding carried in the document `meta`. A blob over `maxBlobBytes` is
 *   auto-routed by `add()` to the chunked-stream path instead: `encode` returns
 *   a multi-request plan the write path executes, storing one document plus its
 *   chunk resources over a `WasTransport` of the codec's own. That needs the
 *   backend's `chunked-streams` affordance, checked before the first write.
 *   Reads reassemble transparently, so `get()` returns the same `Blob` either
 *   way.
 * - **Enforced sequence (conditional writes).** The codec sets
 *   `conditionalWrites`, so the write path pre-reads the current envelope and
 *   hands it to `encode`: an update advances `sequence` from its prior value and
 *   pins the write to the server's current ETag via `If-Match`, while a fresh
 *   insert (`sequence: 0`) is guarded by `If-None-Match: *`. A caller that
 *   named its own baseline (`put({ ifMatch })`) keeps it: the write is pinned
 *   to the revision the caller last saw rather than to the codec's pre-read, so
 *   a compare-and-swap loop works the same on an encrypted collection as on a
 *   plaintext one. A stale write surfaces as a `PreconditionFailedError` (412)
 *   -- the lost-update guard -- rather than the old advisory
 *   last-writer-wins. Against a backend that does
 *   not advertise `conditional-writes` (no ETag) an update degrades to
 *   advisory, and a create-by-put is refused by the write path (the masked-404
 *   pre-read could otherwise silently clobber; see `upsertResource`).
 * - **Encrypted metadata.** A Resource's user-writable `custom`
 *   (`name`/`tags`, via `setName`/`setTags`/`setMeta`) is
 *   encrypted into an EDV Document envelope with the same `documentCipher` used
 *   for content and stored opaquely under `/meta`; the server never sees
 *   plaintext `name`/`tags`. A reader with the keys decrypts it back
 *   transparently via `meta()`. The Collection-level `/meta` surface
 *   (`Collection.meta()` / `setMeta()`) runs through the same pair, with no
 *   resource id to bind: its envelope binds the collection id
 *   (`was.collection`) instead, and the decode side refuses both a
 *   resource-bound envelope served into that slot and a collection-bound one
 *   served into a resource's.
 */
import { base64, base64urlnopad } from '@scure/base'
import { EdvClientCore, assertDocId } from '@interop/edv-client'
import type {
  IEDVDocument,
  IEncryptedDocument,
  IKeyAgreementKey,
  IKeyResolver,
  IRecipientTemplate
} from '@interop/data-integrity-core'
import type {
  BlindedQuery,
  ChunkedWrite,
  CodecIndexing,
  CodecRequestContext,
  CodecWrite,
  EncryptionProvider,
  IndexSchema,
  ResourceCodec,
  ResponseLike
} from '../codec.js'
import {
  EMPTY_INDEX_SCHEMA,
  assertQueryAttributes
} from '../internal/indexSchema.js'
import {
  EncryptionError,
  EncryptOnlyCipherError,
  IntegrityError,
  KeyUnwrapError,
  NotSupportedError,
  UnknownEpochError,
  ValidationError
} from '../errors.js'
import { blobBytes } from '../internal/blob.js'
import { readEtag, writeHeaders } from '../internal/conditional.js'
import type { WritePrecondition } from '../internal/conditional.js'
import { WasTransport } from './WasTransport.js'
import { isEncryptedEnvelope } from '../sync/envelope.js'
import { resolveEpochKeys } from './epochKeys.js'
import { didKeyResolver, epochKeyIdFor } from './epochCrypto.js'
import { resolveHmacKey } from './hmacKey.js'
import type { BlindingKey } from './hmacKey.js'
import {
  DECODER,
  isBlob,
  isTextContentType,
  readJsonData,
  resolvePayload
} from '../internal/content.js'
import type {
  CollectionEncryption,
  Json,
  ResourceData,
  ResourceMetadataCustom,
  ResourceMetadataCustomInput
} from '../types.js'
import {
  DEFAULT_CONTENT_TYPE,
  EDV_SCHEME_VERSION,
  envelopeBytes
} from './constants.js'

/**
 * Default threshold above which an encrypted binary write is routed to the
 * chunked-stream path instead of being sealed into one document, measured in
 * raw (pre-base64) bytes. It is a routing threshold, not a hard cap: `add()`
 * carries a larger blob as a document plus chunk resources, which needs the
 * backend's `chunked-streams` feature. 512 KiB: a single-document envelope is
 * stored as a JSON-family content type routed through the server's in-memory
 * JSON body parser (a ~1 MiB cap), and a binary payload inflates ~33% inside
 * the document (base64) and again ~33% in the JWE ciphertext (base64url) --
 * ~1.78x total, so 512 KiB raw stays safely under the cap. Raise
 * `maxBlobBytes` against a server with a larger JSON body limit.
 */
const DEFAULT_MAX_BLOB_BYTES = 512 * 1024

/**
 * The `meta.encoding` discriminator a chunked binary document carries: its
 * bytes live in the document's chunk resources, not in `content`. It is sealed
 * inside the JWE payload (the cipher encrypts `meta` alongside `content`), so
 * it is the AEAD-authenticated signal the read side routes on, and it keeps the
 * decrypted document self-describing alongside `'utf-8'` and `'base64'`.
 */
const CHUNKED_ENCODING = 'chunked'

/**
 * Builds the `WasTransport` a codec's chunked-stream paths drive, over the
 * signed requester core of one request. Injected into {@link EdvCodec} by the
 * build that knows where the Collection lives (a Space on a server); a codec
 * built without one has no server behind it and refuses the chunked path.
 *
 * @param options {object}
 * @param options.context {CodecRequestContext}   the signed-request context
 * @param [options.documentHeaders] {Record<string, string>}   extra headers
 *   for document writes (the `Key-Epoch` stamp the codec seam applies)
 * @returns {WasTransport}
 */
export type CodecTransportFactory = (options: {
  context: CodecRequestContext
  documentHeaders?: Record<string, string>
}) => WasTransport

/**
 * Builds the transport factory for a Collection reachable over WAS: the
 * codec's route to its own document and chunk resources on the server.
 *
 * @param options {object}
 * @param options.spaceId {string}        the Space holding the Collection
 * @param options.collectionId {string}   the Collection
 * @param options.contentType {string}    stored envelope content type
 * @returns {CodecTransportFactory}
 */
export function wasTransportFactory({
  spaceId,
  collectionId,
  contentType
}: {
  spaceId: string
  collectionId: string
  contentType: string
}): CodecTransportFactory {
  return ({ context, documentHeaders }) =>
    new WasTransport({
      was: { request: input => context.request(input) },
      spaceId,
      collectionId,
      contentType,
      features: context.features,
      ...(documentHeaders !== undefined && { documentHeaders })
    })
}

/**
 * A shared strict UTF-8 decoder used to test whether a non-JSON payload is
 * valid UTF-8 (so it can be stored legibly as text rather than base64).
 * `fatal: true` makes `decode` throw on malformed input; `ignoreBOM: true`
 * keeps a leading BOM (`EF BB BF`) in the decoded string -- without it the
 * decoder silently strips those 3 bytes and the text round-trip is no longer
 * byte-exact. The decoder is stateless across non-streaming calls, so one
 * instance is reused.
 */
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

/**
 * Builds the AEAD-bound `was` protected-header parameter: the scheme version
 * and key epoch always, and then exactly one slot marker -- the resource id
 * when it is known at encrypt time (absent for a content-derived id, which
 * does not exist until after encryption), or the collection id for the
 * Collection metadata envelope, which belongs to no resource. The one shape
 * both the content and the metadata write paths bind.
 *
 * @param options {object}
 * @param options.version {number}   the EDV-over-WAS scheme version
 * @param [options.resource] {string}   the resource id the envelope is bound to
 * @param [options.collection] {string}   the collection id the envelope is
 *   bound to (the Collection metadata slot only, never alongside `resource`)
 * @param [options.epoch] {string}   the key epoch the write encrypts under
 * @returns {{ v: number, resource?: string, collection?: string,
 *   epoch?: string }}
 */
function wasParam({
  version,
  resource,
  collection,
  epoch
}: {
  version: number
  resource?: string
  collection?: string
  epoch?: string
}): { v: number; resource?: string; collection?: string; epoch?: string } {
  return {
    v: version,
    ...(resource !== undefined && { resource }),
    ...(collection !== undefined && { collection }),
    ...(epoch !== undefined && { epoch })
  }
}

/**
 * Whether a decrypt error means "this candidate key does not open the envelope"
 * (so the loop should try the next key) rather than an integrity failure. True
 * for the upstream typed key-miss error -- `@interop/minimal-cipher` /
 * `@interop/edv-client` raise a `KeyMissError` (the null-CEK unwrap path and the
 * kid-mismatch path) when a candidate key is simply the wrong or a rotated key,
 * not a corrupted envelope. It is matched by `err.name === 'KeyMissError'`
 * rather than `instanceof`: name-dispatch survives pnpm installing two copies of
 * the cipher package (a second copy's `KeyMissError` is a distinct class but
 * carries the same `name`), so was-client need not import the class at all.
 *
 * Also true for a {@link KeyUnwrapError} raised by a candidate itself -- a lazy
 * epoch key whose recipient entry turned out corrupt when its first decrypt
 * forced the unwrap (see `lazyEpochKey`): that says nothing about the stored
 * envelope, so the loop must move on to the next candidate rather than report
 * tampering. Every other error means the key DID select a recipient and unwrap,
 * but the content's AEAD tag did not verify -- a data-integrity failure
 * (WebCrypto's `OperationError` in browsers, Node's "unable to authenticate
 * data") -- which must surface as an {@link IntegrityError}, not be masked as a
 * key miss.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isKeyMiss(err: unknown): boolean {
  return (
    err instanceof KeyUnwrapError ||
    (err instanceof Error && err.name === 'KeyMissError')
  )
}

/**
 * Extracts the JWE recipient key ids (`kid`) a stored envelope names (an epoch
 * envelope carries one kid: the epoch key id). Returns `[]` for a malformed
 * recipient shape, so routing falls through to letting the cipher surface its
 * own typed decrypt error.
 *
 * @param encryptedDoc {IEncryptedDocument}
 * @returns {string[]}
 */
function envelopeRecipientKids(encryptedDoc: IEncryptedDocument): string[] {
  const jwe = encryptedDoc.jwe as { recipients?: unknown } | null | undefined
  if (jwe === null || typeof jwe !== 'object') {
    return []
  }
  const recipients = jwe.recipients
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
 * A {@link ResourceCodec} that encrypts on write and decrypts on read using an
 * `EdvClientCore`'s public `documentCipher`. One instance is bound per encrypted
 * collection handle.
 */
export class EdvCodec implements ResourceCodec {
  readonly conditionalWrites = true

  readonly #edv: EdvClientCore
  /**
   * The static JWE recipient descriptor every write encrypts to (the write
   * key's `{ kid, alg }` header; the ephemeral `epk` is minted later inside
   * `encrypt`). Deterministic per codec, so computed once here instead of per
   * write.
   */
  readonly #recipients: IRecipientTemplate[]
  readonly #readKeys: IKeyAgreementKey[]
  /**
   * The key-epoch id writes stamp (the descriptor's `currentEpoch`). Every
   * envelope seals to an epoch key and binds this id as `was.epoch`
   * (epoch-from-birth: there is no epoch-less encrypted collection).
   */
  readonly #writeEpoch: string
  readonly #contentType: string
  /**
   * The size, in raw bytes, above which a binary write is routed to the
   * chunked-stream path instead of being sealed into one document. A routing
   * threshold, not a hard cap.
   */
  readonly #maxBlobBytes: number
  /**
   * The size of each encrypted chunk a routed write emits, or `undefined` to
   * take the EDV core's default (1 MiB). One chunk is one upload, so it has to
   * stay under the backend's `maxUploadBytes`; nothing here can check that (the
   * feature probe answers affordance tokens, not the backend's constraints), so
   * a chunk over the limit surfaces as the server's 413.
   */
  readonly #chunkSize?: number
  readonly #idDerivation: 'random' | 'content'
  /**
   * The EDV-over-WAS scheme version this codec binds into every envelope's
   * `was.v` protected-header parameter (the descriptor's `version`,
   * {@link EDV_SCHEME_VERSION} when absent). Read side rejects an envelope
   * stamped with a greater version.
   */
  readonly #version: number
  /**
   * Builds the `WasTransport` the chunked-stream paths drive, or `undefined`
   * on a codec with no server behind it (the local-replica cipher builds).
   * The factory is the codec's only way to address a resource by path, so a
   * codec built without one cannot reach the network at all -- there is no id
   * it could fabricate a route from.
   */
  readonly #transportFactory?: CodecTransportFactory
  /**
   * The id of the Collection this codec was built for. It is bound into the
   * Collection metadata envelope's `was.collection` on write and required to
   * match on read, and it labels decrypt-routing errors
   * ({@link UnknownEpochError}).
   */
  readonly #collectionId: string
  /**
   * The id of every epoch the descriptor lists -- held by this reader or not.
   * Decrypt routing uses it to tell the two unroutable-envelope cases apart:
   * an envelope kid whose epoch is listed here but matches no candidate key
   * means this reader is not a recipient of that epoch
   * ({@link KeyUnwrapError}); a kid whose epoch is not listed at all means the
   * descriptor this codec was built from has never seen the epoch
   * ({@link UnknownEpochError} -- the stale-descriptor signal).
   */
  readonly #epochIds: ReadonlySet<string>
  /**
   * The collection's blinded-index key, or `null` where the collection
   * declares none. It blinds attribute names and values both on write (the
   * `indexed` entries an envelope carries) and on query, so equal plaintext
   * yields equal tokens and the server can match without learning either.
   */
  readonly #blindingKey: BlindingKey | null
  /**
   * The collection's persisted index schema, as last applied through
   * {@link indexing}. Empty until the schema is loaded (at codec resolution) or
   * a `declareIndex` installs one -- and while it is empty the write seam emits
   * no `indexed` entries, since there is nothing declared to index.
   */
  #schema: IndexSchema = EMPTY_INDEX_SCHEMA
  /**
   * The scheme-agnostic search capability handed to the handle layer, present
   * exactly when this collection declares a blinding key.
   */
  readonly #indexing?: CodecIndexing

  /**
   * @param options {object}
   * @param options.edv {EdvClientCore}             holds the cipher + key resolver
   * @param options.keyAgreementKey {IKeyAgreementKey}   the key writes encrypt
   *   under: the reconstructed `currentEpoch` key pair.
   * @param options.readKeys {IKeyAgreementKey[]}   the candidate keys a read
   *   may decrypt with: one per epoch this reader can unwrap. A read selects
   *   the one whose id matches the stored envelope's recipient, so a resource
   *   written under an older epoch still decrypts.
   * @param options.writeEpoch {string}   the key-epoch id to stamp on writes
   *   (the `currentEpoch`), surfaced as {@link EncodedWrite.epoch} and bound
   *   into every envelope's `was.epoch`, which the decode side checks against
   *   the decrypting key's epoch unconditionally.
   * @param options.contentType {string}            stored envelope content type
   * @param options.maxBlobBytes {number}   the size above which a binary write
   *   is routed to the chunked-stream path instead of one document
   * @param [options.chunkSize] {number}   the size of each encrypted chunk a
   *   routed write emits (defaults to the EDV core's 1 MiB). One chunk is one
   *   upload, so it must stay under the backend's `maxUploadBytes`; that
   *   constraint is not advertised through the feature probe, so it is the
   *   caller's to respect (see `createEdvEncryption`)
   * @param options.idDerivation {string}           how `add()` mints a document
   *   id: `'random'` (classic `generateId()`) or `'content'` (derived from the
   *   JWE ciphertext, content-addressed)
   * @param [options.version] {number}   the EDV-over-WAS scheme version to bind
   *   into each envelope's `was.v` (defaults to {@link EDV_SCHEME_VERSION})
   * @param [options.transportFactory] {CodecTransportFactory}   builds the
   *   transport the chunked-stream path drives; omitted by a build with no
   *   server behind it, which then refuses that path
   * @param options.collectionId {string}   the Collection this codec reads and
   *   writes: bound into the Collection metadata envelope's `was.collection`
   *   (and checked on read), and it labels decrypt-routing errors
   * @param options.epochIds {string[]}   the id of every epoch the descriptor
   *   lists (held by this reader or not); decrypt routing checks it to tell a
   *   not-a-recipient envelope apart from a stale-descriptor one
   * @param [options.hmac] {BlindingKey}   the collection's blinded-index key,
   *   where it declares one
   */
  constructor({
    edv,
    keyAgreementKey,
    readKeys,
    writeEpoch,
    contentType,
    maxBlobBytes,
    chunkSize,
    idDerivation,
    version,
    transportFactory,
    collectionId,
    epochIds,
    hmac
  }: {
    edv: EdvClientCore
    keyAgreementKey: IKeyAgreementKey
    readKeys: IKeyAgreementKey[]
    writeEpoch: string
    contentType: string
    maxBlobBytes: number
    chunkSize?: number
    idDerivation: 'random' | 'content'
    version?: number
    transportFactory?: CodecTransportFactory
    collectionId: string
    epochIds: string[]
    hmac?: BlindingKey | null
  }) {
    this.#edv = edv
    this.#recipients =
      edv.documentCipher.createDefaultRecipients(keyAgreementKey)
    this.#readKeys = readKeys
    this.#writeEpoch = writeEpoch
    this.#contentType = contentType
    this.#maxBlobBytes = maxBlobBytes
    this.#chunkSize = chunkSize
    this.#idDerivation = idDerivation
    this.#version = version ?? EDV_SCHEME_VERSION
    this.#transportFactory = transportFactory
    this.#collectionId = collectionId
    this.#epochIds = new Set(epochIds)
    this.#blindingKey = hmac ?? null
    if (this.#blindingKey !== null) {
      this.#indexing = {
        applySchema: (schema: IndexSchema): void => this.#applySchema(schema),
        schema: (): IndexSchema => this.#schema,
        buildQuery: (input: {
          equals?: Record<string, unknown> | Array<Record<string, unknown>>
          has?: string | string[]
        }): Promise<BlindedQuery> => this.#buildQuery(input)
      }
    }
  }

  /**
   * The collection's blinded-index key, or `null` where it declares none.
   *
   * @returns {BlindingKey | null}
   */
  get blindingKey(): BlindingKey | null {
    return this.#blindingKey
  }

  /**
   * @inheritdoc
   */
  get indexing(): CodecIndexing | undefined {
    return this.#indexing
  }

  /**
   * Installs the persisted schema: records it, then registers each declared
   * attribute with the EDV core, whose index helper is what actually blinds
   * attributes on write and builds query terms. Registration is idempotent, so
   * re-applying the same schema (or a superset of it) is safe.
   *
   * @param schema {IndexSchema}
   * @returns {void}
   */
  #applySchema(schema: IndexSchema): void {
    this.#schema = schema
    for (const entry of schema.indexes) {
      this.#edv.ensureIndex({
        attribute: entry.attribute,
        unique: entry.unique === true
      })
    }
  }

  /**
   * Blinds a caller's search terms with the collection's blinding key. Refuses
   * an attribute the persisted schema does not declare (see
   * `assertQueryAttributes`), and refuses a query that blinded to no terms at
   * all -- the residual footgun the name check cannot see, e.g. a compound
   * index queried by something other than a leading prefix of its members.
   *
   * Reached only through the `indexing` adapter, which exists only on a codec
   * whose (readonly) blinding key is non-null, so the key is non-null here.
   *
   * @param input {object}
   * @param [input.equals] {object | object[]}
   * @param [input.has] {string | string[]}
   * @returns {Promise<BlindedQuery>}
   */
  async #buildQuery({
    equals,
    has
  }: {
    equals?: Record<string, unknown> | Array<Record<string, unknown>>
    has?: string | string[]
  }): Promise<BlindedQuery> {
    const hmac = this.#blindingKey!
    assertQueryAttributes({ schema: this.#schema, equals, has })
    const query = (await this.#edv.indexHelper.buildQuery({
      hmac,
      equals,
      has
    })) as BlindedQuery
    const termless =
      (query.equals?.every(term => Object.keys(term).length === 0) ?? false) ||
      query.has?.length === 0
    if (termless) {
      throw new ValidationError(
        'This search blinded to no index terms, so it would match nothing. ' +
          'A compound index can only be queried by a leading prefix of its ' +
          "attributes; check the collection's declared indexes with " +
          'indexes().'
      )
    }
    return query
  }

  /**
   * @inheritdoc
   */
  async encode({
    id,
    data,
    contentType,
    current,
    precondition
  }: {
    id?: string
    data: ResourceData
    contentType?: string
    current?: ResponseLike | null
    precondition?: WritePrecondition
  }): Promise<CodecWrite> {
    if (id !== undefined && !current) {
      try {
        // A full multibase decode + multihash length check (the same assertion
        // the EDV core applies), tighter than a charset heuristic: it rejects a
        // human-readable id, which would otherwise leak onto the URL. Only
        // creates are guarded: on an update (`current` present, pre-read from
        // the server) the id IS already the server resource id, so refusing it
        // prevents no leak -- it only blocks editing a document another client
        // authored under its own id scheme (e.g. a legacy uuid row).
        assertDocId(id)
      } catch {
        throw new ValidationError(
          `Cannot write a human-readable id "${id}" to an encrypted ` +
            'collection -- it would leak onto the URL. Use add() to mint an ' +
            'EDV document id, or carry the human-readable label inside the ' +
            'encrypted content.'
        )
      }
    }
    // `add()` (no caller id): mint a random id up front, or -- in `'content'`
    // mode -- leave it unset and stamp the content-derived id after encryption
    // (the id is a function of the ciphertext, which does not exist yet).
    let docId =
      id ??
      (this.#idDerivation === 'content'
        ? undefined
        : ((await this.#edv.generateId()) as string))
    const parts = await this.#toDocument(data, contentType, docId)
    if (parts.kind === 'chunked') {
      if (docId === undefined) {
        throw new ValidationError(
          `Encrypted binary write of ${parts.size} bytes exceeds the ` +
            `single-document threshold of ${this.#maxBlobBytes} bytes, so it ` +
            'must be stored as a document plus chunk resources -- which a ' +
            "content-addressed collection (idDerivation: 'content') cannot " +
            'do: the document is written twice (once to reserve it, once to ' +
            'record the chunk count), so no single ciphertext derives its id. ' +
            'Store large blobs in a random-id collection, or keep the payload ' +
            'under the threshold.'
        )
      }
      return this.#chunkedWrite({
        id: docId,
        stream: parts.stream,
        meta: parts.meta
      })
    }
    const { content, meta } = parts

    // When the write path pre-read a current envelope, advance `sequence` from
    // its prior value (`encrypt({ update: true })` increments it) and pin the
    // write to the server's current ETag with `If-Match`. With no prior envelope
    // this is a fresh insert (`sequence: 0`) guarded by `If-None-Match: *`
    // (create-if-absent), so a concurrent first writer cannot be clobbered.
    let priorDoc: IEncryptedDocument | null = null
    if (current) {
      const read = await readJsonData(current)
      this.#assertEnvelope(read, 'update')
      priorDoc = read
    }

    const { documentCipher } = this.#edv
    const encrypted = await documentCipher.encrypt({
      doc: {
        ...(docId !== undefined && { id: docId }),
        content,
        // `content` and `meta` are both sealed inside the JWE; `meta` carries
        // the plaintext content type and the inline-encoding discriminator,
        // taken fresh from this write (the new type/encoding wins on update).
        meta,
        ...(priorDoc && { sequence: priorDoc.sequence }),
        // Carry the prior envelope's blinded `indexed` entries into the
        // update. With no blinding key edv-client stores `doc.indexed`
        // verbatim; omitting it would replace the entries with `[]` and
        // silently drop the record from `find()`. With a blinding key the
        // entries are recomputed from the schema and this copy is the prior
        // state that recomputation updates.
        ...(priorDoc?.indexed !== undefined && { indexed: priorDoc.indexed })
      },
      // Bind an AEAD-authenticated `was` parameter into the JWE protected
      // header: the scheme version, the resource id when known at encrypt time
      // (omitted for a content-derived id, which does not exist until after
      // encryption), and the write epoch. A server that swaps two envelopes
      // between ids (or replays one under a rolled-back epoch) is then detected
      // on decrypt.
      //
      // Blind the declared attributes into the envelope's cleartext `indexed`
      // entries, so the server can match a search without decrypting anything.
      // Absent a blinding key or a declared attribute there is nothing to
      // index, and the prior entries passed above are stored verbatim.
      ...this.#sealParams({
        ...(docId !== undefined && { resource: docId }),
        hmac: this.#writeBlindingKey()
      }),
      update: priorDoc !== null
    })
    if (docId === undefined) {
      // Encrypt-then-stamp: the id lives in the cleartext envelope, outside the
      // JWE, so deriving it from the ciphertext and setting it afterwards does
      // not invalidate the envelope.
      docId = await documentCipher.deriveId({ jwe: encrypted.jwe })
      encrypted.id = docId
    }
    // Serialized on first read of `body` and kept for any later read, so the
    // wire bytes are built once per write and only when someone asks for them.
    let bytes: Uint8Array | undefined
    return {
      id: docId,
      // Lazy: the HTTP write path reads `body` and pays the serialization, and
      // a local-replica consumer reads `envelope` instead and pays nothing.
      // Enumerable and forced by a spread or a structured clone, so a consumer
      // that copies this object still sees the same bytes under the same key.
      get body() {
        bytes ??= envelopeBytes(encrypted)
        return bytes
      },
      // The same envelope in object form, so a consumer holding a local replica
      // (the sync `DocCipher`) need not force `body` and re-parse the bytes it
      // was just serialized from. `body` remains the wire truth.
      envelope: encrypted,
      contentType: this.#contentType,
      // Surface the plaintext content type (the server-opaque envelope type
      // stays `contentType`) so `add()` reports the real resource type.
      resourceContentType: meta.contentType as string,
      // The caller's own compare-and-swap baseline wins when they named one:
      // an `If-Match` derived from this codec's pre-read would pin the write to
      // current server state rather than to the revision the caller last saw,
      // which silently turns a lost-update guard into last-write-wins. The
      // write path has already checked the caller's baseline against the
      // pre-read, so the two agree by the time this runs.
      //
      // Otherwise pin an update to the server's current ETag and guard a fresh
      // insert with create-if-absent. An update's `If-Match` carries a
      // server-provided ETag, so it degrades to an advisory write against a
      // backend without the conditional-writes feature (the ETag is absent). A
      // fresh insert's `If-None-Match: *` needs no server-provided validator
      // and so is emitted unconditionally by design -- it expresses the
      // insert's intent (create-only-if-absent). A backend that does not honor
      // it would ignore it, so the write path refuses the
      // insert-after-null-pre-read up front on such a backend (see
      // `upsertResource`) -- a masked-404 pre-read must not silently overwrite
      // an existing document there.
      ...(precondition ??
        (priorDoc
          ? { ifMatch: readEtag(current ?? null) }
          : { ifNoneMatch: true })),
      // Stamp the key epoch this write encrypted under (the `currentEpoch`), so
      // the server records it and a reader can pick the epoch key.
      epoch: this.#writeEpoch
    }
  }

  /**
   * Builds the `WasTransport` the chunked-stream paths drive, over the signed
   * requester core supplied and this codec's injected factory. The handle's
   * memoized feature probe is passed straight through, so the transport's own
   * affordance gates cost no extra descriptor read.
   *
   * @param context {CodecRequestContext}
   * @param [documentHeaders] {Record<string, string>}   extra headers for
   *   document writes (the `Key-Epoch` stamp the codec seam applies)
   * @returns {WasTransport}
   */
  #transportFor(
    context: CodecRequestContext,
    documentHeaders?: Record<string, string>
  ): WasTransport {
    if (this.#transportFactory === undefined) {
      throw new NotSupportedError(
        `Collection "${this.#collectionId}" has no server behind it: this ` +
          'codec was built for a local replica and holds no route to address ' +
          'a document and its chunk resources with. Chunked encrypted blobs ' +
          'can only be read and written through a Collection handle bound to ' +
          'a Space.'
      )
    }
    return this.#transportFactory({ context, documentHeaders })
  }

  /**
   * Refuses the operation unless the collection's backend advertises the
   * `chunked-streams` affordance. Checked before the first write, so an
   * unsupported server never ends up holding a document stub with no chunks.
   *
   * @param context {CodecRequestContext}
   * @param what {string}   the operation, for the message
   * @returns {Promise<void>}
   */
  async #assertChunkedStreams(
    context: CodecRequestContext,
    what: string
  ): Promise<void> {
    if (await context.features.has('chunked-streams')) {
      return
    }
    // "No features" has two causes, and only one of them is about the server's
    // capabilities: a descriptor that was read and lists no `chunked-streams`,
    // versus a descriptor that could not be read at all (no backend descriptor
    // endpoint, a deleted collection, or a capability that cannot read it --
    // WAS masks unauthorized reads as 404). Name the one that applies, so a
    // capable server whose collection is gone does not look incapable.
    if (await context.features.descriptorAbsent()) {
      throw new NotSupportedError(
        `${what} needs the collection's backend to advertise the ` +
          `'chunked-streams' feature, but the backend descriptor could not be ` +
          'read at all: the collection may not exist, or this capability may ' +
          'not be able to read its descriptor. Confirm the collection and the ' +
          'capability, then retry.'
      )
    }
    throw new NotSupportedError(
      `${what} needs the collection's backend to advertise the ` +
        `'chunked-streams' feature, which it does not. Store the blob in a ` +
        'collection on a backend that supports chunked streams, or keep the ' +
        `payload under the ${this.#maxBlobBytes}-byte single-document ` +
        "threshold (raise it with the provider's `maxBlobBytes` where the " +
        'server accepts a larger body).'
    )
  }

  /**
   * The plan for a binary payload over the single-document threshold: one EDV
   * document plus its chunk resources, written by `EdvClientCore.insert({ doc,
   * stream, transport })` over a transport built from the write context. The
   * document id is minted before the plan is returned, so the caller can report
   * it without waiting for the write.
   *
   * The `was` binding, the recipients and the write epoch are exactly the
   * single-document path's, and `additionalProtectedParams` carries the binding
   * into both the document envelope and every chunk's AAD. `content` stays
   * empty: the bytes are the chunks, and `meta` records the plaintext content
   * type plus the chunked encoding discriminator so a read reconstructs the
   * same `Blob` a small binary read returns. `meta` is sealed inside the JWE
   * payload, so that discriminator is what the read side routes on: a server
   * cannot mint it, and cannot suppress it to hide the chunks either.
   *
   * The write is two-phase (`EdvClientCore.insert` writes the document, then
   * streams the chunks), so a failure partway leaves a document stub whose
   * sealed stream state is still `{ pending: true }` -- undecryptable, listed,
   * and never re-used, since a retry mints a fresh id. The plan therefore
   * compensates: if the document was written and the write then failed, it
   * best-effort deletes the stub before rethrowing.
   *
   * @param options {object}
   * @param options.id {string}                        the minted document id
   * @param options.stream {ReadableStream<Uint8Array>}   the payload, as the
   *   stream the EDV core re-chunks (never buffered whole by this codec)
   * @param options.meta {Record<string, unknown>}     the document meta to seal
   * @returns {ChunkedWrite}
   */
  #chunkedWrite({
    id,
    stream,
    meta
  }: {
    id: string
    stream: ReadableStream<Uint8Array>
    meta: Record<string, unknown>
  }): ChunkedWrite {
    return {
      chunked: true,
      id,
      resourceContentType: meta.contentType as string,
      // What the scheme-agnostic write path appends when it refuses this plan
      // for a write by id: only this codec knows why the payload needs several
      // requests, and which low-level API writes one directly.
      guidance:
        'This payload is too large for a single encrypted document, so it is ' +
        'stored as a document plus chunk resources. Drive the write yourself ' +
        'with `EdvClientCore.update({ doc, stream, transport })` over a ' +
        '`WasTransport`, against a server whose backend advertises the ' +
        "'chunked-streams' feature.",
      execute: async (context: CodecRequestContext) => {
        await this.#assertChunkedStreams(context, 'Writing a large blob')
        // The EDV core owns the write and swallows the responses, so the
        // transport reports the document write it made: whether one landed at
        // all (the cleanup decision below) and the validator the server acked
        // it with.
        const transport = this.#transportFor(
          context,
          writeHeaders({ epoch: this.#writeEpoch })
        )
        try {
          await this.#edv.insert({
            doc: { id, content: {}, meta },
            stream,
            ...(this.#chunkSize !== undefined && {
              chunkSize: this.#chunkSize
            }),
            ...this.#sealParams({
              resource: id,
              hmac: this.#writeBlindingKey()
            }),
            transport
          })
        } catch (err) {
          throw await this.#chunkedWriteFailed({ err, id, transport })
        }
        const etag = transport.lastDocumentWrite?.etag
        return { id, ...(etag !== undefined && { etag }) }
      }
    }
  }

  /**
   * Compensates a failed chunked write and builds the error to rethrow. The
   * document stub is deleted only when the transport reports it actually wrote
   * one: a write that failed before that (the id is freshly minted, so this is
   * a server or network failure, not a collision) must not delete a resource
   * this write never created. The delete is best effort -- it is a cleanup, and
   * its own failure must not mask the failure that caused it -- so its outcome
   * only shapes the message.
   *
   * @param options {object}
   * @param options.err {unknown}   the failure from the chunked write
   * @param options.id {string}     the document id the write minted
   * @param options.transport {WasTransport}   the transport the write ran on
   * @returns {Promise<Error>}   the error to throw, carrying `err` as its cause
   */
  async #chunkedWriteFailed({
    err,
    id,
    transport
  }: {
    err: unknown
    id: string
    transport: WasTransport
  }): Promise<Error> {
    if (transport.lastDocumentWrite === undefined) {
      return err instanceof Error ? err : new Error(String(err))
    }
    let removed = true
    try {
      await transport.deleteDocument({ id })
    } catch {
      removed = false
    }
    return new EncryptionError(
      `The chunked encrypted write of resource "${id}" failed partway: its ` +
        'document was written but its chunks were not, so the stored ' +
        'document cannot be read. ' +
        (removed
          ? 'The incomplete document was deleted; retry the write.'
          : 'The incomplete document could NOT be deleted and is still ' +
            'stored; delete it and retry the write.'),
      { cause: err }
    )
  }

  /**
   * The blinding key a content write should index with: the collection's key
   * once the applied schema declares at least one attribute, else `undefined`
   * (the cipher then computes no `indexed` entries and passes any already
   * stored on the prior envelope through unchanged).
   *
   * @returns {BlindingKey | undefined}
   */
  #writeBlindingKey(): BlindingKey | undefined {
    if (this.#blindingKey === null || this.#schema.indexes.length === 0) {
      return undefined
    }
    return this.#blindingKey
  }

  /**
   * The recipient/AAD wiring every write seals with: the epoch recipients, the
   * key resolver that resolves them, the blinding key the caller decided on,
   * and the AEAD-bound `was` protected-header parameter carrying this codec's
   * scheme version, the write epoch, and the caller's slot marker. Spread into
   * each `encrypt`/`insert` call so the single-document, chunked and metadata
   * write paths cannot drift apart.
   *
   * @param options {object}
   * @param [options.resource] {string}   the resource id the envelope binds
   *   (absent for a content-derived id, which does not exist until after
   *   encryption)
   * @param [options.collection] {string}   the collection id the envelope binds
   *   (the Collection metadata slot only, never alongside `resource`)
   * @param options.hmac {BlindingKey | undefined}   the blinding key to index
   *   with, or `undefined` to emit no blinded entries
   * @returns {{ recipients: IRecipientTemplate[], keyResolver: IKeyResolver,
   *   hmac: BlindingKey, additionalProtectedParams: { was: object } }}
   */
  #sealParams({
    resource,
    collection,
    hmac
  }: {
    resource?: string
    collection?: string
    hmac: BlindingKey | undefined
  }) {
    const was = wasParam({
      version: this.#version,
      ...(resource !== undefined && { resource }),
      ...(collection !== undefined && { collection }),
      epoch: this.#writeEpoch
    })
    return {
      recipients: this.#recipients,
      keyResolver: this.#edv.keyResolver,
      hmac,
      additionalProtectedParams: { was }
    }
  }

  /**
   * @inheritdoc
   */
  async decode(
    response: ResponseLike,
    expectedId?: string,
    context?: CodecRequestContext
  ): Promise<Json | Blob> {
    const stored = await readJsonData(response)
    const decrypted = await this.#openEnvelope({ doc: stored, expectedId })
    // A chunked document's bytes live in its chunk resources. Both routing
    // inputs are AEAD-authenticated, never the cleartext copies on the
    // envelope: the `meta.encoding` discriminator sealed in the JWE payload
    // decides that this IS a chunked document (a server cannot bolt a
    // cleartext `stream` onto an ordinary document to mask its sealed
    // content), and the sealed `stream.chunks` count then says how many chunks
    // to fetch (a server cannot lower it to truncate the read). A sealed
    // discriminator with no sealed count is an interrupted write, whose state
    // is still `{ pending: true }`: it fails loudly rather than decoding to an
    // empty document.
    if (decrypted.meta?.encoding === CHUNKED_ENCODING) {
      return this.#readChunked({
        // Address the chunk resources by the AEAD-bound `was.resource` id, not
        // by the envelope's cleartext `id`: a server that serves document A's
        // authentic envelope with the cleartext id swapped to B would
        // otherwise have the read fetch (and cleanly decrypt) B's chunks,
        // exactly the envelope swap the `was.resource` binding exists to
        // detect.
        id: decrypted.resourceId,
        chunks: (decrypted.stream as { chunks?: unknown } | undefined)?.chunks,
        meta: decrypted.meta,
        keyId: decrypted.keyId,
        context
      })
    }
    return this.#fromDocument(decrypted.content, decrypted.meta)
  }

  /**
   * Reassembles a chunked binary document: drives `EdvClientCore.getStream`
   * over a transport built from the read context, buffers the decrypt stream,
   * and returns the same `Blob` a small binary read returns.
   *
   * Only AEAD-authenticated inputs are trusted -- the sealed chunk count and
   * the `was.resource` id the envelope is bound to, never the envelope's
   * cleartext `id` -- and the decrypt uses the very key that opened the
   * document envelope, so a chunk sealed to some other epoch fails to
   * authenticate rather than being accepted.
   *
   * @param options {object}
   * @param [options.id] {string}   the AEAD-bound resource id (= WAS resource
   *   id, the parent of the chunk resources)
   * @param options.chunks {unknown}   the sealed chunk count
   * @param [options.meta] {Record<string, unknown>}   the decrypted meta
   * @param options.keyId {string}   the id of the key that decrypted the
   *   document envelope
   * @param [options.context] {CodecRequestContext}   the signed-request context
   * @returns {Promise<Blob>}
   */
  async #readChunked({
    id,
    chunks,
    meta,
    keyId,
    context
  }: {
    id?: string
    chunks: unknown
    meta?: Record<string, unknown>
    keyId: string
    context?: CodecRequestContext
  }): Promise<Blob> {
    if (typeof chunks !== 'number') {
      throw new EncryptionError(
        'Cannot read this resource: it is a chunked encrypted blob whose ' +
          'sealed stream state records no chunk count, so the write that ' +
          'created it never completed. Re-upload the blob.'
      )
    }
    if (context === undefined) {
      throw new EncryptionError(
        'Cannot read this resource: it is a chunked encrypted blob, whose ' +
          'bytes live in separate chunk resources, and this caller supplied no ' +
          'request context to fetch them with. Read it through a Resource or ' +
          'Collection handle (`resource.get()`), which supplies one.'
      )
    }
    if (id === undefined) {
      throw new EncryptionError(
        'Cannot read this resource: the stored chunked document binds no ' +
          '`was.resource` id, so its chunk resources cannot be addressed. ' +
          "Only the envelope's AEAD-bound id may address them -- the cleartext " +
          'id on the envelope is server-controlled and could point the read at ' +
          "another document's chunks."
      )
    }
    await this.#assertChunkedStreams(context, 'Reading a large blob')
    const keyAgreementKey = this.#readKeys.find(key => key.id === keyId)
    const stream = (await this.#edv.getStream({
      doc: { id, stream: { chunks } } as IEDVDocument,
      keyAgreementKey,
      transport: this.#transportFor(context)
    })) as ReadableStream<Uint8Array>
    const contentType =
      typeof meta?.contentType === 'string' ? meta.contentType : undefined
    return streamToBlob({
      stream,
      ...(contentType !== undefined && { type: contentType })
    })
  }

  /**
   * Opens a stored envelope: asserts it IS an EDV envelope, decrypts it with
   * whichever read key its JWE recipient names, and only then verifies the
   * AEAD-authenticated `was` binding (decrypt success is what proves the
   * protected header authentic, so the order is load-bearing). The one opening
   * shared by {@link decode} and {@link decodeMeta}.
   *
   * @param options {object}
   * @param options.doc {unknown}   the stored document read from the server
   * @param [options.expectedId] {string}   the resource id the read targeted
   * @param [options.collectionSlot] {boolean}   the read addressed the
   *   Collection metadata slot, which belongs to no resource: an envelope bound
   *   to a resource id is refused there, and one bound to this Collection's id
   *   is required (see {@link _verifyBinding}). Set only by the
   *   Collection-level metadata read
   * @returns {Promise<object>}   the decrypted document (`content`, `meta`, the
   *   AEAD-authenticated `stream` state where one was sealed, `keyId`, and the
   *   AEAD-bound `resourceId` the envelope declares, where it binds one)
   */
  async #openEnvelope({
    doc,
    expectedId,
    collectionSlot
  }: {
    doc: unknown
    expectedId?: string
    collectionSlot?: boolean
  }): Promise<{
    content?: unknown
    meta?: Record<string, unknown>
    stream?: unknown
    keyId: string
    resourceId?: string
  }> {
    this.#assertEnvelope(doc, 'read')
    const decrypted = await this.#decrypt(doc)
    const resourceId = await this.#verifyBinding({
      jwe: doc.jwe,
      expectedId,
      collectionSlot,
      keyId: decrypted.keyId
    })
    return { ...decrypted, ...(resourceId !== undefined && { resourceId }) }
  }

  /**
   * Decrypts a stored EDV envelope, selecting which read key to use by matching
   * the envelope's JWE recipient `kid` against this reader's candidate keys
   * (one per epoch it can unwrap). A resource written under an older epoch
   * selects that epoch's key, so history stays readable.
   *
   * A stored envelope naming only recipients this reader holds no candidate
   * key for fails fast, and which error it raises depends on whether the
   * descriptor lists the named epoch. An epoch the descriptor lists but wraps
   * only to other recipients raises {@link KeyUnwrapError}: this reader is
   * not a recipient of that epoch (it never was, or it was removed and the
   * epoch rotated), so re-reading the descriptor cannot help. That is the
   * read axis only; it says nothing about whether the server will still
   * serve (pull) the ciphertext. An epoch the descriptor does not list at
   * all raises {@link UnknownEpochError} -- the signal that the cached
   * Collection Description may be stale (an epoch rotation emits no
   * change-feed entry) and the codec must be rebuilt from a re-read
   * descriptor. A candidate whose entry then fails to unwrap also surfaces
   * {@link KeyUnwrapError}.
   *
   * Also returns the `id` of the key that actually decrypted the envelope (its
   * JWE recipient `kid`), so {@link _verifyBinding} can check a `was.epoch`
   * binding against the epoch of the decrypting key.
   *
   * @param encryptedDoc {IEncryptedDocument}
   * @returns {Promise<object>}   the decrypted document plus `keyId`
   */
  async #decrypt(encryptedDoc: IEncryptedDocument): Promise<{
    content?: unknown
    meta?: Record<string, unknown>
    stream?: unknown
    keyId: string
  }> {
    const kids = envelopeRecipientKids(encryptedDoc)
    const kidSet = new Set(kids)
    // Prefer the read key whose id names a recipient of this envelope; for a
    // well-formed envelope the exact match always hits. A non-empty recipient
    // set that matches NO candidate is unroutable, so fail fast rather than
    // burning ECDH attempts that cannot succeed. Which failure it is depends
    // on whether the descriptor lists the named epoch: an epoch key's kid is
    // `<epoch did:key>#<fingerprint>`, so the portion before the fragment
    // names the epoch. Listed but wrapped only to others: this reader is not
    // a recipient of that epoch (the membership signal, KeyUnwrapError). Not
    // listed at all: the descriptor has never seen the epoch (the
    // stale-descriptor signal, UnknownEpochError). The `rest` fallback below
    // is then reached only for a malformed envelope naming no recipient kid
    // at all, letting a candidate surface the cipher's own typed decrypt
    // error.
    const preferred = this.#readKeys.filter(key => kidSet.has(key.id))
    if (preferred.length === 0 && kids.length > 0) {
      const listed = kids.some(kid =>
        this.#epochIds.has(kid.split('#')[0] ?? kid)
      )
      if (listed) {
        throw new KeyUnwrapError(
          'Cannot decrypt this resource: it was encrypted under a key epoch ' +
            'this reader holds no key for. The epoch is on the Collection ' +
            'Description, but none of its recipient entries name this reader ' +
            '(it was never a recipient of that epoch, or it was removed and ' +
            'the epoch rotated). This is the read axis only -- the server ' +
            'may still serve the ciphertext (a separate zcap decision).'
        )
      }
      throw new UnknownEpochError({ collectionId: this.#collectionId, kids })
    }
    const rest = this.#readKeys.filter(key => !kidSet.has(key.id))
    for (const keyAgreementKey of [...preferred, ...rest]) {
      try {
        const decrypted = await this.#edv.documentCipher.decrypt({
          encryptedDoc,
          keyAgreementKey
        })
        return { ...decrypted, keyId: keyAgreementKey.id }
      } catch (err) {
        if (isKeyMiss(err)) {
          // This candidate is not a recipient of this envelope, or could not
          // unwrap its content-encryption key; try the next candidate.
          continue
        }
        // The candidate DID select a recipient and unwrap the CEK, but the
        // content's AEAD tag failed to authenticate: the stored ciphertext is
        // corrupt or has been tampered with. Surface this immediately as an
        // integrity failure rather than masking it as a membership/key miss by
        // continuing into `rest` (a real key miss never reaches AEAD, so this
        // can only be a genuine integrity failure on a key that matched).
        throw new IntegrityError(
          'Cannot decrypt this resource: its ciphertext failed to authenticate ' +
            '(the AEAD integrity tag did not verify). This reader holds a key ' +
            'that unwrapped the envelope, so this is not a key-epoch/membership ' +
            'problem -- the stored envelope is corrupt or has been tampered ' +
            'with.',
          { cause: err }
        )
      }
    }
    throw new KeyUnwrapError(
      "Cannot decrypt this resource: none of this reader's epoch keys unwrap " +
        'it. It was encrypted under a key epoch this reader holds no key for ' +
        '(it was never a recipient of that epoch, or it was removed from the ' +
        'collection and the epoch was rotated). This is the read axis only -- ' +
        'the server may still serve the ciphertext (a separate zcap decision).'
    )
  }

  /**
   * Verifies the AEAD-authenticated `was` binding on a successfully-decrypted
   * envelope (spec "Request Body Integrity"'s envelope half). Decrypt success
   * proves the protected header authentic, so this runs only after a decrypt
   * succeeds. Enforces, in order:
   *
   * - No `was` parameter at all: refused -- every envelope binds `was`
   *   (epoch-from-birth left no legacy era), so its absence means a writer this
   *   scheme does not admit -- {@link EncryptionError}.
   * - `was.v` missing or not a number: refused like a missing `was` (every
   *   envelope stamps its scheme version) -- {@link EncryptionError}. Greater
   *   than this codec's scheme version: a future-scheme envelope this client
   *   does not implement -- {@link EncryptionError}.
   * - Then the slot markers, which declare positively which of the profile's
   *   slots the envelope was written for -- `was.resource` a resource slot,
   *   `was.collection` the Collection metadata slot, neither a content-derived
   *   content envelope. A read of the Collection metadata slot
   *   (`collectionSlot`) is checked by `#verifyCollectionSlot`, a read of a
   *   resource slot by `#verifyResourceSlot`.
   * - Finally, unconditionally: `was.epoch` missing or not a string: refused
   *   like a missing `was` -- {@link EncryptionError}. Present, it must equal
   *   the epoch (the `did:key` before the `#`) of the key that actually
   *   decrypted -- a mismatch is a replay under a different epoch's key --
   *   {@link IntegrityError}. The check is unconditional: there is no
   *   epoch-less envelope to carve out.
   *
   * @param options {object}
   * @param options.jwe {unknown}   the envelope's JWE (its `protected` header is
   *   parsed for `was`)
   * @param [options.expectedId] {string}   the resource id the read targeted
   * @param [options.collectionSlot] {boolean}   the read addressed the
   *   Collection metadata slot
   * @param options.keyId {string}   the id of the key that decrypted, for the
   *   epoch check
   * @returns {Promise<string | undefined>}   the verified `was.resource` id the
   *   envelope binds, or `undefined` where it binds none (a content-derived
   *   content envelope, or the Collection metadata slot). It is the only
   *   trustworthy resource id on a stored document -- the envelope's top-level
   *   `id` is cleartext and server-controlled -- so a read that addresses
   *   anything under the document's path (the chunked-stream path) must use
   *   this one.
   */
  async #verifyBinding({
    jwe,
    expectedId,
    collectionSlot,
    keyId
  }: {
    jwe: unknown
    expectedId?: string
    collectionSlot?: boolean
    keyId: string
  }): Promise<string | undefined> {
    const was = parseWasHeader(jwe)
    if (was === undefined) {
      throw new EncryptionError(
        'Cannot decrypt this resource: its envelope carries no `was` binding ' +
          'in the JWE protected header. Every EDV-over-WAS envelope binds the ' +
          'scheme version and key epoch at encrypt time; an envelope without ' +
          'the binding was written by a writer this scheme does not admit.'
      )
    }
    if (typeof was.v !== 'number') {
      throw new EncryptionError(
        'Cannot decrypt this resource: its envelope binds no `was.v` scheme ' +
          'version. Every EDV-over-WAS envelope stamps the scheme version at ' +
          'encrypt time; an envelope without the stamp was written by a ' +
          'writer this scheme does not admit.'
      )
    }
    if (was.v > this.#version) {
      throw new EncryptionError(
        `Cannot decrypt this resource: its envelope is stamped with ` +
          `EDV-over-WAS scheme version ${was.v}, which this client (version ` +
          `${this.#version}) does not implement. Upgrade the client.`
      )
    }
    if (collectionSlot) {
      this.#verifyCollectionSlot(was)
    } else {
      await this.#verifyResourceSlot({ was, expectedId, jwe })
    }
    if (typeof was.epoch !== 'string') {
      throw new EncryptionError(
        'Cannot decrypt this resource: its envelope binds no `was.epoch`. ' +
          'Every EDV-over-WAS envelope seals to a key epoch and binds its id ' +
          'at encrypt time; an envelope without the binding was written by a ' +
          'writer this scheme does not admit.'
      )
    }
    const decryptedEpoch = keyId.split('#')[0]
    if (decryptedEpoch !== was.epoch) {
      throw new IntegrityError(
        `Cannot decrypt this resource: its envelope is bound to key epoch ` +
          `"${was.epoch}" but was decrypted with a key from epoch ` +
          `"${decryptedEpoch}". The server replayed it under a different ` +
          'epoch.'
      )
    }
    return typeof was.resource === 'string' ? was.resource : undefined
  }

  /**
   * The slot-marker half of `#verifyBinding` for a read of the Collection
   * metadata slot. Enforces:
   *
   * - `was.resource` present: refused outright -- a resource's envelope was
   *   served in the Collection's metadata slot, which belongs to no resource --
   *   {@link IntegrityError}.
   * - `was.collection` missing or not a string: refused -- the envelope belongs
   *   to some other slot, notably a content-derived content envelope, whose
   *   member set is otherwise identical -- {@link IntegrityError}.
   * - `was.collection` not this codec's collection id: one Collection's
   *   metadata served as another's -- {@link IntegrityError}.
   *
   * @param was {Record<string, unknown>}   the parsed `was` protected-header
   *   parameter
   * @returns {void}
   */
  #verifyCollectionSlot(was: Record<string, unknown>): void {
    if (typeof was.resource === 'string') {
      throw new IntegrityError(
        `Cannot decrypt this Collection's metadata: the stored envelope is ` +
          `bound to resource "${was.resource}", but the Collection metadata ` +
          "slot belongs to no resource. The server swapped a resource's " +
          "metadata envelope into the Collection's metadata slot."
      )
    }
    if (typeof was.collection !== 'string') {
      throw new IntegrityError(
        `Cannot decrypt this Collection's metadata: the stored envelope ` +
          'binds no `was.collection`, so it was written for some other slot ' +
          '(a content envelope, whose binding is otherwise identical). The ' +
          "server served a foreign envelope in the Collection's metadata slot."
      )
    }
    if (was.collection !== this.#collectionId) {
      throw new IntegrityError(
        `Cannot decrypt this Collection's metadata: the stored envelope is ` +
          `bound to collection "${was.collection}", not to the requested ` +
          `collection ("${this.#collectionId}"). The server served one ` +
          "Collection's metadata as another's."
      )
    }
  }

  /**
   * The slot-marker half of `#verifyBinding` for a read of a resource slot
   * (content or resource metadata). Enforces:
   *
   * - `was.collection` present: refused before any id comparison -- the
   *   Collection's metadata envelope was served in a resource slot --
   *   {@link IntegrityError}.
   * - `was.resource` present and the expected id known: a mismatch is a
   *   server-side swap of two resources' envelopes -- {@link IntegrityError}.
   * - `resource` absent (a content-derived write) and the expected
   *   id known: the envelope's ciphertext must re-derive to the expected id
   *   ({@link EdvDocumentCipher.deriveId}); a mismatch means the envelope was
   *   copied under a different id -- {@link IntegrityError}.
   *
   * @param options {object}
   * @param options.was {Record<string, unknown>}   the parsed `was`
   *   protected-header parameter
   * @param [options.expectedId] {string}   the resource id the read targeted
   * @param options.jwe {unknown}   the envelope's JWE, whose ciphertext the
   *   content-derived branch re-derives the id from
   * @returns {Promise<void>}
   */
  async #verifyResourceSlot({
    was,
    expectedId,
    jwe
  }: {
    was: Record<string, unknown>
    expectedId?: string
    jwe: unknown
  }): Promise<void> {
    // A resource slot (content or resource metadata). The Collection's own
    // metadata envelope has no business here, whatever id it names, so it is
    // refused before any resource-id comparison.
    if (was.collection !== undefined) {
      throw new IntegrityError(
        `Cannot decrypt this resource: the stored envelope is bound to ` +
          `collection "${String(was.collection)}", but a resource's slot ` +
          'belongs to no collection binding. The server served the ' +
          "Collection's own metadata envelope in a resource's slot."
      )
    }
    if (typeof was.resource === 'string') {
      if (expectedId !== undefined && was.resource !== expectedId) {
        throw new IntegrityError(
          `Cannot decrypt this resource: the stored envelope is bound to a ` +
            `different resource id ("${was.resource}") than the one requested ` +
            `("${expectedId}"). The server swapped two resources' envelopes.`
        )
      }
    } else if (expectedId !== undefined) {
      // Content-derived write (no `resource`): the id is a function of the
      // ciphertext, so re-derive and compare.
      const { documentCipher } = this.#edv
      const derived = await documentCipher.deriveId({
        jwe: jwe as Parameters<typeof documentCipher.deriveId>[0]['jwe']
      })
      if (derived !== expectedId) {
        throw new IntegrityError(
          `Cannot decrypt this resource: its content-derived id ("${derived}") ` +
            `does not match the requested id ("${expectedId}"). The server ` +
            'served this envelope under an id it was not written for.'
        )
      }
    }
  }

  /**
   * @inheritdoc
   *
   * Encrypts the user-writable `custom` into an EDV Document envelope
   * (`{ jwe, ... }`) with the same `documentCipher.encrypt` used for content --
   * `custom` becomes the document `content`. The envelope's own `sequence` is
   * inert (metadata concurrency is the server's plaintext `metaVersion`, not the
   * envelope), so each write re-encrypts fresh with no `update`.
   */
  async encodeMeta({
    custom,
    id: resourceId
  }: {
    custom: ResourceMetadataCustomInput
    id?: string
  }): Promise<{ custom: object; epoch: string }> {
    const { documentCipher } = this.#edv
    // The document needs an EDV id (the cipher asserts one on decrypt). It is
    // opaque to the server -- carried inside the un-decryptable envelope -- and
    // minted fresh each write, since the metadata envelope is never updated in
    // place (concurrency is the server's plaintext `metaVersion`, Decision 3).
    const id = (await this.#edv.generateId()) as string
    // Bind the `was` parameter to the RESOURCE id (not the metadata envelope's
    // own random EDV id), so a server-side swap of two resources' metadata is
    // AEAD-detected on decode. A Resource-level write always knows that id at
    // encrypt time (it is never content-derived here); a Collection-level write
    // has no resource to bind and binds this collection's id instead, so its
    // slot is declared positively -- a content envelope (which binds neither
    // marker) served in the Collection metadata slot is then detected too. It
    // seals to the current epoch key like every write, so it binds `was.epoch`
    // like every write.
    const encrypted = await documentCipher.encrypt({
      doc: { id, content: custom as Record<string, unknown> },
      ...this.#sealParams({
        ...(resourceId === undefined
          ? { collection: this.#collectionId }
          : { resource: resourceId }),
        // Deliberately un-blinded, even on a searchable collection: this
        // envelope is the WAS `/meta` value, not part of the resource's content
        // document, and it is stored in a different slot the search endpoint
        // never reads. The `meta.*` attribute paths a declared index may name
        // address the *content document's* own `meta` (the content type and
        // inline-encoding discriminator), which is a different object entirely
        // -- so blinding here would emit entries that can never match a query
        // and would leak the shape of the metadata into a slot with no index at
        // all.
        hmac: undefined
      })
    })
    // Surface the epoch this envelope sealed under: a Collection-level `/meta`
    // PUT carries it as the body's top-level `epoch` stamp (the server clears
    // that stamp when it is omitted).
    return { custom: encrypted, epoch: this.#writeEpoch }
  }

  /**
   * @inheritdoc
   *
   * Decrypts the stored `custom` envelope back to plaintext `{ name, tags }`. An
   * absent `custom` (no metadata written yet, or cleared) decodes to `{}`; a
   * present value must be an EDV envelope (else {@link EncryptionError}, the
   * `_assertEnvelope` guard), so a foreign plaintext `custom` fails closed.
   *
   * An omitted `expectedId` means the Collection-level metadata slot (a
   * Resource metadata read always passes its resource id), so an envelope bound
   * to a resource is refused there as a server-side swap, and one that does not
   * bind this Collection's own id is refused as an envelope of some other slot.
   */
  async decodeMeta(
    {
      custom
    }: {
      custom?: unknown
    },
    expectedId?: string
  ): Promise<ResourceMetadataCustom> {
    if (custom === undefined || custom === null) {
      return {}
    }
    const decrypted = await this.#openEnvelope({
      doc: custom,
      expectedId,
      collectionSlot: expectedId === undefined
    })
    return (decrypted.content ?? {}) as ResourceMetadataCustom
  }

  /**
   * Asserts that a document read from an encrypted collection is an EDV envelope
   * (`{ jwe, ... }`) before it is handed to the cipher. A plaintext or foreign
   * resource -- one written without this codec -- carries no `jwe`, which would
   * otherwise make the EDV core throw a raw `TypeError`. Surfacing a typed
   * `EncryptionError` keeps the fail-closed contract legible to callers. The
   * envelope test itself is the shared `isEncryptedEnvelope` predicate, so this
   * guard and the crypto-free read paths cannot disagree on what an envelope
   * is.
   *
   * For an `update`, the envelope's `sequence` is also validated: the cipher
   * requires a non-negative safe integer to advance from, so a foreign envelope
   * without one (or with a malformed one) must fail here as a typed
   * `EncryptionError` rather than as the cipher's raw `Error`.
   *
   * @param doc {unknown}
   * @param context {string}   the operation in progress (`read` / `update`),
   *   for the message
   * @returns {asserts doc is IEncryptedDocument}
   */
  #assertEnvelope(
    doc: unknown,
    context: string
  ): asserts doc is IEncryptedDocument {
    if (!isEncryptedEnvelope(doc as Json | undefined)) {
      throw new EncryptionError(
        `Cannot ${context} an encrypted resource: the stored document is not ` +
          'an EDV envelope (it carries no `jwe` field). It was likely written ' +
          'as plaintext, or by a writer that did not use this encrypted ' +
          'collection.'
      )
    }
    if (context === 'update') {
      const { sequence } = doc as { sequence?: unknown }
      if (
        typeof sequence !== 'number' ||
        !Number.isSafeInteger(sequence) ||
        sequence < 0
      ) {
        throw new EncryptionError(
          'Cannot update an encrypted resource: the stored EDV envelope ' +
            'carries no valid `sequence` (a non-negative safe integer is ' +
            'required to advance it). It was likely written by a foreign ' +
            'tool that did not maintain the EDV document sequence.'
        )
      }
    }
  }

  /**
   * Splits a caller value into a decrypted EDV document `{ content, meta }`,
   * carrying the plaintext content type and inline-encoding discriminator in
   * `meta`. Three cases:
   *
   * 1. JSON object/array to `content` verbatim, `meta = { contentType }` (no
   *   `encoding`); the shape of `content` is never inspected on read, so a
   *   caller object shaped like `{ text }` / `{ bytes }` round-trips as itself.
   * 2. Text (`Blob`/`Uint8Array` of a text-family type that is valid UTF-8)
   *   to `content = { text }`, `meta = { contentType, encoding: 'utf-8' }`;
   *   stored legibly with no base64 inflation.
   * 3. Binary (any other `Blob`/`Uint8Array`) to `content = { bytes: base64 }`,
   *   `meta = { contentType, encoding: 'base64' }`.
   *
   * A binary payload over {@link #maxBlobBytes} is not an inline document at
   * all: it answers `kind: 'chunked'`, carrying a byte stream (plus its size,
   * for messages) and the `meta` the chunked-stream path seals, and the caller
   * routes the write there. The routing decision is made on the payload's size
   * alone, so a `Blob` over the threshold is never buffered here: it is handed
   * on as `blob.stream()`, and the EDV core re-chunks it as it reads.
   *
   * A bare primitive is rejected (mirroring the plaintext `prepareBody`
   * contract). The binary/text detection and content-type precedence are the
   * shared `resolvePayload` rules, so the plaintext and encrypted write paths
   * cannot drift.
   *
   * @param data {ResourceData}
   * @param [contentType] {string}   caller-supplied content type
   * @param [id] {string}            resource id, for the extension guess
   * @returns {Promise<object>}   the inline document `{ content, meta }`, or
   *   the `{ stream, size, meta }` of a payload to route to the chunked-stream
   *   path
   */
  async #toDocument(
    data: ResourceData,
    contentType?: string,
    id?: string
  ): Promise<
    | {
        kind: 'inline'
        content: Record<string, unknown>
        meta: Record<string, unknown>
      }
    | {
        kind: 'chunked'
        stream: ReadableStream<Uint8Array>
        size: number
        meta: Record<string, unknown>
      }
  > {
    const payload = resolvePayload({ data, contentType, id })

    if (payload.kind === 'binary') {
      const resolvedType = payload.contentType
      // Route on the size alone (`Blob.size` is synchronous), so an
      // over-threshold blob is never read into memory here just to measure it.
      const size = isBlob(payload.data)
        ? payload.data.size
        : payload.data.length
      if (size > this.#maxBlobBytes) {
        // Too large for one document: route it to the chunked-stream path,
        // where the bytes live in the document's own chunk resources. Hand it
        // over as a stream -- a `Blob` streams itself, and bytes already in
        // hand become a one-value stream the same way -- so the payload is not
        // held twice while the EDV core re-chunks it.
        return {
          kind: 'chunked',
          stream: bytesToStream(payload.data),
          size,
          meta: { contentType: resolvedType, encoding: CHUNKED_ENCODING }
        }
      }
      // Under the threshold the bytes are sealed inline, so buffer them now.
      const bytes = isBlob(payload.data)
        ? await blobBytes(payload.data)
        : payload.data
      // Text-family AND valid UTF-8 to store as a legible string. The UTF-8 gate
      // guarantees the bytes survive the string round-trip exactly; anything
      // else falls through to base64, which is always byte-safe.
      if (isTextContentType(resolvedType)) {
        const text = decodeUtf8(bytes)
        if (text !== null) {
          return {
            kind: 'inline',
            content: { text },
            meta: { contentType: resolvedType, encoding: 'utf-8' }
          }
        }
      }
      return {
        kind: 'inline',
        content: { bytes: base64.encode(bytes) },
        meta: { contentType: resolvedType, encoding: 'base64' }
      }
    }

    if (payload.kind === 'json') {
      // JSON object/array: content verbatim, no encoding (the read side treats
      // an absent `meta.encoding` as JSON). EDV models `content` as an object
      // record; a JSON array is also a valid encrypted value here, so widen it.
      return {
        kind: 'inline',
        content: data as Record<string, unknown>,
        meta: { contentType: contentType ?? 'application/json' }
      }
    }

    throw new ValidationError(
      'Encrypted resource data must be a plain object/array (JSON) or a ' +
        'Blob/Uint8Array (binary).'
    )
  }

  /**
   * Reconstructs a caller value from a decrypted EDV document, discriminating
   * on `meta.encoding`:
   *
   * - `'utf-8'` to a `Blob` typed `meta.contentType` from `content.text`.
   * - `'base64'` to a `Blob` typed `meta.contentType` from `content.bytes`.
   * - absent (or `meta` absent) to `content` returned verbatim as JSON.
   *
   * A malformed inner shape (an encoding that does not match its container key's
   * type) throws {@link EncryptionError} -- the decrypted-document analogue of
   * `_assertEnvelope`'s outer guard.
   *
   * @param content {unknown}
   * @param [meta] {Record<string, unknown>}
   * @returns {Json | Blob}
   */
  #fromDocument(content: unknown, meta?: Record<string, unknown>): Json | Blob {
    const encoding = meta?.encoding
    const contentType =
      typeof meta?.contentType === 'string' ? meta.contentType : undefined
    if (encoding === 'utf-8') {
      const text = (content as { text?: unknown } | null)?.text
      if (typeof text !== 'string') {
        throw new EncryptionError(
          'Malformed encrypted text document: meta.encoding is "utf-8" but ' +
            'content.text is not a string.'
        )
      }
      // `Blob` encodes a string part as UTF-8 itself, with the same
      // unpaired-surrogate handling as `TextEncoder`.
      return new Blob([text], { type: contentType })
    }
    if (encoding === 'base64') {
      const base64Text = (content as { bytes?: unknown } | null)?.bytes
      if (typeof base64Text !== 'string') {
        throw new EncryptionError(
          'Malformed encrypted binary document: meta.encoding is "base64" but ' +
            'content.bytes is not a string.'
        )
      }
      return new Blob([base64.decode(base64Text) as BlobPart], {
        type: contentType
      })
    }
    return content as Json
  }
}

/**
 * Presents a binary payload as the `ReadableStream`
 * `EdvClientCore.insert({ stream })` consumes. A `Blob` streams itself; bytes
 * already in hand are wrapped in a `Blob` and stream the same way. The encrypt
 * stream re-chunks whatever it is fed at its own `chunkSize`, so the shape of
 * the source stream does not affect the stored chunks.
 *
 * @param data {Blob | Uint8Array}
 * @returns {ReadableStream<Uint8Array>}
 */
function bytesToStream(data: Blob | Uint8Array): ReadableStream<Uint8Array> {
  const blob = isBlob(data) ? data : new Blob([data as BlobPart])
  return blob.stream() as ReadableStream<Uint8Array>
}

/**
 * Drains a byte stream into one `Blob` of the given type. `Blob` does the
 * concatenation: its parts are the chunks the stream yielded, in order.
 *
 * @param options {object}
 * @param options.stream {ReadableStream<Uint8Array>}
 * @param [options.type] {string}   the blob's content type
 * @returns {Promise<Blob>}
 */
async function streamToBlob({
  stream,
  type
}: {
  stream: ReadableStream<Uint8Array>
  type?: string
}): Promise<Blob> {
  const reader = stream.getReader()
  const parts: BlobPart[] = []
  for (;;) {
    const { value, done } = await reader.read()
    if (done) {
      break
    }
    if (value !== undefined) {
      parts.push(value as BlobPart)
    }
  }
  return new Blob(parts, type !== undefined ? { type } : undefined)
}

/**
 * Decodes bytes as strict UTF-8, returning `null` when they are not valid UTF-8
 * (so the caller can fall back to base64). Uses the shared fatal decoder.
 *
 * @param bytes {Uint8Array}
 * @returns {string | null}
 */
function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return UTF8_DECODER.decode(bytes)
  } catch {
    return null
  }
}

/**
 * Parses the `was` binding out of a JWE's protected header. The header is
 * base64url (no padding) JSON; a successful decrypt has already proven it
 * authentic, so this parse is trusted. Returns the `was` object, or `undefined`
 * when the header is absent/unparseable or carries no `was` member (the caller
 * refuses such an envelope).
 *
 * @param jwe {unknown}
 * @returns {Record<string, unknown> | undefined}
 */
function parseWasHeader(jwe: unknown): Record<string, unknown> | undefined {
  const protectedHeader = (jwe as { protected?: unknown } | null)?.protected
  if (typeof protectedHeader !== 'string') {
    return undefined
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(
      // The shared lenient decoder, deliberately NOT `UTF8_DECODER`: its
      // `fatal: true` would turn malformed bytes into a throw rather than the
      // documented `undefined` return. The header is already proven authentic
      // by a successful decrypt.
      DECODER.decode(base64urlnopad.decode(protectedHeader))
    )
  } catch {
    return undefined
  }
  const was = (parsed as { was?: unknown } | null)?.was
  if (was === null || typeof was !== 'object') {
    return undefined
  }
  return was as Record<string, unknown>
}

/**
 * The EDV scheme tag this provider handles (matches the Collection descriptor).
 */
const EDV_SCHEME = 'edv'

/**
 * The per-collection key material an EDV codec is built from.
 */
export interface EdvKeys {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  /**
   * The collection's blinded-index key, for a keystore that custodies the HMAC
   * key directly rather than reading it off the descriptor. An explicitly
   * supplied key wins over unwrapping the descriptor's `hmac` member; omit it
   * to let the descriptor decide (and to get `null` when the collection
   * declares no blinded index at all).
   */
  hmac?: BlindingKey
}

/**
 * Builds an {@link EncryptionProvider} for the `edv` scheme: a pure **keystore**
 * that turns a collection's keys into an {@link EdvCodec}. Pass the result as
 * `WasClient`'s `encryption` option.
 *
 * It does **not** decide which collections are encrypted -- that policy is the
 * Collection's `encryption` descriptor (or a per-handle override). Core calls
 * `codecFor` only for a collection already known to be encrypted; this provider
 * then supplies the keys: the override-supplied `keys` when present, else
 * `resolveKeys({ spaceId, collectionId })`. `resolveKeys` returning `null` means
 * "I hold no keys for this collection", so core fails closed (it does **not**
 * mean plaintext -- the descriptor/override already decided that). A non-`edv`
 * scheme yields `null` (this provider does not handle it).
 *
 * @param options {object}
 * @param options.resolveKeys {function}   the keystore: returns the collection's
 *   `{ keyAgreementKey, keyResolver }`, or `null` if this client holds no keys
 *   for it (fail-closed -- not a plaintext signal)
 * @param [options.contentType] {string}   stored envelope content type;
 *   defaults to `application/json`. Pass `JOSE_CONTENT_TYPE`
 *   (`application/jose+json`) against a server that registers an
 *   `application/*+json` parser.
 * @param [options.maxBlobBytes] {number}   the size in raw bytes above which a
 *   binary `add()` is routed to the chunked-stream path instead of one document
 *   (default 512 KiB, sized so a single-document envelope stays under a
 *   server's ~1 MiB JSON body cap; raise it against a server with a larger
 *   limit). A routing threshold, not a hard cap.
 * @param [options.chunkSize] {number}   the size of each encrypted chunk a
 *   routed write emits, in bytes (default 1 MiB). Each chunk is one upload, so
 *   it must stay under the backend's `maxUploadBytes` constraint (the
 *   encrypted chunk is somewhat larger than `chunkSize`, so leave headroom).
 *   This is not checked client-side: the shared backend probe reads the
 *   descriptor's affordance tokens, not its `constraints`, so a chunk over the
 *   limit is rejected by the server with a `PayloadTooLargeError` (413) and
 *   the failed write's document stub is then cleaned up.
 * @param [options.idDerivation] {string}   how `add()` mints a document id.
 *   `'random'` (default) is the classic mutable-document model: a random
 *   `generateId()` id, updated in place via `sequence`. `'content'` derives the
 *   id from the encrypted envelope's JWE ciphertext
 *   (`EdvDocumentCipher.deriveId`), making documents content-addressed and
 *   therefore immutable (an "update" is delete-old + add-new) -- the model a
 *   replicating store wants, since the id is stable across replicas with no
 *   mapping table. Both formats pass the same EDV id check; the explicit-id
 *   `put(id, ...)` path is unaffected either way.
 * @returns {EncryptionProvider}
 */
export function createEdvEncryption({
  resolveKeys,
  contentType = DEFAULT_CONTENT_TYPE,
  maxBlobBytes = DEFAULT_MAX_BLOB_BYTES,
  chunkSize,
  idDerivation = 'random'
}: {
  resolveKeys: (ref: {
    spaceId: string
    collectionId: string
  }) => Promise<EdvKeys | null>
  contentType?: string
  maxBlobBytes?: number
  chunkSize?: number
  idDerivation?: 'random' | 'content'
}): EncryptionProvider {
  return {
    async codecFor({ spaceId, collectionId, scheme, encryption, keys }) {
      if (scheme !== EDV_SCHEME) {
        return null
      }
      // Guard the descriptor before consulting the keystore, so a collection
      // whose descriptor cannot be opened reports THAT rather than the vaguer
      // "holds no keys" the null return below would produce. `buildEdvCodec`
      // guards again for callers that reach it directly; the guard is pure, so
      // running it twice costs nothing.
      guardEncryptionDescriptor({
        label: `${spaceId}/${collectionId}`,
        encryption
      })
      // Prefer override-supplied keys; otherwise consult the keystore.
      const resolved =
        (keys as EdvKeys | undefined) ??
        (await resolveKeys({ spaceId, collectionId }))
      if (!resolved) {
        return null
      }
      return buildEdvCodec({
        label: `${spaceId}/${collectionId}`,
        transportFactory: wasTransportFactory({
          spaceId,
          collectionId,
          contentType
        }),
        collectionId,
        encryption,
        keys: resolved,
        contentType,
        maxBlobBytes,
        ...(chunkSize !== undefined && { chunkSize }),
        idDerivation
      })
    }
  }
}

/**
 * Builds the {@link EdvCodec} for one encrypted collection from a reader's
 * keys and the collection's encryption descriptor. The whole of the codec
 * build that follows key resolution: the fail-closed descriptor guard, the
 * reader's per-epoch keys, the collection's blinding key, and the EDV core the
 * codec drives. Shared by the keystore provider (`createEdvEncryption`'s
 * `codecFor`, which resolves the keys first) and by the local-replica cipher,
 * which holds its keys already.
 *
 * @param options {object}
 * @param options.collectionId {string}   the collection's WAS id
 * @param [options.label] {string}   how the collection is named in errors;
 *   defaults to its id alone, which is all a build with no Space knows
 * @param [options.transportFactory] {CodecTransportFactory}   builds the
 *   transport the chunked-stream path drives; omitted by the local-replica
 *   build, which has no server to address
 * @param [options.encryption] {CollectionEncryption}   the collection's
 *   encryption descriptor; must carry the key-epoch roster
 * @param options.keys {EdvKeys}   the reader's key material
 * @param options.idDerivation {'random' | 'content'}   how `add()` mints ids
 * @param [options.contentType] {string}   stored envelope content type
 * @param [options.maxBlobBytes] {number}   the single-document threshold
 * @param [options.chunkSize] {number}   the size of each encrypted chunk
 * @returns {Promise<EdvCodec>}
 */
export async function buildEdvCodec({
  collectionId,
  label = `"${collectionId}"`,
  transportFactory,
  encryption,
  keys,
  idDerivation,
  contentType = DEFAULT_CONTENT_TYPE,
  maxBlobBytes = DEFAULT_MAX_BLOB_BYTES,
  chunkSize
}: {
  collectionId: string
  label?: string
  transportFactory?: CodecTransportFactory
  encryption?: CollectionEncryption
  keys: EdvKeys
  idDerivation: 'random' | 'content'
  contentType?: string
  maxBlobBytes?: number
  chunkSize?: number
}): Promise<EdvCodec> {
  const descriptor = guardEncryptionDescriptor({
    label,
    encryption
  })
  const descriptorVersion = descriptor.version
  // Resolve the reader's per-epoch keys from the descriptor -- the
  // `currentEpoch` key pair for writes, every epoch key it can unwrap for
  // reads -- and drive the cipher with those. The reader's own
  // key-agreement key never encrypts or decrypts resources itself; it
  // only unwraps epoch keys. Non-null: the epochs guard above already
  // refused a descriptor without epochs, the one case resolveEpochKeys
  // resolves null for.
  const epochKeys = (await resolveEpochKeys({
    encryption: descriptor,
    keyAgreementKey: keys.keyAgreementKey
  }))!
  // Epoch keys are self-describing did:key key-agreement keys, so a
  // resource's recipient (the epoch public key) resolves through the
  // standard did:key resolver, independent of the reader's own keystore.
  const keyAgreementKey = epochKeys.writeKey
  // The collection's blinding key: an explicitly supplied one (a keystore
  // custodying the HMAC key itself) wins over unwrapping the descriptor's
  // `hmac` member; `null` means the collection declares no blinded index.
  const hmac =
    keys.hmac ??
    (await resolveHmacKey({
      encryption: descriptor,
      keyAgreementKey: keys.keyAgreementKey
    }))
  const edv = new EdvClientCore({
    keyAgreementKey,
    keyResolver: didKeyResolver,
    ...(hmac !== null && { hmac })
  })
  return new EdvCodec({
    edv,
    keyAgreementKey,
    hmac,
    readKeys: epochKeys.readKeys,
    writeEpoch: epochKeys.writeEpoch,
    contentType,
    maxBlobBytes,
    ...(chunkSize !== undefined && { chunkSize }),
    idDerivation,
    version: descriptorVersion ?? EDV_SCHEME_VERSION,
    ...(transportFactory !== undefined && { transportFactory }),
    collectionId,
    // Every epoch the descriptor lists, recipient of it or not, so
    // decrypt routing can tell "not a recipient of this epoch" apart
    // from "descriptor has never seen this epoch".
    epochIds: descriptor.epochs.map(epoch => epoch.id)
  })
}

/**
 * Refuses an encryption descriptor this client cannot operate on, fail-closed:
 * a descriptor from a future scheme version (this client does not implement
 * it, and silently operating on it could mis-handle the data), and a
 * descriptor without a key-epoch roster (under this design it can only mean a
 * descriptor whose provision-time install has not run yet, or a tampering
 * host that stripped the roster -- never a collection to encrypt straight to
 * a key-agreement key). The single guard shared by the multi-recipient build
 * (`createEdvEncryption`'s `codecFor`) and the encrypt-only build, so the two
 * cannot drift.
 *
 * @param options {object}
 * @param options.label {string}   names the collection in error messages
 * @param [options.encryption] {CollectionEncryption}   the descriptor
 * @returns {CollectionEncryption}   the descriptor, with `epochs` narrowed
 *   non-empty
 */
function guardEncryptionDescriptor({
  label,
  encryption
}: {
  label: string
  encryption?: CollectionEncryption
}): CollectionEncryption & {
  epochs: NonNullable<CollectionEncryption['epochs']>
} {
  const descriptorVersion = encryption?.version
  if (
    typeof descriptorVersion === 'number' &&
    descriptorVersion > EDV_SCHEME_VERSION
  ) {
    throw new EncryptionError(
      `Collection ${label} declares EDV-over-WAS scheme version ` +
        `${descriptorVersion}, which this client (version ` +
        `${EDV_SCHEME_VERSION}) does not implement. Upgrade the client.`
    )
  }
  if (!encryption?.epochs || encryption.epochs.length === 0) {
    throw new EncryptionError(
      `Collection ${label} is declared encrypted but its descriptor carries ` +
        "no key epochs. Every encrypted collection's descriptor carries an " +
        'epoch roster from creation (install epoch[0] with ensureFirstEpoch ' +
        'at provision time); a descriptor without one is refused rather than ' +
        'encrypted straight to a key-agreement key.'
    )
  }
  return encryption as CollectionEncryption & {
    epochs: NonNullable<CollectionEncryption['epochs']>
  }
}

/**
 * Builds a write-only {@link EdvCodec} for one encrypted collection from its
 * descriptor alone -- no key-agreement secret anywhere. Encryption in this
 * scheme needs none: a write seals a fresh content-encryption key to the write
 * epoch's PUBLIC key, and the epoch id IS that key's did:key, so the write
 * recipient is reconstructed from the descriptor's `currentEpoch` and resolved
 * through the standard did:key resolver. The codec's write key is a
 * public-only stand-in (the id the recipient template and resolver work from;
 * its `deriveSecret` refuses with {@link EncryptOnlyCipherError}) and it holds
 * no read keys, so it encrypts everything and decrypts nothing.
 *
 * Applies the same fail-closed guards as `codecFor`: a future-scheme
 * descriptor and a descriptor without epochs are refused. The write epoch is
 * the descriptor's `currentEpoch`; a descriptor that omits it seals to the
 * last listed epoch (the roster is append-only, so that is the newest). A
 * `currentEpoch` the roster does not list violates the descriptor invariant
 * and is refused fail-closed -- silently re-routing it could seal new
 * plaintext to a rotated-out epoch whose removed recipients still hold keys.
 *
 * @param options {object}
 * @param options.collectionId {string}   labels errors; and on a slot-bound
 *   write, the id bound into the envelope
 * @param options.idDerivation {'content' | 'random'}   how ids are minted
 * @param options.encryption {CollectionEncryption}   the collection's
 *   descriptor; must carry the key-epoch roster
 * @returns {Promise<EdvCodec>}
 */
export async function encryptOnlyEdvCodec({
  collectionId,
  idDerivation,
  encryption
}: {
  collectionId: string
  idDerivation: 'content' | 'random'
  encryption: CollectionEncryption
}): Promise<EdvCodec> {
  const descriptor = guardEncryptionDescriptor({
    label: `"${collectionId}"`,
    encryption
  })
  const { epochs, currentEpoch } = descriptor
  // `currentEpoch` MUST name a listed epoch (storage-core's descriptor
  // invariant). A descriptor that violates it is stale, partially synced, or
  // tampered with; refuse rather than silently seal to another epoch.
  if (
    currentEpoch !== undefined &&
    !epochs.some(epoch => epoch.id === currentEpoch)
  ) {
    throw new EncryptionError(
      `Collection "${collectionId}" declares currentEpoch "${currentEpoch}" ` +
        'but its epoch roster does not list it. A descriptor names its ' +
        'current epoch among the epochs it lists; re-read the descriptor ' +
        'before writing.'
    )
  }
  // With no `currentEpoch`, the last listed epoch is the newest: the roster
  // is append-only and the current epoch never moves back.
  const writeEpoch = currentEpoch ?? epochs.at(-1)!.id
  let writeKeyId: string
  try {
    writeKeyId = epochKeyIdFor(writeEpoch)
    // Fail fast on a malformed epoch id: the resolver validates the fragment
    // is a well-formed X25519 public-key fingerprint, exactly what every
    // write's recipient resolution will do.
    await didKeyResolver({ id: writeKeyId })
  } catch (err) {
    throw new EncryptionError(
      `Collection "${collectionId}" lists a malformed key-epoch id ` +
        `"${writeEpoch}": it is not the did:key of an X25519 key-agreement ` +
        'key, so no write recipient can be reconstructed from it.',
      { cause: err }
    )
  }
  const writeKey: IKeyAgreementKey = {
    id: writeKeyId,
    async deriveSecret(): Promise<Uint8Array> {
      throw new EncryptOnlyCipherError(
        `The cipher for collection "${collectionId}" is encrypt-only: it ` +
          'was built from the descriptor alone and holds no key-agreement ' +
          'secret to derive with.'
      )
    }
  }
  const edv = new EdvClientCore({
    keyAgreementKey: writeKey,
    keyResolver: didKeyResolver
  })
  return new EdvCodec({
    edv,
    keyAgreementKey: writeKey,
    readKeys: [],
    writeEpoch,
    contentType: DEFAULT_CONTENT_TYPE,
    maxBlobBytes: DEFAULT_MAX_BLOB_BYTES,
    idDerivation,
    version: descriptor.version ?? EDV_SCHEME_VERSION,
    collectionId,
    epochIds: epochs.map(epoch => epoch.id)
  })
}
