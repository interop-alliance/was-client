/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The resource codec seam: a pluggable transform sitting between a caller's
 * plaintext value and the bytes a Resource actually stores. The default
 * identity codec preserves today's plaintext behavior byte-for-byte; the opt-in
 * EDV codec (in the `@interop/was-client/edv` subpath) encrypts on write and
 * decrypts on read, so `collection.put(id, obj)` transparently round-trips
 * ciphertext.
 *
 * Core defines only these interfaces and the identity default -- the crypto
 * implementation lives in the subpath so the `@interop/edv-client` /
 * `@interop/minimal-cipher` graph stays out of core was-client. An app wires the
 * two together by passing an `EncryptionProvider` (built by the subpath) to
 * `WasClient`; core holds it as an opaque interface and never imports the
 * subpath.
 *
 * Whether a collection is encrypted is a per-collection client concern, not a
 * backend capability -- an encrypted document is opaque JSON any document
 * backend stores faithfully. Two concerns drive it, deliberately split:
 *
 * - **Policy** (is this collection encrypted, and under which scheme?) is
 *   decided by a per-handle override, else the Collection's declared
 *   `encryption` descriptor (read from its Description; see
 *   `internal/codec.ts`), else plaintext. A delegated consumer that did not
 *   create the collection discovers this from the descriptor.
 * - **Keys** (the material to encrypt/decrypt with) come from the injected
 *   {@link EncryptionProvider}, a pure keystore. When policy says "encrypted"
 *   but the keystore holds no keys, core fails closed (throws) rather than
 *   silently writing plaintext.
 */
import type { HttpResponse } from '@interop/http-client'
import type { FeatureProbe } from './internal/features.js'
import type { WritePrecondition } from './internal/conditional.js'
import type {
  CollectionEncryption,
  Json,
  RequestInput,
  ResourceData,
  ResourceMetadataCustom,
  ResourceMetadataCustomInput
} from './types.js'

/**
 * The minimal read-response surface a codec consumes: the pre-parsed JSON body
 * (`data`), the `json()` fallback for a body the http-client did not
 * pre-parse, and the response headers (for the `ETag` validator). A real
 * `HttpResponse` satisfies it structurally, and so does a stored-body adapter
 * wrapping a local replica's envelope -- so a non-HTTP consumer of a codec
 * (the sync `DocCipher`) needs no fake response object, and the compiler
 * checks the adapter's shape the day a codec reads another field.
 *
 * The identity codec is the exception: it passes bytes through untransformed,
 * so its `decode` needs the full `HttpResponse` stream surface and is only
 * ever called with one (the handle read path).
 */
export interface ResponseLike {
  data?: unknown
  json(): Promise<unknown>
  headers: { get(name: string): string | null }
}

/**
 * The result of {@link ResourceCodec.encode}: the stored representation of a
 * write, plus the id to store it under.
 *
 * - `id` -- when present, the write is a `PUT` to this resource id (the codec
 *   either echoes the caller's id or, for `add()`, mints one). When absent, the
 *   write is a `POST` and the server mints the id (the identity codec's `add()`
 *   path).
 * - `json` / `body` -- mutually exclusive payloads, mirroring the request
 *   layer: `json` for a structured body, `body` for raw bytes. A codec that
 *   also surfaces `envelope` may expose `body` as a lazy getter that serializes
 *   on first read, so a consumer with no use for the wire bytes should read
 *   `envelope` and leave `body` untouched rather than type-testing it first.
 *   The getter is enumerable, so a spread or a structured clone of this object
 *   still carries the same `body` bytes -- it just pays for them.
 * - `contentType` -- the content type to send for a `body` write (e.g.
 *   `application/jose+json` for an encrypted envelope).
 * - `resourceContentType` -- the plaintext content type of the resource, when it
 *   differs from the stored `contentType`. An encrypting codec sets this to the
 *   caller's resolved type (e.g. `image/png`) while `contentType` stays the
 *   opaque envelope type, so `add()` can report the real type in
 *   {@link AddResult.contentType}. Absent for the identity codec (its
 *   `contentType` already is the resource type).
 * - `ifMatch` / `ifNoneMatch` -- an optional conditional-write precondition the
 *   codec computed (e.g. the EDV codec maps its `sequence` onto an `If-Match`
 *   ETag for lost-update-safe updates, or `If-None-Match: *` for a fresh
 *   insert -- or echoes the caller's own `precondition` when one was supplied).
 *   The write path forwards these as the request's conditional headers.
 *   Only honored for a codec that sets {@link ResourceCodec.conditionalWrites}.
 * - `envelope` -- the already-parsed object form of `body`, for a consumer that
 *   needs the object rather than the bytes (an encrypting codec that built an
 *   envelope object before serializing it can hand it over instead of making
 *   the consumer decode and re-parse the bytes). Purely an optimization and
 *   always optional: `body` stays the wire truth, and a consumer that finds no
 *   `envelope` parses `body` itself.
 * - `epoch` -- the key-epoch id the codec encrypted this write under, on a
 *   multi-recipient encrypted collection. The write path emits it as the
 *   `Key-Epoch` request header, so the server stamps
 *   {@link ResourceMetadata.epoch}. Absent for a plaintext or single-key
 *   encrypted write (the header is then not sent, which clears any prior stamp).
 */
export interface EncodedWrite {
  id?: string
  json?: object
  body?: Uint8Array | Blob
  contentType?: string
  resourceContentType?: string
  ifMatch?: string
  ifNoneMatch?: boolean
  envelope?: unknown
  epoch?: string
}

/**
 * The signed-request escape hatch core hands a codec that needs to drive its
 * own multi-request I/O, plus the collection's shared backend-feature probe.
 * Bound to one collection handle and its capability, so a codec never sees the
 * zcap machinery.
 *
 * `request` returns the raw `HttpResponse` (the `was.request()` surface
 * `WasTransport` consumes) but throws the client's typed `WasError` subclasses,
 * the same mapping every core request goes through -- a codec-driven write is
 * still a write of the caller's `add()`, so its failures must be the errors
 * `add()` documents. The typed errors carry the HTTP `status`, so a consumer
 * that dispatches on status (`WasTransport`) is unaffected.
 *
 * `features` is the handle's memoized probe, so a codec's affordance gate costs
 * no extra round trip -- and can tell "the backend advertises no such feature"
 * from "the backend descriptor could not be read at all".
 */
export interface CodecRequestContext {
  request(input: RequestInput): Promise<HttpResponse>
  features: FeatureProbe
}

/**
 * The escape hatch from the single-request `EncodedWrite`: a plan for a write
 * that cannot be expressed as one request, returned by {@link
 * ResourceCodec.encode} instead of an `EncodedWrite`. The EDV codec returns one
 * for a binary payload above its single-document threshold, where the stored
 * form is a document envelope plus a series of chunk resources.
 *
 * `chunked` is the discriminant, and `id` is the resource id the plan will
 * write to (known before `execute` runs, so a caller can report it without
 * waiting). `execute` performs the whole write over the supplied context and
 * resolves what the caller needs to shape its result. Only the insert path
 * (`Collection.add`) drives a plan; the write-by-id path refuses one.
 */
export interface ChunkedWrite {
  chunked: true
  id: string
  /**
   * The plaintext content type of the resource, reported as the created
   * resource's type (there is no single stored body whose type to report).
   */
  resourceContentType?: string
  /**
   * Scheme-specific guidance the core write path appends to the generic error
   * it throws when it refuses the plan (a write by id, where auto-routing does
   * not apply). Only the codec knows why its payload needs several requests and
   * which low-level API drives that write directly, so the wording is supplied
   * here rather than hardcoded in the scheme-agnostic core.
   */
  guidance?: string
  /**
   * Runs the multi-request write.
   *
   * @param context {CodecRequestContext}
   * @returns {Promise<{ id: string; etag?: string }>}   the created resource id
   *   and, when the last write surfaced one, its `ETag` validator
   */
  execute(context: CodecRequestContext): Promise<{ id: string; etag?: string }>
}

/**
 * What {@link ResourceCodec.encode} produces: the ordinary single-request
 * encoding, or a {@link ChunkedWrite} plan for a payload that needs more than
 * one request.
 */
export type CodecWrite = EncodedWrite | ChunkedWrite

/**
 * Whether an `encode` result is a multi-request {@link ChunkedWrite} plan
 * rather than a single-request {@link EncodedWrite}.
 *
 * @param write {CodecWrite}
 * @returns {boolean}
 */
export function isChunkedWrite(write: CodecWrite): write is ChunkedWrite {
  return (write as ChunkedWrite).chunked === true
}

/**
 * One entry of a collection's persisted index schema: an attribute path (or an
 * array of them, for a compound index), whether the index is unique, and the
 * schema revision it was added in.
 *
 * `addedIn` is the partial-coverage marker: a document written before the
 * attribute was declared carries no token for it, so a querier comparing
 * `addedIn` against how long the collection has existed knows matches may be
 * incomplete until those documents are rewritten.
 */
export interface IndexDeclaration {
  attribute: string | string[]
  unique?: true
  addedIn: number
}

/**
 * The collection's persisted index schema: which attributes are searchable, and
 * a monotonic `revision` bumped by each declaration. It is stored inside the
 * collection's encrypted metadata envelope, so any recipient can discover what
 * is queryable without out-of-band coordination (the attribute names are
 * themselves sensitive -- they describe the data model -- so they never travel
 * as server-visible plaintext).
 */
export interface IndexSchema {
  revision: number
  indexes: IndexDeclaration[]
}

/**
 * A built search query in the form the server evaluates: an index key id plus
 * blinded terms. The client blinds attribute names and values before they leave
 * it, so the server matches opaque strings and learns neither.
 */
export interface BlindedQuery {
  index: string
  equals?: Array<Record<string, string>>
  has?: string[]
  count?: boolean
  limit?: number
  cursor?: string
}

/**
 * The optional search capability of a codec that indexes what it stores. It is
 * deliberately scheme-agnostic -- no EDV type appears in it -- so the handle
 * layer can drive declaration and search without knowing how blinding works.
 * The identity (plaintext) codec does not implement it, which is how the handle
 * layer detects that a collection is not searchable this way.
 */
export interface CodecIndexing {
  /**
   * Installs the collection's persisted schema on this codec, so subsequent
   * writes emit index tokens for the declared attributes and queries can be
   * built for them. Called at codec-resolution time with the stored schema, and
   * again by `declareIndex` after it persists a new one.
   *
   * @param schema {IndexSchema}
   * @returns {void}
   */
  applySchema(schema: IndexSchema): void

  /**
   * The schema currently installed on this codec (the empty schema before one
   * is applied).
   *
   * @returns {IndexSchema}
   */
  schema(): IndexSchema

  /**
   * Blinds a caller's search terms into the query the server evaluates.
   * Attributes absent from the installed schema are refused rather than
   * silently blinded into a term-less query that matches nothing.
   *
   * @param input {object}
   * @param [input.equals] {object | object[]}   attribute/value pairs to match
   * @param [input.has] {string | string[]}   attribute names a document must have
   * @returns {Promise<BlindedQuery>}
   */
  buildQuery(input: {
    equals?: Record<string, unknown> | Array<Record<string, unknown>>
    has?: string | string[]
  }): Promise<BlindedQuery>
}

/**
 * A pluggable encode/decode transform bound to a single collection handle.
 * Implementations must be stateless with respect to a given call (a resolved
 * codec is reused across every read/write on the handle).
 */
export interface ResourceCodec {
  /**
   * The codec's search capability, when it indexes what it stores (the EDV
   * codec on a collection whose descriptor declares a blinded-index key).
   * Absent for the identity codec and for an encrypted collection provisioned
   * without an index key, so `Collection.declareIndex()` / `find()` refuse
   * rather than pretend.
   */
  readonly indexing?: CodecIndexing

  /**
   * Whether this codec drives optimistic-concurrency (conditional) writes. When
   * `true`, the write path pre-reads the current stored resource and passes it
   * to {@link encode} as `current` (along with the caller's own `precondition`,
   * when one was named), then forwards the precondition `encode` returns ({@link EncodedWrite.ifMatch} / `ifNoneMatch`). The EDV codec sets
   * this so its `sequence` is enforced (lost-update-safe) rather than advisory;
   * the identity codec leaves it unset (plaintext writes carry only the caller's
   * explicit precondition).
   */
  readonly conditionalWrites?: boolean

  /**
   * Transforms a caller's write value into its stored representation. `id` is
   * present for `put(id, ...)` (and absent for `add(...)`, where the codec may
   * mint one by returning {@link EncodedWrite.id}).
   *
   * @param input {object}
   * @param [input.id] {string}                       resource id (absent on add)
   * @param input.data {ResourceData}                 the plaintext value
   * @param [input.contentType] {string}              caller-supplied content type
   * @param [input.current] {ResponseLike | null}     the current stored response
   *   (or `null` if absent), supplied only when {@link conditionalWrites} is
   *   set, so the codec can derive the next `sequence` and the `If-Match` ETag.
   * @param [input.precondition] {WritePrecondition}   the caller's explicit
   *   compare-and-swap baseline (`Resource.put`'s `ifMatch` / `ifNoneMatch`),
   *   supplied only when {@link conditionalWrites} is set and the caller named
   *   one. A conditional codec pins the write to it instead of to the ETag its
   *   own pre-read observed, so a lost-update guard keeps working on a
   *   collection whose codec computes its own preconditions.
   * @returns {Promise<CodecWrite>}   the single-request encoding, or -- for a
   *   payload the codec cannot store in one request -- a {@link ChunkedWrite}
   *   plan the insert path executes. Only `add()` drives a plan; a write by id
   *   refuses one.
   */
  encode(input: {
    id?: string
    data: ResourceData
    contentType?: string
    current?: ResponseLike | null
    precondition?: WritePrecondition
  }): Promise<CodecWrite>

  /**
   * Transforms a stored (non-null) read response back into a caller value: a
   * parsed object for JSON, a `Blob` for binary, decrypting first when the
   * codec encrypts.
   *
   * @param response {ResponseLike}
   * @param [expectedId] {string}   the resource id the read targeted. An
   *   encrypting codec verifies the decrypted envelope's AEAD-authenticated
   *   binding against it (a server-side swap of two envelopes is then detected);
   *   the identity codec ignores it. Optional and backward compatible -- a
   *   caller that does not know the id (or the plaintext codec) omits it.
   * @param [context] {CodecRequestContext}   the signed-request escape hatch,
   *   passed by every handle read. A codec whose stored form can span several
   *   resources (the EDV codec's chunked blobs) reads the remainder through it;
   *   the identity codec ignores it. A caller with no request layer (the sync
   *   `DocCipher`, reading a local replica) omits it, and a codec that then
   *   meets a multi-resource document throws rather than return a stub.
   * @returns {Promise<Json | Blob>}
   */
  decode(
    response: ResponseLike,
    expectedId?: string,
    context?: CodecRequestContext
  ): Promise<Json | Blob>

  /**
   * Transforms a caller's user-writable metadata (`custom`) into the value to
   * store under `custom` on a `PUT .../meta` write. The identity codec returns
   * `custom` unchanged (server-visible plaintext `{ name, tags }`); an
   * encrypting codec returns an opaque encryption envelope, so `name` / `tags`
   * are never server-visible.
   *
   * @param input {object}
   * @param input.custom {ResourceMetadataCustomInput}   the plaintext user
   *   metadata; extra members beyond `name` / `tags` are admitted (the
   *   Collection-level `custom` carries the persisted `indexSchema` alongside
   *   them) while `name` / `tags` themselves stay checked at their stored
   *   types
   * @param [input.id] {string}   the resource id the metadata belongs to. An
   *   encrypting codec binds it into the metadata envelope's AEAD-authenticated
   *   protected header (so a server-side swap of two resources' metadata is
   *   detected on decode); the identity codec ignores it. Absent for a
   *   Collection-level metadata write, which belongs to no resource -- an
   *   encrypting codec then binds its own collection id instead.
   * @returns {Promise<{ custom: object; epoch?: string }>}   the value to store
   *   under `custom`, plus -- for an encrypting codec -- `epoch`, the key-epoch
   *   id the metadata envelope sealed under. A Collection-level `/meta` write
   *   forwards it as the PUT body's top-level `epoch` stamp (the server clears
   *   the stamp when it is omitted, so it must be sent on every encrypted
   *   Collection metadata write). Absent for a plaintext/identity codec.
   */
  encodeMeta(input: {
    custom: ResourceMetadataCustomInput
    id?: string
  }): Promise<{ custom: object; epoch?: string }>

  /**
   * Inverts {@link encodeMeta}: transforms the stored `custom` value read from
   * `.../meta` back into the caller's plaintext `{ name, tags }`. The identity
   * codec returns `stored.custom ?? {}` unchanged; an encrypting codec decrypts
   * the envelope. An absent `custom` (no metadata written) decodes to `{}`.
   *
   * @param stored {object}
   * @param [stored.custom] {unknown}   the stored `custom` value from `/meta`
   * @param [expectedId] {string}   the resource id the metadata belongs to. An
   *   encrypting codec verifies the envelope's AEAD-authenticated binding
   *   against it; the identity codec ignores it. Omitted for a Collection-level
   *   read, where an encrypting codec instead requires the envelope to be bound
   *   to that collection.
   * @returns {Promise<ResourceMetadataCustom>}
   */
  decodeMeta(
    stored: { custom?: unknown },
    expectedId?: string
  ): Promise<ResourceMetadataCustom>
}

/**
 * The keystore + codec factory for encrypted collections. Injected into
 * {@link WasClient} by an app that imports the `@interop/was-client/edv`
 * subpath (built by `createEdvEncryption`); core only ever holds this interface
 * and never imports the crypto graph.
 *
 * It is **not** the policy decider: core calls {@link codecFor} only after it
 * has already decided -- from a per-handle override or the Collection's
 * declared `encryption` descriptor -- that a collection is encrypted.
 * `codecFor` then turns the declared `scheme` (and the client's keys for the
 * collection) into a codec. Returning `null` means "I hold no keys for this
 * collection"; core then fails closed (throws) rather than silently downgrading
 * to plaintext.
 */
export interface EncryptionProvider {
  /**
   * Builds the encrypting codec for a collection already known to be encrypted.
   *
   * @param input {object}
   * @param input.spaceId {string}
   * @param input.collectionId {string}
   * @param input.scheme {string}   the declared encryption scheme (e.g. `edv`)
   * @param [input.encryption] {CollectionEncryption}   the full encryption
   *   descriptor read from the Collection Description (when core discovered it
   *   via the descriptor rather than an override). Carries the key-epoch public
   *   references (`epochs` / `currentEpoch`) a multi-recipient provider needs
   *   to resolve per-epoch keys; absent on an override-driven resolution, where
   *   the provider falls back to its single-key path.
   * @param [input.keys] {unknown}   override-supplied key material (a per-handle
   *   `encryption` override); when present the provider uses it instead of its
   *   keystore. Opaque to core; the provider interprets it per `scheme`.
   * @returns {Promise<ResourceCodec | null>}   the codec, or `null` if the
   *   provider holds no keys / does not handle `scheme` (core then fails closed)
   */
  codecFor(input: {
    spaceId: string
    collectionId: string
    scheme: string
    encryption?: CollectionEncryption
    keys?: unknown
  }): Promise<ResourceCodec | null>
}
