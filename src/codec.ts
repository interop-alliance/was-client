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
 *   `encryption` marker (read from its Description; see `internal/codec.ts`),
 *   else plaintext. A delegated consumer that did not create the collection
 *   discovers this from the marker.
 * - **Keys** (the material to encrypt/decrypt with) come from the injected
 *   {@link EncryptionProvider}, a pure keystore. When policy says "encrypted"
 *   but the keystore holds no keys, core fails closed (throws) rather than
 *   silently writing plaintext.
 */
import type { HttpResponse } from '@interop/http-client'
import type {
  CollectionEncryption,
  Json,
  ResourceData,
  ResourceMetadataCustom
} from './types.js'

/**
 * The result of {@link ResourceCodec.encode}: the stored representation of a
 * write, plus the id to store it under.
 *
 * - `id` -- when present, the write is a `PUT` to this resource id (the codec
 *   either echoes the caller's id or, for `add()`, mints one). When absent, the
 *   write is a `POST` and the server mints the id (the identity codec's `add()`
 *   path).
 * - `json` / `body` -- mutually exclusive payloads, mirroring the request
 *   layer: `json` for a structured body, `body` for raw bytes.
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
 *   insert). The write path forwards these as the request's conditional headers.
 *   Only honored for a codec that sets {@link ResourceCodec.conditionalWrites}.
 * - `epoch` -- the key-epoch id the codec encrypted this write under, on a
 *   multi-recipient encrypted collection. The write path emits it as the
 *   `WAS-Key-Epoch` request header, so the server stamps
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
  epoch?: string
}

/**
 * A pluggable encode/decode transform bound to a single collection handle.
 * Implementations must be stateless with respect to a given call (a resolved
 * codec is reused across every read/write on the handle).
 */
export interface ResourceCodec {
  /**
   * Whether this codec drives optimistic-concurrency (conditional) writes. When
   * `true`, the write path pre-reads the current stored resource and passes it
   * to {@link encode} as `current`, then forwards the precondition `encode`
   * returns ({@link EncodedWrite.ifMatch} / `ifNoneMatch`). The EDV codec sets
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
   * @param [input.current] {HttpResponse | null}     the current stored response
   *   (or `null` if absent), supplied only when {@link conditionalWrites} is set,
   *   so the codec can derive the next `sequence` and the `If-Match` ETag.
   * @returns {Promise<EncodedWrite>}
   */
  encode(input: {
    id?: string
    data: ResourceData
    contentType?: string
    current?: HttpResponse | null
  }): Promise<EncodedWrite>

  /**
   * Transforms a stored (non-null) read response back into a caller value: a
   * parsed object for JSON, a `Blob` for binary, decrypting first when the
   * codec encrypts.
   *
   * @param response {HttpResponse}
   * @param [expectedId] {string}   the resource id the read targeted. An
   *   encrypting codec verifies the decrypted envelope's AEAD-authenticated
   *   binding against it (a server-side swap of two envelopes is then detected);
   *   the identity codec ignores it. Optional and backward compatible -- a
   *   caller that does not know the id (or the plaintext codec) omits it.
   * @returns {Promise<Json | Blob>}
   */
  decode(response: HttpResponse, expectedId?: string): Promise<Json | Blob>

  /**
   * Transforms a caller's user-writable metadata (`custom`) into the value to
   * store under `custom` on a `PUT .../meta` write. The identity codec returns
   * `custom` unchanged (server-visible plaintext `{ name, tags }`); an
   * encrypting codec returns an opaque encryption envelope, so `name` / `tags`
   * are never server-visible.
   *
   * @param input {object}
   * @param input.custom {ResourceMetadataCustom}   the plaintext user metadata
   * @param [input.id] {string}   the resource id the metadata belongs to. An
   *   encrypting codec binds it into the metadata envelope's AEAD-authenticated
   *   protected header (so a server-side swap of two resources' metadata is
   *   detected on decode); the identity codec ignores it.
   * @returns {Promise<{ custom: object }>}   the value to store under `custom`
   */
  encodeMeta(input: {
    custom: ResourceMetadataCustom
    id?: string
  }): Promise<{ custom: object }>

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
   *   against it; the identity codec ignores it.
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
 * has already decided -- from a per-handle override or the Collection's declared
 * `encryption` marker -- that a collection is encrypted. `codecFor` then turns
 * the declared `scheme` (and the client's keys for the collection) into a codec.
 * Returning `null` means "I hold no keys for this collection"; core then fails
 * closed (throws) rather than silently downgrading to plaintext.
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
   *   marker read from the Collection Description (when core discovered it via
   *   the marker rather than an override). Carries the key-epoch public
   *   references (`epochs` / `currentEpoch`) a multi-recipient provider needs to
   *   resolve per-epoch keys; absent on an override-driven resolution, where the
   *   provider falls back to its single-key path.
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
