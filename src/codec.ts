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
import type { Json } from './types.js'

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
 * - `ifMatch` / `ifNoneMatch` -- an optional conditional-write precondition the
 *   codec computed (e.g. the EDV codec maps its `sequence` onto an `If-Match`
 *   ETag for lost-update-safe updates, or `If-None-Match: *` for a fresh
 *   insert). The write path forwards these as the request's conditional headers.
 *   Only honored for a codec that sets {@link ResourceCodec.conditionalWrites}.
 */
export interface EncodedWrite {
  id?: string
  json?: object
  body?: Uint8Array | Blob
  contentType?: string
  ifMatch?: string
  ifNoneMatch?: boolean
}

/**
 * A pluggable encode/decode transform bound to a single collection handle.
 * Implementations must be stateless with respect to a given call (a resolved
 * codec is reused across every read/write on the handle).
 */
export interface ResourceCodec {
  /**
   * Whether server-visible custom metadata (`resource.setName` / `setTags` /
   * `setMeta`) is permitted. The identity codec allows it; an encrypting codec
   * forbids it (the values would be stored as server-visible plaintext -- a
   * leak), so those methods throw on an encrypted collection.
   */
  readonly allowsServerMetadata: boolean

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
   * @param input.data {Json | Blob | Uint8Array}     the plaintext value
   * @param [input.contentType] {string}              caller-supplied content type
   * @param [input.current] {HttpResponse | null}     the current stored response
   *   (or `null` if absent), supplied only when {@link conditionalWrites} is set,
   *   so the codec can derive the next `sequence` and the `If-Match` ETag.
   * @returns {Promise<EncodedWrite>}
   */
  encode(input: {
    id?: string
    data: Json | Blob | Uint8Array
    contentType?: string
    current?: HttpResponse | null
  }): Promise<EncodedWrite>

  /**
   * Transforms a stored (non-null) read response back into a caller value: a
   * parsed object for JSON, a `Blob` for binary, decrypting first when the
   * codec encrypts.
   *
   * @param response {HttpResponse}
   * @returns {Promise<Json | Blob>}
   */
  decode(response: HttpResponse): Promise<Json | Blob>
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
    keys?: unknown
  }): Promise<ResourceCodec | null>
}
