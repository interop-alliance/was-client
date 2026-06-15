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
 * Whether a collection is encrypted is a per-collection client concern (does the
 * client hold keys for it?), not a backend capability -- an encrypted document
 * is opaque JSON any document backend stores faithfully. So the switch is keys
 * alone: the encrypting codec binds iff the provider returns one for the
 * collection.
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
 *   `application/edv+json` for an encrypted envelope).
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
 * Supplies the encrypting {@link ResourceCodec} for a collection, if the client
 * holds keys for it. Injected into {@link WasClient} by an app that imports the
 * `@interop/was-client/edv` subpath; core only ever holds this interface.
 *
 * `resolveCodec` returns `null` when this client has no keys for the collection,
 * so it should be read/written in plaintext. This is the whole switch: a
 * collection is encrypted iff the provider returns a codec for it.
 */
export interface EncryptionProvider {
  /**
   * @param input {object}
   * @param input.spaceId {string}
   * @param input.collectionId {string}
   * @returns {Promise<ResourceCodec | null>}
   */
  resolveCodec(input: {
    spaceId: string
    collectionId: string
  }): Promise<ResourceCodec | null>
}
