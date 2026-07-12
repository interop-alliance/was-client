/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A navigational handle to a single Resource (a JSON object or binary blob
 * keyed by id within a Collection). Sugar over the Collection item operations,
 * with explicit `getText()` / `getBytes()` escape hatches.
 */
import type { HttpResponse } from '@interop/http-client'
import { resourcePath, resourcePolicy, resourceMeta } from './internal/paths.js'
import { assertNotReserved } from './internal/reserved.js'
import { WasServerError } from './errors.js'
import type { ClientContext } from './internal/request.js'
import { send } from './internal/request.js'
import { CodecHolder, resolveCodec } from './internal/codec.js'
import { writeHeaders, readEtag } from './internal/conditional.js'
import { upsertResource } from './internal/write.js'
import { readPolicy, writePolicy, deletePolicy } from './internal/policy.js'
import type { ResourceCodec } from './codec.js'
import type {
  EncryptionOverride,
  IZcap,
  Json,
  ResourceData,
  PolicyDocument,
  ResourceMetadata,
  ResourceMetadataCustom
} from './types.js'

/**
 * A shared `TextEncoder` for re-serializing a pre-parsed JSON body to bytes in
 * `getBytes()` (stateless, so one instance is reused).
 */
const ENCODER = new TextEncoder()

/**
 * Re-serializes a read response's pre-parsed JSON body to a string, or returns
 * `undefined` when the body was not pre-parsed (a non-JSON content-type, whose
 * raw stream the caller reads directly). `@interop/http-client` consumes a JSON
 * content-type's body into `.data`, leaving the stream spent, so `getText()` /
 * `getBytes()` reconstruct the text from the parsed value rather than re-reading
 * the stream -- semantically identical JSON, but not guaranteed byte-identical
 * (insignificant whitespace is not preserved).
 *
 * @param response {HttpResponse}
 * @returns {string | undefined}
 */
function preParsedJson(response: HttpResponse): string | undefined {
  return response.data !== undefined ? JSON.stringify(response.data) : undefined
}

export class Resource {
  readonly spaceId: string
  readonly collectionId: string
  readonly id: string

  private readonly _context: ClientContext
  private readonly _capability?: IZcap
  /**
   * Resolves the codec for this resource: the parent collection's shared codec
   * when this handle came from `collection.resource(id)`, otherwise one
   * resolved (and memoized per handle) for its own collection. A standalone
   * resource discovers its collection's `encryption` marker (one GET on the
   * collection, cached per handle) unless a per-handle override is set, and
   * fails closed if it cannot key an encrypted collection. A fresh standalone
   * handle re-reads the marker, so retain the handle to reuse it. A failed
   * resolution (e.g. a transient 500/network error during marker discovery) is
   * not memoized: the cache is cleared so the next call retries rather than
   * re-throwing the stale error forever.
   *
   * A handle obtained via `collection.resource(id)` delegates to the parent's
   * shared resolver on every call rather than memoizing locally: the parent
   * already memoizes (so this adds no round-trip), and delegating lets a parent
   * reset (e.g. after `configure()` adds the encryption marker) propagate here.
   */
  private readonly _codec: () => Promise<ResourceCodec>

  /**
   * @param options {object}
   * @param options.context {ClientContext}
   * @param options.spaceId {string}
   * @param options.collectionId {string}
   * @param options.resourceId {string}
   * @param [options.capability] {IZcap}   capability attached to every request
   * @param [options.codec] {function}   resolver sharing the parent collection's
   *   codec, so a resource handle obtained via `collection.resource(id)` does
   *   not repeat the backend() round-trip. A standalone resource resolves its
   *   own.
   * @param [options.encryption] {EncryptionOverride}   per-handle encryption
   *   override for a standalone resource (ignored when `codec` is supplied --
   *   the shared parent codec wins)
   */
  constructor({
    context,
    spaceId,
    collectionId,
    resourceId,
    capability,
    codec,
    encryption
  }: {
    context: ClientContext
    spaceId: string
    collectionId: string
    resourceId: string
    capability?: IZcap
    codec?: () => Promise<ResourceCodec>
    encryption?: EncryptionOverride
  }) {
    // Guard the id against the Reserved Path Segment Registry up front, so a
    // reserved id from caller input can never be mis-targeted at a
    // collection-level endpoint. `resourcePath(s, c, 'policy')` is byte-identical
    // to the collection policy path, so an unguarded `resource('policy').delete()`
    // would silently wipe the collection's access-control policy; the same
    // collision exists for `backend` / `quota` / `linkset` / `meta`. Guarding in
    // the constructor covers every operation (read, delete, meta, policy, put),
    // not just writes.
    assertNotReserved({ id: resourceId, kind: 'resource' })
    this._context = context
    this.spaceId = spaceId
    this.collectionId = collectionId
    this.id = resourceId
    this._capability = capability
    if (codec) {
      this._codec = codec
    } else {
      const holder = new CodecHolder(() =>
        resolveCodec(this._context, {
          spaceId: this.spaceId,
          collectionId: this.collectionId,
          override: encryption,
          capability: this._capability
        })
      )
      this._codec = () => holder.get()
    }
  }

  private get _path(): string {
    return resourcePath(this.spaceId, this.collectionId, this.id)
  }

  /**
   * Sends the shared resource GET -- the byte-identical request the three public
   * readers (`get` / `getText` / `getBytes`) issue -- resolving a missing or
   * unauthorized resource (404) to `null` via the `read` flag.
   *
   * @returns {Promise<HttpResponse | null>}
   */
  private async _read(): Promise<HttpResponse | null> {
    return send(this._context, {
      path: this._path,
      method: 'GET',
      capability: this._capability,
      read: true
    })
  }

  /**
   * Reads the resource, auto-parsing JSON to an object and returning binary as
   * a `Blob`. Returns `null` if the resource is missing or not visible to you
   * (WAS returns 404 for both not-found and unauthorized).
   *
   * @returns {Promise<Json | Blob | null>}
   */
  async get(): Promise<Json | Blob | null> {
    const codec = await this._codec()
    const response = await this._read()
    return response === null ? null : codec.decode(response)
  }

  /**
   * Reads the resource body as text. Returns `null` on a missing/unauthorized
   * resource (404 conflation caveat). A raw escape hatch: it does NOT run the
   * codec, so on an encrypted collection it never decrypts -- use `get()` to
   * decrypt.
   *
   * For a JSON content-type the request layer has already consumed and parsed
   * the body stream (`@interop/http-client` offers no opt-out through ezcap),
   * so the text is re-serialized from the parsed value: semantically identical
   * JSON, but not guaranteed byte-identical to what was uploaded (insignificant
   * whitespace is not preserved).
   *
   * @returns {Promise<string | null>}
   */
  async getText(): Promise<string | null> {
    const response = await this._read()
    if (response === null) {
      return null
    }
    const json = preParsedJson(response)
    return json !== undefined ? json : response.text()
  }

  /**
   * Reads the resource body as raw bytes. Returns `null` on a
   * missing/unauthorized resource (404 conflation caveat). A raw escape hatch:
   * it does NOT run the codec, so on an encrypted collection it never decrypts
   * -- use `get()` to decrypt.
   *
   * For a JSON content-type the request layer has already consumed and parsed
   * the body stream (`@interop/http-client` offers no opt-out through ezcap),
   * so the bytes are re-serialized from the parsed value: semantically
   * identical JSON, but not guaranteed byte-identical to what was uploaded
   * (insignificant whitespace is not preserved).
   *
   * @returns {Promise<Uint8Array | null>}
   */
  async getBytes(): Promise<Uint8Array | null> {
    const response = await this._read()
    if (response === null) {
      return null
    }
    const json = preParsedJson(response)
    return json !== undefined
      ? ENCODER.encode(json)
      : new Uint8Array(await response.arrayBuffer())
  }

  /**
   * Creates or replaces the resource by id (upsert). JSON for plain
   * objects/arrays, binary for `Blob`/`Uint8Array`. Throws `NotFoundError` if
   * the parent collection does not exist (WAS does not auto-create parents).
   *
   * For binary data with no explicit `contentType` (and no `Blob.type`), the
   * content-type is guessed from the resource id's file extension for common
   * static-web types -- so `resource('index.html').put(bytes)` is sent as
   * `text/html`. An unrecognized/absent extension sends no content-type, and the
   * server applies its own required-`Content-Type` rule.
   *
   * Conditional writes (the backend's `conditional-writes` feature): pass
   * `ifMatch` (the ETag from a prior read/write) for an update-if-unchanged, or
   * `ifNoneMatch: true` for a create-if-absent. A failed precondition throws
   * `PreconditionFailedError` (412). On an encrypted collection these are managed
   * automatically by the codec (the EDV `sequence` becomes the enforced ETag), so
   * the explicit options are for plaintext collections -- and because the codec
   * pre-reads the current document to compute them, updating an existing
   * encrypted document needs read access (a PUT-only capability can only create;
   * see `upsertResource`). Returns the new `etag`.
   *
   * @param data {ResourceData}
   * @param options {object}
   * @param [options.contentType] {string}   content-type for binary data
   * @param [options.ifMatch] {string}       update only if the ETag matches
   * @param [options.ifNoneMatch] {boolean}  create only if absent
   * @returns {Promise<{ etag?: string }>}   the stored resource's new ETag
   */
  async put(
    data: ResourceData,
    options: {
      contentType?: string
      ifMatch?: string
      ifNoneMatch?: boolean
    } = {}
  ): Promise<{ etag?: string }> {
    const codec = await this._codec()
    const response = await upsertResource(this._context, {
      path: this._path,
      codec,
      id: this.id,
      data,
      contentType: options.contentType,
      capability: this._capability,
      precondition: {
        ifMatch: options.ifMatch,
        ifNoneMatch: options.ifNoneMatch
      }
    })
    return { etag: readEtag(response) }
  }

  /**
   * Deletes the resource. Idempotent. Pass `ifMatch` (the backend's
   * `conditional-writes` feature) to delete only if the resource's current ETag
   * matches; a stale validator throws `PreconditionFailedError` (412).
   *
   * @param options {object}
   * @param [options.ifMatch] {string}   delete only if the ETag matches
   * @returns {Promise<void>}
   */
  async delete(options: { ifMatch?: string } = {}): Promise<void> {
    await send(this._context, {
      path: this._path,
      method: 'DELETE',
      capability: this._capability,
      // A conditional delete is not idempotent: a stale `If-Match` must surface
      // as a 412 rather than being swallowed as an absent-target success.
      idempotent: options.ifMatch === undefined,
      headers: writeHeaders({ precondition: { ifMatch: options.ifMatch } })
    })
  }

  private get _metaPath(): string {
    return resourceMeta(this.spaceId, this.collectionId, this.id)
  }

  /**
   * Reads the resource's metadata object (server-managed `contentType` / `size`
   * / timestamps plus the user-writable `custom` object). Returns `null` if the
   * resource is missing or not visible to you (404 conflation caveat). A server
   * without metadata support surfaces its 501 as `NotImplementedError`.
   *
   * On an encrypted collection the stored `custom` is an opaque envelope; this
   * decodes it (decrypts, via the codec) so a caller always sees plaintext
   * `{ name, tags }`. A resource with no user metadata reports `custom` as `{}`.
   *
   * Against a backend with the `conditional-writes` feature the result also
   * carries the metadata's current `etag` (the `/meta` `metaVersion` validator)
   * -- pass it as `setMeta(meta, { ifMatch })` for a lost-update-safe metadata
   * update.
   *
   * @returns {Promise<(ResourceMetadata & { etag?: string }) | null>}
   */
  async meta(): Promise<(ResourceMetadata & { etag?: string }) | null> {
    const codec = await this._codec()
    const response = await send(this._context, {
      path: this._metaPath,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    if (response === null) {
      return null
    }
    if (response.data === undefined) {
      // A 200 whose body `@interop/http-client` did not pre-parse into `.data`
      // (a non-JSON content-type, or an empty/204 body): a metadata document
      // always carries its server-managed fields as JSON, so an absent `.data`
      // is a malformed response. Fail with a typed error rather than
      // dereferencing `metadata.custom` off `undefined` as a raw `TypeError`.
      // (Kept distinct from the `null` return, which means the resource is
      // missing or not visible -- not that the server answered malformed.)
      throw new WasServerError(
        `Metadata response for "${this.id}" carried no JSON body ` +
          `(content-type ` +
          `"${response.headers.get('content-type') ?? 'unknown'}").`
      )
    }
    const metadata = response.data as ResourceMetadata
    // Decode the user-writable `custom` (decrypting it on an encrypted
    // collection) so callers uniformly see plaintext `{ name, tags }`.
    const custom = await codec.decodeMeta({ custom: metadata.custom })
    const decoded = { ...metadata, custom }
    const etag = readEtag(response)
    return etag !== undefined ? { ...decoded, etag } : decoded
  }

  /**
   * Replaces the resource's user-writable metadata (`custom`). This is a full
   * replacement: any property omitted from `custom` is cleared, and an omitted
   * `custom` clears them all. Does not create the resource -- a `PUT` to the
   * metadata of a nonexistent resource throws `NotFoundError`. Servers without
   * metadata support surface their 501 as `NotImplementedError`.
   *
   * On an encrypted collection `custom` is encrypted into an opaque envelope by
   * the codec before it is sent, so `name` / `tags` are never stored as
   * server-visible plaintext -- transparently, the same call works on plaintext
   * and encrypted collections alike.
   *
   * Conditional metadata writes (the backend's `conditional-writes` feature):
   * pass `ifMatch` (the `etag` from a prior `meta()`) for an
   * update-if-unchanged, or `ifNoneMatch: true` for a write-only-if-no-metadata.
   * A failed precondition throws `PreconditionFailedError` (412). The `/meta`
   * ETag (`metaVersion`) is independent of the content ETag. Returns the new
   * `etag`.
   *
   * @param meta {object}
   * @param [meta.custom] {ResourceMetadataCustom}   the user-writable properties
   * @param options {object}
   * @param [options.ifMatch] {string}       update only if the `/meta` ETag matches
   * @param [options.ifNoneMatch] {boolean}  write only if no metadata is set
   * @returns {Promise<{ etag?: string }>}   the metadata's new ETag
   */
  async setMeta(
    meta: { custom?: ResourceMetadataCustom } = {},
    options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
  ): Promise<{ etag?: string }> {
    const codec = await this._codec()
    const { custom } = await codec.encodeMeta({ custom: meta.custom ?? {} })
    const response = await send(this._context, {
      path: this._metaPath,
      method: 'PUT',
      capability: this._capability,
      json: { custom },
      headers: writeHeaders({
        precondition: {
          ifMatch: options.ifMatch,
          ifNoneMatch: options.ifNoneMatch
        }
      })
    })
    return { etag: readEtag(response) }
  }

  /**
   * Sets the resource's human-readable `name` (the value surfaced in collection
   * listings), preserving any existing `tags`. Convenience over `setMeta()`.
   * The write is pinned to the `etag` the `meta()` read returned (when the
   * backend supports `conditional-writes`), so a concurrent metadata write
   * surfaces as `PreconditionFailedError` instead of being silently erased by
   * this full-replacement write.
   *
   * @param name {string}
   * @returns {Promise<void>}
   */
  async setName(name: string): Promise<void> {
    const current = await this.meta()
    await this.setMeta(
      { custom: { ...current?.custom, name } },
      { ifMatch: current?.etag }
    )
  }

  /**
   * Sets the resource's `tags`, preserving any existing `name`. Convenience over
   * `setMeta()`. Pinned to the `meta()` read's `etag` like {@link setName}.
   *
   * @param tags {Record<string, string>}
   * @returns {Promise<void>}
   */
  async setTags(tags: Record<string, string>): Promise<void> {
    const current = await this.meta()
    await this.setMeta(
      { custom: { ...current?.custom, tags } },
      { ifMatch: current?.etag }
    )
  }

  private get _policyPath(): string {
    return resourcePolicy(this.spaceId, this.collectionId, this.id)
  }

  /**
   * Reads the resource's access-control policy. Returns `null` when no policy is
   * set (or it is not visible to you). Managing a policy is a controller-level
   * operation.
   *
   * @returns {Promise<PolicyDocument | null>}
   */
  async getPolicy(): Promise<PolicyDocument | null> {
    return readPolicy(this._context, {
      policyPath: this._policyPath,
      capability: this._capability
    })
  }

  /**
   * Sets (creates or replaces) the resource's access-control policy.
   *
   * @param policy {PolicyDocument}
   * @returns {Promise<void>}
   */
  async setPolicy(policy: PolicyDocument): Promise<void> {
    return writePolicy(this._context, {
      policyPath: this._policyPath,
      policy,
      capability: this._capability
    })
  }

  /**
   * Makes this single resource world-readable: it becomes readable without
   * authorization. Sugar for `setPolicy({ type: 'PublicCanRead' })`.
   *
   * @returns {Promise<void>}
   */
  async setPublic(): Promise<void> {
    await this.setPolicy({ type: 'PublicCanRead' })
  }

  /**
   * Returns `true` when this resource policy is `PublicCanRead`.
   *
   * @returns {Promise<boolean>}
   */
  async isPublic(): Promise<boolean> {
    const policy = await this.getPolicy()
    return policy?.type === 'PublicCanRead'
  }

  /**
   * Removes the resource's access-control policy, reverting it to
   * capability-only access. Idempotent.
   *
   * @returns {Promise<void>}
   */
  async clearPolicy(): Promise<void> {
    return deletePolicy(this._context, {
      policyPath: this._policyPath,
      capability: this._capability
    })
  }
}
