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
import type { ClientContext } from './internal/request.js'
import { send } from './internal/request.js'
import { CodecHolder, resolveCodec, readCollectionMarker } from './internal/codec.js'
import { writeHeaders, readEtag } from './internal/conditional.js'
import { sendEncodedWrite } from './internal/write.js'
import { readPolicy, writePolicy, deletePolicy } from './internal/policy.js'
import type { ResourceCodec } from './codec.js'
import { ValidationError } from './errors.js'
import type {
  EncryptionOverride,
  IZcap,
  Json,
  ResourceData,
  PolicyDocument,
  ResourceMetadata,
  ResourceMetadataCustom
} from './types.js'

export class Resource {
  readonly spaceId: string
  readonly collectionId: string
  readonly id: string

  private readonly _context: ClientContext
  private readonly _capability?: IZcap
  private readonly _codecThunk?: () => Promise<ResourceCodec>
  private readonly _encryptionOverride?: EncryptionOverride
  private readonly _codecHolder: CodecHolder

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
    assertNotReserved(resourceId, 'resource')
    this._context = context
    this.spaceId = spaceId
    this.collectionId = collectionId
    this.id = resourceId
    this._capability = capability
    this._codecThunk = codec
    this._encryptionOverride = encryption
    this._codecHolder = new CodecHolder(() =>
      resolveCodec(this._context, {
        spaceId: this.spaceId,
        collectionId: this.collectionId,
        override: this._encryptionOverride,
        readMarker: () =>
          readCollectionMarker(this._context, {
            spaceId: this.spaceId,
            collectionId: this.collectionId,
            capability: this._capability
          })
      })
    )
  }

  private get _path(): string {
    return resourcePath(this.spaceId, this.collectionId, this.id)
  }

  /**
   * Resolves (once, then caches) the codec for this resource: the parent
   * collection's shared codec when this handle came from
   * `collection.resource(id)`, otherwise one resolved for its own collection. A
   * standalone resource discovers its collection's `encryption` marker (one GET
   * on the collection, cached per handle) unless a per-handle override is set,
   * and fails closed if it cannot key an encrypted collection. A fresh
   * standalone handle re-reads the marker, so retain the handle to reuse it. A
   * failed resolution (e.g. a transient 500/network error during marker
   * discovery) is not memoized: the cache is cleared so the next call retries
   * rather than re-throwing the stale error forever.
   *
   * A handle obtained via `collection.resource(id)` delegates to the parent's
   * shared thunk on every call rather than memoizing locally: the parent already
   * memoizes (so this adds no round-trip), and delegating lets a parent reset
   * (e.g. after `configure()` adds the encryption marker) propagate here.
   *
   * @returns {Promise<ResourceCodec>}
   */
  private _codec(): Promise<ResourceCodec> {
    if (this._codecThunk) {
      return this._codecThunk()
    }
    return this._codecHolder.get()
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
    const response = await send(this._context, {
      path: this._path,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : codec.decode(response)
  }

  /**
   * Reads the resource body as text. Returns `null` on a missing/unauthorized
   * resource (404 conflation caveat). A raw escape hatch: it does NOT run the
   * codec, so on an encrypted collection it never decrypts -- use `get()` to
   * decrypt.
   *
   * @returns {Promise<string | null>}
   */
  async getText(): Promise<string | null> {
    const response = await send(this._context, {
      path: this._path,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : response.text()
  }

  /**
   * Reads the resource body as raw bytes. Returns `null` on a
   * missing/unauthorized resource (404 conflation caveat). A raw escape hatch:
   * it does NOT run the codec, so on an encrypted collection it never decrypts
   * -- use `get()` to decrypt.
   *
   * @returns {Promise<Uint8Array | null>}
   */
  async getBytes(): Promise<Uint8Array | null> {
    const response = await send(this._context, {
      path: this._path,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    if (response === null) {
      return null
    }
    return new Uint8Array(await response.arrayBuffer())
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
   * the explicit options are for plaintext collections. Returns the new `etag`.
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
    // A conditional codec (e.g. the EDV codec) needs the current stored envelope
    // to advance its sequence and pin the write to the current ETag, so pre-read
    // it. A plaintext codec needs no pre-read.
    let current: HttpResponse | null | undefined
    if (codec.conditionalWrites) {
      current = await send(this._context, {
        path: this._path,
        method: 'GET',
        capability: this._capability,
        read: true
      })
    }
    const encoded = await codec.encode({
      id: this.id,
      data,
      contentType: options.contentType,
      current
    })
    // A conditional codec computes the precondition itself (from the sequence /
    // ETag); a plaintext codec defers to the caller's explicit options.
    const precondition = codec.conditionalWrites
      ? { ifMatch: encoded.ifMatch, ifNoneMatch: encoded.ifNoneMatch }
      : { ifMatch: options.ifMatch, ifNoneMatch: options.ifNoneMatch }
    const response = await sendEncodedWrite(this._context, {
      path: this._path,
      method: 'PUT',
      capability: this._capability,
      encoded,
      precondition
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
      headers: writeHeaders(undefined, { ifMatch: options.ifMatch })
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
   * Against a backend with the `conditional-writes` feature the result also
   * carries the resource's current `etag` (the strong validator) -- pass it as
   * `put(data, { ifMatch })` for a lost-update-safe update.
   *
   * @returns {Promise<(ResourceMetadata & { etag?: string }) | null>}
   */
  async meta(): Promise<(ResourceMetadata & { etag?: string }) | null> {
    const response = await send(this._context, {
      path: this._metaPath,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    if (response === null) {
      return null
    }
    const metadata = response.data as ResourceMetadata
    const etag = readEtag(response)
    return etag !== undefined ? { ...metadata, etag } : metadata
  }

  /**
   * Replaces the resource's user-writable metadata (`custom`). This is a full
   * replacement: any property omitted from `custom` is cleared, and an omitted
   * `custom` clears them all. Does not create the resource -- a `PUT` to the
   * metadata of a nonexistent resource throws `NotFoundError`. Servers without
   * metadata support surface their 501 as `NotImplementedError`.
   *
   * On an encrypted collection this throws a `ValidationError`: `custom`
   * (`name` / `tags`) would be stored as server-visible plaintext, defeating the
   * encryption. Carry those values inside the encrypted content instead.
   *
   * @param meta {object}
   * @param [meta.custom] {ResourceMetadataCustom}   the user-writable properties
   * @returns {Promise<void>}
   */
  async setMeta(meta: { custom?: ResourceMetadataCustom } = {}): Promise<void> {
    const codec = await this._codec()
    if (!codec.allowsServerMetadata) {
      throw new ValidationError(
        'Cannot set server-visible metadata (name/tags) on an encrypted ' +
          'collection -- it would be stored as plaintext. Carry these values ' +
          'inside the encrypted content instead.'
      )
    }
    await send(this._context, {
      path: this._metaPath,
      method: 'PUT',
      capability: this._capability,
      json: { custom: meta.custom ?? {} }
    })
  }

  /**
   * Sets the resource's human-readable `name` (the value surfaced in collection
   * listings), preserving any existing `tags`. Convenience over `setMeta()`.
   *
   * @param name {string}
   * @returns {Promise<void>}
   */
  async setName(name: string): Promise<void> {
    const current = await this.meta()
    await this.setMeta({ custom: { ...current?.custom, name } })
  }

  /**
   * Sets the resource's `tags`, preserving any existing `name`. Convenience over
   * `setMeta()`.
   *
   * @param tags {Record<string, string>}
   * @returns {Promise<void>}
   */
  async setTags(tags: Record<string, string>): Promise<void> {
    const current = await this.meta()
    await this.setMeta({ custom: { ...current?.custom, tags } })
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
