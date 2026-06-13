/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A navigational handle to a single Resource (a JSON object or binary blob
 * keyed by id within a Collection). Sugar over the Collection item operations,
 * with explicit `getText()` / `getBytes()` escape hatches.
 */
import { resourcePath, resourcePolicy, resourceMeta } from './internal/paths.js'
import { prepareBody, parseResource } from './internal/content.js'
import { assertNotReserved } from './internal/reserved.js'
import type { ClientContext } from './internal/request.js'
import { send } from './internal/request.js'
import type {
  IZcap,
  Json,
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

  /**
   * @param options {object}
   * @param options.context {ClientContext}
   * @param options.spaceId {string}
   * @param options.collectionId {string}
   * @param options.resourceId {string}
   * @param [options.capability] {IZcap}   capability attached to every request
   */
  constructor({
    context,
    spaceId,
    collectionId,
    resourceId,
    capability
  }: {
    context: ClientContext
    spaceId: string
    collectionId: string
    resourceId: string
    capability?: IZcap
  }) {
    this._context = context
    this.spaceId = spaceId
    this.collectionId = collectionId
    this.id = resourceId
    this._capability = capability
  }

  private get _path(): string {
    return resourcePath(this.spaceId, this.collectionId, this.id)
  }

  /**
   * Reads the resource, auto-parsing JSON to an object and returning binary as
   * a `Blob`. Returns `null` if the resource is missing or not visible to you
   * (WAS returns 404 for both not-found and unauthorized).
   *
   * @returns {Promise<Json | Blob | null>}
   */
  async get(): Promise<Json | Blob | null> {
    const response = await send(this._context, {
      path: this._path,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return parseResource(response)
  }

  /**
   * Reads the resource body as text. Returns `null` on a missing/unauthorized
   * resource (404 conflation caveat).
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
   * missing/unauthorized resource (404 conflation caveat).
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
   * @param data {Json | Blob | Uint8Array}
   * @param options {object}
   * @param [options.contentType] {string}   content-type for binary data
   * @returns {Promise<void>}
   */
  async put(
    data: Json | Blob | Uint8Array,
    options: { contentType?: string } = {}
  ): Promise<void> {
    assertNotReserved(this.id, 'resource')
    const prepared = prepareBody(data, options)
    await send(this._context, {
      path: this._path,
      method: 'PUT',
      capability: this._capability,
      json: prepared.json,
      body: prepared.body,
      headers: prepared.contentType
        ? { 'content-type': prepared.contentType }
        : undefined
    })
  }

  /**
   * Deletes the resource. Idempotent.
   *
   * @returns {Promise<void>}
   */
  async delete(): Promise<void> {
    await send(this._context, {
      path: this._path,
      method: 'DELETE',
      capability: this._capability,
      idempotent: true
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
   * @returns {Promise<ResourceMetadata | null>}
   */
  async meta(): Promise<ResourceMetadata | null> {
    const response = await send(this._context, {
      path: this._metaPath,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as ResourceMetadata)
  }

  /**
   * Replaces the resource's user-writable metadata (`custom`). This is a full
   * replacement: any property omitted from `custom` is cleared, and an omitted
   * `custom` clears them all. Does not create the resource -- a `PUT` to the
   * metadata of a nonexistent resource throws `NotFoundError`. Servers without
   * metadata support surface their 501 as `NotImplementedError`.
   *
   * @param meta {object}
   * @param [meta.custom] {ResourceMetadataCustom}   the user-writable properties
   * @returns {Promise<void>}
   */
  async setMeta(meta: { custom?: ResourceMetadataCustom } = {}): Promise<void> {
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
    const response = await send(this._context, {
      path: this._policyPath,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as PolicyDocument)
  }

  /**
   * Sets (creates or replaces) the resource's access-control policy.
   *
   * @param policy {PolicyDocument}
   * @returns {Promise<void>}
   */
  async setPolicy(policy: PolicyDocument): Promise<void> {
    await send(this._context, {
      path: this._policyPath,
      method: 'PUT',
      capability: this._capability,
      json: policy
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
    await send(this._context, {
      path: this._policyPath,
      method: 'DELETE',
      capability: this._capability,
      idempotent: true
    })
  }
}
