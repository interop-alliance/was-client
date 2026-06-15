/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A navigational handle to a Collection within a Space. Exposes its own
 * lifecycle (`describe`/`configure`/`delete`) and contained-resource operations
 * (`add`/`get`/`put`/`list`, plus `resource(id)` for delete-by-id).
 */
import {
  collectionPath,
  collectionItems,
  collectionPolicy,
  collectionLinkset,
  collectionBackend,
  collectionQuota,
  resourcePath,
  toUrl
} from './internal/paths.js'
import { prepareBody, parseResource } from './internal/content.js'
import { assertNotReserved } from './internal/reserved.js'
import { delegateGrant } from './internal/grant.js'
import type { ClientContext } from './internal/request.js'
import { send } from './internal/request.js'
import { Resource } from './Resource.js'
import type {
  AddResult,
  BackendDescriptor,
  BackendReference,
  BackendUsage,
  CollectionDescription,
  GrantOptions,
  HandleOptions,
  IDelegatedZcap,
  IZcap,
  Json,
  LinkSet,
  PolicyDocument,
  CollectionResourcesList
} from './types.js'

export class Collection {
  readonly spaceId: string
  readonly id: string

  private readonly _context: ClientContext
  private readonly _capability?: IZcap

  /**
   * @param options {object}
   * @param options.context {ClientContext} - Shared context (serverUrl, ezcap
   *   client, controllerDid)
   * @param options.spaceId {string}
   * @param options.collectionId {string}
   * @param [options.capability] {IZcap} - capability attached to every request
   */
  constructor({
    context,
    spaceId,
    collectionId,
    capability
  }: {
    context: ClientContext
    spaceId: string
    collectionId: string
    capability?: IZcap
  }) {
    this._context = context
    this.spaceId = spaceId
    this.id = collectionId
    this._capability = capability
  }

  private get _path(): string {
    return collectionPath(this.spaceId, this.id)
  }

  private get _itemsPath(): string {
    return collectionItems(this.spaceId, this.id)
  }

  /**
   * Reads the Collection Description. Returns `null` if the collection is
   * missing or not visible to you (WAS returns 404 for both not-found and
   * unauthorized).
   *
   * @returns {Promise<CollectionDescription | null>}
   */
  async describe(): Promise<CollectionDescription | null> {
    const response = await send(this._context, {
      path: this._path,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as CollectionDescription)
  }

  /**
   * Creates or updates the collection by id (upsert). Merges the given fields
   * over the current description.
   *
   * @param desc {object}
   * @param [desc.name] {string}
   * @param [desc.backend] {BackendReference}
   * @returns {Promise<CollectionDescription>}
   */
  async configure(desc: {
    name?: string
    backend?: BackendReference
  }): Promise<CollectionDescription> {
    assertNotReserved(this.id, 'collection')
    const current = await this.describe()
    const name = desc.name ?? current?.name
    const body: Record<string, unknown> = { id: this.id, name }
    if (desc.backend) {
      body.backend = desc.backend
    }
    await send(this._context, {
      path: this._path,
      method: 'PUT',
      capability: this._capability,
      json: body
    })
    return {
      id: this.id,
      type: current?.type ?? ['Collection'],
      ...(name !== undefined ? { name } : {})
    }
  }

  /**
   * Deletes the whole collection. Idempotent. To delete a single resource, use
   * `collection.resource(id).delete()`.
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

  /**
   * Returns a lazy handle to a resource by id. No I/O.
   *
   * @param resourceId {string}
   * @param options {object}
   * @param [options.capability] {IZcap}
   * @returns {Resource}
   */
  resource(resourceId: string, options: HandleOptions = {}): Resource {
    return new Resource({
      context: this._context,
      spaceId: this.spaceId,
      collectionId: this.id,
      resourceId,
      capability: options.capability ?? this._capability
    })
  }

  /**
   * Adds a resource with a server-generated id. JSON for plain objects/arrays,
   * binary for `Blob`/`Uint8Array`. Throws `NotFoundError` if the collection
   * does not exist (WAS does not auto-create parents).
   *
   * @param data {Json | Blob | Uint8Array}
   * @param options {object}
   * @param [options.contentType] {string}   content-type for binary data
   * @returns {Promise<AddResult>}
   */
  async add(
    data: Json | Blob | Uint8Array,
    options: { contentType?: string } = {}
  ): Promise<AddResult> {
    const prepared = prepareBody(data, options)
    const response = await send(this._context, {
      path: this._itemsPath,
      method: 'POST',
      capability: this._capability,
      json: prepared.json,
      body: prepared.body,
      headers: prepared.contentType
        ? { 'content-type': prepared.contentType }
        : undefined
    })
    // POST always returns a response (404/errors throw via send()).
    const created = (response as { data?: unknown }).data as {
      id: string
      'content-type'?: string
      url?: string
    }
    const location =
      (response as { headers: Headers }).headers.get('location') ?? undefined
    return {
      id: created.id,
      url:
        location ??
        toUrl({
          serverUrl: this._context.serverUrl,
          path: resourcePath(this.spaceId, this.id, created.id)
        }),
      contentType: created['content-type']
    }
  }

  /**
   * Reads a resource by id, auto-parsing JSON to an object and returning binary
   * as a `Blob`. Returns `null` on a missing/unauthorized resource (404
   * conflation caveat).
   *
   * @param resourceId {string}
   * @returns {Promise<Json | Blob | null>}
   */
  async get(resourceId: string): Promise<Json | Blob | null> {
    const response = await send(this._context, {
      path: resourcePath(this.spaceId, this.id, resourceId),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return parseResource(response)
  }

  /**
   * Creates or replaces a resource by id (upsert).
   *
   * @param resourceId {string}
   * @param data {Json | Blob | Uint8Array}
   * @param options {object}
   * @param [options.contentType] {string}   content-type for binary data
   * @returns {Promise<void>}
   */
  async put(
    resourceId: string,
    data: Json | Blob | Uint8Array,
    options: { contentType?: string } = {}
  ): Promise<void> {
    await this.resource(resourceId).put(data, options)
  }

  /**
   * Lists the items in the collection. Returns `null` if the collection is
   * missing or not visible to you (404 conflation caveat).
   *
   * @returns {Promise<CollectionResourcesList | null>}
   */
  async list(): Promise<CollectionResourcesList | null> {
    const response = await send(this._context, {
      path: this._itemsPath,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as CollectionResourcesList)
  }

  /**
   * Delegates access to this collection. Prefills the grant `target` with this
   * collection's URL (and the bound `capability`, if any, for re-delegation).
   *
   * @param options {GrantOptions}
   * @returns {Promise<IDelegatedZcap>}
   */
  async grant(options: GrantOptions): Promise<IDelegatedZcap> {
    return delegateGrant(this._context, {
      ...options,
      target:
        options.target ??
        toUrl({ serverUrl: this._context.serverUrl, path: this._path }),
      capability: options.capability ?? this._capability
    })
  }

  /**
   * Reads the collection's access-control policy. Returns `null` when no policy
   * is set (or it is not visible to you). Managing a policy is a controller-level
   * operation; a capability scoped to the collection does not cover its policy
   * sub-resource.
   *
   * @returns {Promise<PolicyDocument | null>}
   */
  async getPolicy(): Promise<PolicyDocument | null> {
    const response = await send(this._context, {
      path: collectionPolicy(this.spaceId, this.id),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as PolicyDocument)
  }

  /**
   * Sets (creates or replaces) the collection's access-control policy.
   *
   * @param policy {PolicyDocument}
   * @returns {Promise<void>}
   */
  async setPolicy(policy: PolicyDocument): Promise<void> {
    await send(this._context, {
      path: collectionPolicy(this.spaceId, this.id),
      method: 'PUT',
      capability: this._capability,
      json: policy
    })
  }

  /**
   * Returns `true` when this collection's policy is `PublicCanRead`.
   *
   * @returns {Promise<boolean>}
   */
  async isPublic(): Promise<boolean> {
    const policy = await this.getPolicy()
    return policy?.type === 'PublicCanRead'
  }

  /**
   * Makes the collection world-readable: every resource in it becomes readable
   * without authorization (unless overridden by a more specific policy). Sugar
   * for `setPolicy({ type: 'PublicCanRead' })`.
   *
   * @returns {Promise<void>}
   */
  async setPublic(): Promise<void> {
    await this.setPolicy({ type: 'PublicCanRead' })
  }

  /**
   * Removes the collection's access-control policy, reverting it to
   * capability-only access. Idempotent.
   *
   * @returns {Promise<void>}
   */
  async clearPolicy(): Promise<void> {
    await send(this._context, {
      path: collectionPolicy(this.spaceId, this.id),
      method: 'DELETE',
      capability: this._capability,
      idempotent: true
    })
  }

  /**
   * Reads the collection's linkset (RFC9264 policy discovery). Returns `null`
   * if the collection is missing or not visible to you.
   *
   * @returns {Promise<LinkSet | null>}
   */
  async linkset(): Promise<LinkSet | null> {
    const response = await send(this._context, {
      path: collectionLinkset(this.spaceId, this.id),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as LinkSet)
  }

  /**
   * Reads the storage backend this collection is stored on ("Collection Backend
   * Selected"). Returns `null` if the collection is missing or not visible to
   * you (404 conflation caveat). A server without backend support surfaces its
   * 501 as `NotImplementedError`.
   *
   * The descriptor's optional `features` array advertises backend capabilities;
   * `features` containing `'encrypted-documents'` is the signal a client gates
   * client-side encryption on (the future EDV codec encrypts only when the
   * backend advertises it AND the client holds keys for the collection). An
   * absent feature means the backend makes no claim to it -- treat it as
   * unsupported rather than assuming a default.
   *
   * @returns {Promise<BackendDescriptor | null>}
   */
  async backend(): Promise<BackendDescriptor | null> {
    const response = await send(this._context, {
      path: collectionBackend(this.spaceId, this.id),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as BackendDescriptor)
  }

  /**
   * Reads the collection's storage usage report, scoped to its backend (spec
   * "Quotas"). Returns `null` if the collection is missing or not visible to you
   * (404 conflation caveat). A backend that cannot account per-collection
   * surfaces its 501 as `NotImplementedError`.
   *
   * @returns {Promise<BackendUsage | null>}
   */
  async quota(): Promise<BackendUsage | null> {
    const response = await send(this._context, {
      path: collectionQuota(this.spaceId, this.id),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as BackendUsage)
  }
}
