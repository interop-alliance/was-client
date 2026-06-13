/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A navigational handle to a Space. Exposes its own lifecycle
 * (`describe`/`configure`/`delete`), contained Collections
 * (`collection`/`createCollection`/`collections`), delegation (`grant`), and
 * whole-space `export`/`import`.
 */
import {
  spacePath,
  spaceItems,
  spaceCollections,
  spaceExport,
  spaceImport,
  spaceBackends,
  spaceQuotas,
  spacePolicy,
  spaceLinkset,
  toUrl
} from './internal/paths.js'
import { assertNotReserved } from './internal/reserved.js'
import { delegateGrant } from './internal/grant.js'
import type { ClientContext } from './internal/request.js'
import { send } from './internal/request.js'
import { Collection } from './Collection.js'
import type {
  BackendDescriptor,
  BackendReference,
  CollectionDescription,
  CollectionListing,
  GrantOptions,
  HandleOptions,
  IDelegatedZcap,
  IZcap,
  ImportStats,
  LinkSet,
  PolicyDocument,
  SpaceDescription,
  SpaceQuotaReport
} from './types.js'

export class Space {
  readonly id: string

  private readonly _context: ClientContext
  private readonly _capability?: IZcap

  /**
   * @param options {object}
   * @param options.context {ClientContext}
   * @param options.spaceId {string}
   * @param [options.capability] {IZcap}   capability attached to every request
   */
  constructor({
    context,
    spaceId,
    capability
  }: {
    context: ClientContext
    spaceId: string
    capability?: IZcap
  }) {
    this._context = context
    this.id = spaceId
    this._capability = capability
  }

  private get _path(): string {
    return spacePath(this.id)
  }

  /**
   * Reads the Space Description. Returns `null` if the space is missing or not
   * visible to you (WAS returns 404 for both not-found and unauthorized).
   *
   * @returns {Promise<SpaceDescription | null>}
   */
  async describe(): Promise<SpaceDescription | null> {
    const response = await send(this._context, {
      path: this._path,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as SpaceDescription)
  }

  /**
   * Creates or updates the space by id (upsert). Merges the given fields over
   * the current description; `controller` defaults to the wrapped signer's DID.
   *
   * @param desc {object}
   * @param [desc.name] {string}
   * @param [desc.controller] {string}
   * @returns {Promise<SpaceDescription>}
   */
  async configure(desc: {
    name?: string
    controller?: string
  }): Promise<SpaceDescription> {
    const current = await this.describe()
    const name = desc.name ?? current?.name
    const controller =
      desc.controller ?? current?.controller ?? this._context.controllerDid
    await send(this._context, {
      path: this._path,
      method: 'PUT',
      capability: this._capability,
      json: { id: this.id, name, controller }
    })
    return {
      id: this.id,
      type: current?.type ?? ['Space'],
      ...(name !== undefined ? { name } : {}),
      controller
    }
  }

  /**
   * Deletes the space. Idempotent.
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
   * Returns a lazy handle to a collection by id. No I/O.
   *
   * @param collectionId {string}
   * @param options {object}
   * @param [options.capability] {IZcap}
   * @returns {Collection}
   */
  collection(collectionId: string, options: HandleOptions = {}): Collection {
    return new Collection({
      context: this._context,
      spaceId: this.id,
      collectionId,
      capability: options.capability ?? this._capability
    })
  }

  /**
   * Creates a collection within the space (server-generated id unless `id` is
   * given). Throws `NotFoundError` if the space does not exist.
   *
   * @param desc {object}
   * @param [desc.id] {string}
   * @param [desc.name] {string}
   * @param [desc.backend] {BackendReference}
   * @returns {Promise<Collection>}
   */
  async createCollection(
    desc: { id?: string; name?: string; backend?: BackendReference } = {}
  ): Promise<Collection> {
    if (desc.id !== undefined) {
      assertNotReserved(desc.id, 'collection')
    }
    const body: Record<string, unknown> = {}
    if (desc.id !== undefined) {
      body.id = desc.id
    }
    if (desc.name !== undefined) {
      body.name = desc.name
    }
    if (desc.backend) {
      body.backend = desc.backend
    }
    const response = await send(this._context, {
      path: spaceItems(this.id),
      method: 'POST',
      capability: this._capability,
      json: body
    })
    const created = (response as { data?: unknown })
      .data as CollectionDescription
    return this.collection(created.id)
  }

  /**
   * Lists the collections in the space. Returns `null` if the space is missing
   * or not visible to you (404 conflation caveat).
   *
   * @returns {Promise<CollectionListing | null>}
   */
  async collections(): Promise<CollectionListing | null> {
    const response = await send(this._context, {
      path: spaceCollections(this.id),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as CollectionListing)
  }

  /**
   * Lists the storage backends available within this space. Returns `null` if
   * the space is missing or not visible to you (404 conflation caveat). A
   * server without backend support surfaces its 501 as `NotImplementedError`.
   *
   * @returns {Promise<BackendDescriptor[] | null>}
   */
  async backends(): Promise<BackendDescriptor[] | null> {
    const response = await send(this._context, {
      path: spaceBackends(this.id),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as BackendDescriptor[])
  }

  /**
   * Reads the space's storage quota report, grouped by backend. Returns `null`
   * if the space is missing or not visible to you (404 conflation caveat). A
   * server without quota support surfaces its 501 as `NotImplementedError`.
   *
   * @returns {Promise<SpaceQuotaReport | null>}
   */
  async quotas(): Promise<SpaceQuotaReport | null> {
    const response = await send(this._context, {
      path: spaceQuotas(this.id),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as SpaceQuotaReport)
  }

  /**
   * Delegates access to this space. Prefills the grant `target` with this
   * space's URL (and the bound `capability`, if any, for re-delegation).
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
   * Exports the whole space as a tar (`application/x-tar`) archive.
   *
   * @returns {Promise<Uint8Array>}
   */
  async export(): Promise<Uint8Array> {
    const response = await send(this._context, {
      path: spaceExport(this.id),
      method: 'POST',
      capability: this._capability
    })
    // A successful export always returns a response (errors throw via send()).
    const buffer = await (
      response as { arrayBuffer(): Promise<ArrayBuffer> }
    ).arrayBuffer()
    return new Uint8Array(buffer)
  }

  /**
   * Imports (merges) a tar archive into the space.
   *
   * @param tar {Uint8Array | Blob}
   * @returns {Promise<ImportStats>}
   */
  async import(tar: Uint8Array | Blob): Promise<ImportStats> {
    const body =
      tar instanceof Uint8Array && tar.constructor !== Uint8Array
        ? new Uint8Array(tar.buffer, tar.byteOffset, tar.byteLength)
        : tar
    const response = await send(this._context, {
      path: spaceImport(this.id),
      method: 'POST',
      capability: this._capability,
      body,
      headers: { 'content-type': 'application/x-tar' }
    })
    return (response as { data?: unknown }).data as ImportStats
  }

  /**
   * Reads the space's access-control policy. Returns `null` when no policy is
   * set (or it is not visible to you). A space-level policy is inherited by all
   * collections and resources unless overridden by a more specific one. Managing
   * a policy is a controller-level operation.
   *
   * @returns {Promise<PolicyDocument | null>}
   */
  async getPolicy(): Promise<PolicyDocument | null> {
    const response = await send(this._context, {
      path: spacePolicy(this.id),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as PolicyDocument)
  }

  /**
   * Sets (creates or replaces) the space's access-control policy.
   *
   * @param policy {PolicyDocument}
   * @returns {Promise<void>}
   */
  async setPolicy(policy: PolicyDocument): Promise<void> {
    await send(this._context, {
      path: spacePolicy(this.id),
      method: 'PUT',
      capability: this._capability,
      json: policy
    })
  }

  /**
   * Returns `true` when this space's policy is `PublicCanRead`.
   *
   * @returns {Promise<boolean>}
   */
  async isPublic(): Promise<boolean> {
    const policy = await this.getPolicy()
    return policy?.type === 'PublicCanRead'
  }

  /**
   * Makes the whole space world-readable: every collection and resource under
   * it becomes readable without authorization (unless overridden by a more
   * specific policy). Sugar for `setPolicy({ type: 'PublicCanRead' })`.
   *
   * @returns {Promise<void>}
   */
  async setPublic(): Promise<void> {
    await this.setPolicy({ type: 'PublicCanRead' })
  }

  /**
   * Removes the space's access-control policy, reverting it to capability-only
   * access. Idempotent.
   *
   * @returns {Promise<void>}
   */
  async clearPolicy(): Promise<void> {
    await send(this._context, {
      path: spacePolicy(this.id),
      method: 'DELETE',
      capability: this._capability,
      idempotent: true
    })
  }

  /**
   * Reads the space's linkset (RFC9264 policy discovery). Returns `null` if the
   * space is missing or not visible to you.
   *
   * @returns {Promise<LinkSet | null>}
   */
  async linkset(): Promise<LinkSet | null> {
    const response = await send(this._context, {
      path: spaceLinkset(this.id),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as LinkSet)
  }
}
