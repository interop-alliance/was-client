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
  registeredBackend,
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
  BackendRegistration,
  CollectionDescription,
  CollectionEncryption,
  CollectionsList,
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
      // `controller` is a user-supplied DID string; assert it as the branded
      // `IDID` the wire type now uses (the server validates the DID form).
      controller: controller as SpaceDescription['controller']
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
      capability: options.capability ?? this._capability,
      encryption: options.encryption
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
   * @param [desc.encryption] {CollectionEncryption}   declare the collection
   *   client-side encrypted (e.g. `{ scheme: 'edv' }`). The returned handle is
   *   pre-seeded with a matching encryption override, so the immediate next
   *   write encrypts without a marker-discovery round-trip.
   * @returns {Promise<Collection>}
   */
  async createCollection(
    desc: {
      id?: string
      name?: string
      backend?: BackendReference
      encryption?: CollectionEncryption
    } = {}
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
    if (desc.encryption) {
      body.encryption = desc.encryption
    }
    const response = await send(this._context, {
      path: spaceItems(this.id),
      method: 'POST',
      capability: this._capability,
      json: body
    })
    const created = (response as { data?: unknown })
      .data as CollectionDescription
    // Pre-seed the handle with an override matching the just-declared scheme so
    // the first write encrypts immediately (keys come from the keystore); no
    // describe() round-trip needed before the marker is locally known. A
    // `CollectionEncryption` marker is itself a valid `EncryptionOverride`.
    return this.collection(created.id, { encryption: desc.encryption })
  }

  /**
   * Lists the collections in the space. Returns `null` if the space is missing
   * or not visible to you (404 conflation caveat).
   *
   * @returns {Promise<CollectionsList | null>}
   */
  async collections(): Promise<CollectionsList | null> {
    const response = await send(this._context, {
      path: spaceCollections(this.id),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : (response.data as CollectionsList)
  }

  /**
   * Lists the storage backends available within this space. Returns `null` if
   * the space is missing or not visible to you (404 conflation caveat). A
   * server without backend support surfaces its 501 as `NotImplementedError`.
   *
   * Each descriptor's optional `features` array advertises optional server
   * affordances (e.g. `conditional-writes`). See {@link Collection.backend} for
   * the full note.
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
   * Registers a new `external` ("Bring Your Own Storage") backend against this
   * space (`POST /space/:id/backends`). The registration body carries the
   * secret-bearing `connection` (e.g. an OAuth authorization code); the server
   * persists it and returns the **sanitized** descriptor (no secrets). Requires
   * the Space controller's authority (the same key that owns the space).
   *
   * Throws `ConflictError` if a backend with this `id` already exists
   * (`id-conflict`) or the server does not permit the `provider`
   * (`unsupported-backend`), and `ValidationError` (400) for a malformed body
   * (e.g. the reserved `default` id). To replace an existing backend's
   * connection (the re-consent path), use {@link updateBackend}.
   *
   * @param registration {BackendRegistration}   the backend to register
   *   (`{ id, provider, connection: { kind, … }, name?, storageMode?, features? }`)
   * @returns {Promise<BackendDescriptor>}   the sanitized descriptor of the
   *   newly registered backend
   */
  async registerBackend(
    registration: BackendRegistration
  ): Promise<BackendDescriptor> {
    const response = await send(this._context, {
      path: spaceBackends(this.id),
      method: 'POST',
      capability: this._capability,
      json: registration
    })
    return (response as { data?: unknown }).data as BackendDescriptor
  }

  /**
   * Creates or replaces a registered `external` backend by id
   * (`PUT /space/:id/backends/:id`) -- the re-consent / refresh path, used to
   * swap in fresh `connection` material after a backend's status went `expired`
   * or `revoked`. The target id is taken from `registration.id`. Requires the
   * Space controller's authority.
   *
   * Returns the sanitized descriptor when the PUT **created** a new record (the
   * server replies 201 with a body); returns `null` when it **replaced** an
   * existing record in place (the server replies 204, no body) -- read it back
   * with {@link backends} if you need the refreshed descriptor.
   *
   * @param registration {BackendRegistration}   the backend to upsert; its `id`
   *   selects the target record
   * @returns {Promise<BackendDescriptor | null>}   the descriptor on create, or
   *   `null` on in-place replace
   */
  async updateBackend(
    registration: BackendRegistration
  ): Promise<BackendDescriptor | null> {
    const response = await send(this._context, {
      path: registeredBackend(this.id, registration.id),
      method: 'PUT',
      capability: this._capability,
      json: registration
    })
    // 201 (create) carries the sanitized descriptor; 204 (in-place replace)
    // carries no body, so `data` is undefined.
    return ((response as { data?: unknown } | null)?.data ??
      null) as BackendDescriptor | null
  }

  /**
   * Deregisters (forgets) a registered `external` backend by id
   * (`DELETE /space/:id/backends/:id`). Idempotent -- deregistering an absent
   * backend still resolves. Requires the Space controller's authority.
   *
   * This removes the server's record and its stored connection; whether the
   * upstream provider grant (e.g. an OAuth refresh token) is also revoked is a
   * server/provider concern, not guaranteed by this call.
   *
   * @param backendId {string}   the registered backend's id
   * @returns {Promise<void>}
   */
  async deregisterBackend(backendId: string): Promise<void> {
    await send(this._context, {
      path: registeredBackend(this.id, backendId),
      method: 'DELETE',
      capability: this._capability,
      idempotent: true
    })
  }

  /**
   * Reads the space's storage quota report, grouped by backend. Returns `null`
   * if the space is missing or not visible to you (404 conflation caveat). A
   * server without quota support surfaces its 501 as `NotImplementedError`.
   *
   * @param [options] {object}
   * @param [options.includeCollections] {boolean}   request the per-Collection
   *   `usageByCollection` breakdown on each backend entry (the spec's
   *   `?include=collections` opt-in); omitted by default to keep the report lean
   * @returns {Promise<SpaceQuotaReport | null>}
   */
  async quotas({
    includeCollections = false
  }: { includeCollections?: boolean } = {}): Promise<SpaceQuotaReport | null> {
    const path = includeCollections
      ? `${spaceQuotas(this.id)}?include=collections`
      : spaceQuotas(this.id)
    const response = await send(this._context, {
      path,
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
