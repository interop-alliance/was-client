/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A navigational handle to a Space. Exposes its own lifecycle
 * (`describe`/`configure`/`delete`), contained Collections
 * (`collection`/`createCollection`/`collections`), delegation (`grant`), and
 * whole-space `export`/`import`.
 */
import type { HttpResponse } from '@interop/http-client'
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
import { unreadableDescriptionError } from './internal/describe.js'
import { delegateGrantAt } from './internal/grant.js'
import { submitRevocation } from './internal/revoke.js'
import type { ClientContext } from './internal/request.js'
import { send, readData } from './internal/request.js'
import {
  buildPageWalk,
  collectWalk,
  walkPagesOrEmpty
} from './internal/pagination.js'
import type { PageWalk } from './internal/pagination.js'
import { WasServerError } from './errors.js'
import { createdId, dataOrNull, toPlainBytes } from './internal/content.js'
import {
  readPolicy,
  writePolicy,
  deletePolicy,
  isPublicPolicy,
  setPublicPolicy
} from './internal/policy.js'
import { Collection } from './Collection.js'
import type {
  BackendDescriptor,
  BackendReference,
  BackendRegistration,
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

  private get _policyPath(): string {
    return spacePolicy(this.id)
  }

  /**
   * Reads the Space Description. Returns `null` if the space is missing or not
   * visible to you (WAS returns 404 for both not-found and unauthorized).
   *
   * @returns {Promise<SpaceDescription | null>}
   */
  async describe(): Promise<SpaceDescription | null> {
    return readData<SpaceDescription>(this._context, {
      path: this._path,
      capability: this._capability
    })
  }

  /**
   * Creates or updates the space by id (upsert). Merges the given fields over
   * the current description; `controller` defaults to the wrapped signer's DID.
   *
   * Fails closed when the current description is unreadable and the caller did
   * not supply a full description (both `name` and `controller`), mirroring
   * {@link Collection.configure}: WAS returns 404 for both not-found and
   * unauthorized, so a write-capable but not read-capable caller invoking
   * `configure({ name })` would otherwise merge forward from a `null` current --
   * silently defaulting `controller` to the wrapped signer's DID (a stealth
   * ownership change) and dropping the existing `name`. Pass `force: true` to
   * proceed anyway (a deliberate create through a handle), or supply both
   * `name` and `controller` explicitly so nothing is merged from the unreadable
   * current.
   *
   * @param desc {object}
   * @param [desc.name] {string}
   * @param [desc.controller] {string}
   * @param [desc.force] {boolean}   proceed even when the current description is
   *   unreadable and a full description is not supplied (see above)
   * @returns {Promise<SpaceDescription>}
   */
  async configure(desc: {
    name?: string
    controller?: string
    force?: boolean
  }): Promise<SpaceDescription> {
    const current = await this.describe()
    if (
      current === null &&
      !desc.force &&
      !(desc.name !== undefined && desc.controller !== undefined)
    ) {
      throw unreadableDescriptionError({
        operation: `configure space "${this.id}"`,
        consequence:
          'merging forward could silently change the controller or drop the ' +
          'existing name',
        advice:
          'Supply both `name` and `controller` explicitly, use a ' +
          'read-capable capability, or pass `force: true` if you are ' +
          'creating a new space.'
      })
    }
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
      assertNotReserved({ id: desc.id, kind: 'collection' })
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
    // Pre-seed the handle with an override matching the just-declared scheme so
    // the first write encrypts immediately (keys come from the keystore); no
    // describe() round-trip needed before the marker is locally known. A
    // `CollectionEncryption` marker is itself a valid `EncryptionOverride`.
    return this.collection(createdId(response), {
      encryption: desc.encryption
    })
  }

  /**
   * Reads the first page of the collections listing and packages the means to
   * follow its `next` links (each page fetched with the same authorization).
   * Returns `null` if the space is missing or not visible to you (404 conflation
   * caveat).
   *
   * @returns {Promise<PageWalk<CollectionsList> | null>}
   */
  private async _collectionsWalk(): Promise<PageWalk<CollectionsList> | null> {
    return buildPageWalk<CollectionsList>({
      firstUrl: toUrl({
        serverUrl: this._context.serverUrl,
        path: spaceCollections(this.id)
      }),
      fetchPage: async url => {
        const pageResponse = await send(this._context, {
          url,
          method: 'GET',
          capability: this._capability,
          read: true
        })
        return dataOrNull<CollectionsList>(pageResponse)
      }
    })
  }

  /**
   * Lists the collections in the space. Transparently follows the server's
   * `next` pagination links, buffering every page into a single list (the
   * returned envelope omits `next`). Convenient, but holds the whole listing in
   * memory -- for a large space prefer `collectionsPages()`, which streams one
   * page at a time and allows stopping early. Returns `null` if the space is
   * missing or not visible to you (404 conflation caveat).
   *
   * @returns {Promise<CollectionsList | null>}
   */
  async collections(): Promise<CollectionsList | null> {
    return collectWalk(await this._collectionsWalk())
  }

  /**
   * Lazily yields the collections listing one page at a time, following the
   * server's `next` links on demand (each page fetched with the same
   * authorization). Use this to stream a large space in constant memory or to
   * stop early. Yields nothing if the space is missing or not visible to you
   * (404 conflation caveat) -- unlike `collections()`, the iterator does not
   * distinguish that from an empty space.
   *
   * @returns {AsyncGenerator<CollectionsList>}
   */
  async *collectionsPages(): AsyncGenerator<CollectionsList> {
    yield* walkPagesOrEmpty(await this._collectionsWalk())
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
    return readData<BackendDescriptor[]>(this._context, {
      path: spaceBackends(this.id),
      capability: this._capability
    })
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
   *   (`{ id, provider, connection: { kind, ... }, name?, storageMode?, features? }`)
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
    // A successful registration always carries the sanitized descriptor body.
    return dataOrNull<BackendDescriptor>(response)!
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
    // carries no body, which `dataOrNull` maps to `null`.
    return dataOrNull<BackendDescriptor>(response)
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
    return readData<SpaceQuotaReport>(this._context, {
      path,
      capability: this._capability
    })
  }

  /**
   * Delegates access to this space. Prefills the grant `target` with this
   * space's URL (and the bound `capability`, if any, for re-delegation).
   *
   * @param options {GrantOptions}
   * @returns {Promise<IDelegatedZcap>}
   */
  async grant(options: GrantOptions): Promise<IDelegatedZcap> {
    return delegateGrantAt(this._context, {
      path: this._path,
      options,
      capability: this._capability
    })
  }

  /**
   * Revokes a capability rooted in this space -- the inverse of {@link grant}.
   * From then on the capability is rejected wherever a Space-rooted chain is
   * verified: writes, privileged routes, and the capability leg of reads.
   *
   * Two callers are authorized: this space's controller, and any controller in
   * the capability's own delegation chain (so a delegee can revoke the
   * capability it holds, without a separate grant). Anyone else gets a
   * `NotFoundError`, as does a capability rooted in a different space.
   *
   * Revocation withdraws only what the *capability* granted. Access an
   * access-control policy grants independently survives it, so a `PublicCanRead`
   * target stays publicly readable afterwards. It is also prospective: a revoked
   * reader of an encrypted collection still holds the keys for ciphertext it
   * already fetched.
   *
   * **Not idempotent.** Revoking an already-revoked capability throws
   * `ValidationError` (the server's 400), because its chain now contains a
   * revoked link. The server reports that with the same problem type it uses for
   * a tampered, expired, or foreign-rooted capability, so this method cannot
   * distinguish them and does not swallow any of them. Catch `ValidationError`
   * if you want revoking twice to be a no-op.
   *
   * @param zcap {IDelegatedZcap}   the delegated capability to revoke
   * @returns {Promise<void>}
   */
  async revoke(zcap: IDelegatedZcap): Promise<void> {
    return submitRevocation(this._context, { spaceId: this.id, zcap })
  }

  /**
   * Sends the export request and returns the raw response with its body stream
   * intact, shared by `export`/`exportBlob`/`exportStream`.
   *
   * Guards the JSON-mislabel edge: `@interop/http-client` pre-consumes a
   * response body into `.data` for JSON content-types, so a non-conformant
   * server that labels the tar archive `application/json` would leave us a dead
   * stream. Detecting the consumed body here fails with a typed `WasServerError`
   * naming the mislabeled content-type, rather than a raw "body stream already
   * read" `TypeError` downstream.
   *
   * @returns {Promise<HttpResponse>}
   */
  private async _exportResponse(): Promise<HttpResponse> {
    const response = (await send(this._context, {
      path: spaceExport(this.id),
      method: 'POST',
      capability: this._capability
      // A successful export always returns a response (errors throw via send()).
    })) as HttpResponse
    if (response.bodyUsed || response.data !== undefined) {
      const contentType =
        response.headers.get('content-type') ?? 'an unknown content-type'
      throw new WasServerError(
        `Export response body was already consumed (mislabeled as ` +
          `${contentType}); expected application/x-tar.`
      )
    }
    return response
  }

  /**
   * Exports the whole space as a tar (`application/x-tar`) archive.
   *
   * The entire archive is buffered into memory (a `Uint8Array` cannot be
   * produced incrementally), so exporting a very large space costs its full
   * size in RAM. For a constant-memory path use {@link exportStream}; for the
   * `import()` companion container use {@link exportBlob}.
   *
   * @returns {Promise<Uint8Array>}
   */
  async export(): Promise<Uint8Array> {
    const response = await this._exportResponse()
    return new Uint8Array(await response.arrayBuffer())
  }

  /**
   * Exports the whole space as a tar (`application/x-tar`) archive, as a Blob
   * typed `application/x-tar`. Pairs directly with `import(tar)`, so copying a
   * space is `spaceB.import(await spaceA.exportBlob())`.
   *
   * Note: in Node a Blob is memory-backed, so this does not reduce peak memory
   * versus {@link export} -- it is a typed-container convenience (browsers may
   * spill large Blobs to disk). For the true constant-memory path use
   * {@link exportStream}.
   *
   * @returns {Promise<Blob>}
   */
  async exportBlob(): Promise<Blob> {
    const blob = await (await this._exportResponse()).blob()
    // Normalize the type: some servers omit or mislabel the content-type, and
    // `Blob.type` is load-bearing for `import()` / anchor-download flows.
    return blob.type === 'application/x-tar'
      ? blob
      : new Blob([blob], { type: 'application/x-tar' })
  }

  /**
   * Exports the whole space as a tar (`application/x-tar`) archive, as a lazily
   * consumed byte stream -- constant memory, for piping to a file, a
   * `CompressionStream`, or another request.
   *
   * The stream must be consumed or cancelled; an abandoned stream holds its
   * connection open.
   *
   * @returns {Promise<ReadableStream<Uint8Array>>}
   */
  async exportStream(): Promise<ReadableStream<Uint8Array>> {
    const response = await this._exportResponse()
    if (response.body === null) {
      // A body-less 2xx (204, or an exotic fetch impl) -- fail with a typed
      // error rather than returning a null stream.
      throw new WasServerError('Export response carried no body stream.')
    }
    return response.body as ReadableStream<Uint8Array>
  }

  /**
   * Imports (merges) a tar archive into the space.
   *
   * @param tar {Uint8Array | Blob}
   * @returns {Promise<ImportStats>}
   */
  async import(tar: Uint8Array | Blob): Promise<ImportStats> {
    const body = tar instanceof Uint8Array ? toPlainBytes(tar) : tar
    const response = await send(this._context, {
      path: spaceImport(this.id),
      method: 'POST',
      capability: this._capability,
      body,
      headers: { 'content-type': 'application/x-tar' }
    })
    // A successful import always carries the stats body.
    return dataOrNull<ImportStats>(response)!
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
    return readPolicy(this._context, {
      policyPath: this._policyPath,
      capability: this._capability
    })
  }

  /**
   * Sets (creates or replaces) the space's access-control policy.
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
   * Returns `true` when this space's policy is `PublicCanRead`.
   *
   * @returns {Promise<boolean>}
   */
  async isPublic(): Promise<boolean> {
    return isPublicPolicy(this._context, {
      policyPath: this._policyPath,
      capability: this._capability
    })
  }

  /**
   * Makes the whole space world-readable: every collection and resource under
   * it becomes readable without authorization (unless overridden by a more
   * specific policy). Sugar for `setPolicy({ type: 'PublicCanRead' })`.
   *
   * @returns {Promise<void>}
   */
  async setPublic(): Promise<void> {
    return setPublicPolicy(this._context, {
      policyPath: this._policyPath,
      capability: this._capability
    })
  }

  /**
   * Removes the space's access-control policy, reverting it to capability-only
   * access. Idempotent.
   *
   * @returns {Promise<void>}
   */
  async clearPolicy(): Promise<void> {
    return deletePolicy(this._context, {
      policyPath: this._policyPath,
      capability: this._capability
    })
  }

  /**
   * Reads the space's linkset (RFC9264 policy discovery). Returns `null` if the
   * space is missing or not visible to you.
   *
   * @returns {Promise<LinkSet | null>}
   */
  async linkset(): Promise<LinkSet | null> {
    return readData<LinkSet>(this._context, {
      path: spaceLinkset(this.id),
      capability: this._capability
    })
  }
}
