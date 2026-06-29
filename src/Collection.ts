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
import { assertNotReserved } from './internal/reserved.js'
import { delegateGrant } from './internal/grant.js'
import type { ClientContext } from './internal/request.js'
import { send } from './internal/request.js'
import { resolveCodec } from './internal/codec.js'
import type { MarkerReadResult } from './internal/codec.js'
import { collectPages, walkPages } from './internal/pagination.js'
import type { PageWalk } from './internal/pagination.js'
import { describeCollection } from './internal/describe.js'
import { writeHeaders, readEtag } from './internal/conditional.js'
import type { ResourceCodec } from './codec.js'
import { Resource } from './Resource.js'
import type {
  AddResult,
  BackendDescriptor,
  BackendReference,
  BackendUsage,
  CollectionDescription,
  CollectionEncryption,
  EncryptionOverride,
  GrantOptions,
  HandleOptions,
  IDelegatedZcap,
  IZcap,
  Json,
  ResourceData,
  LinkSet,
  PolicyDocument,
  CollectionResourcesList,
  ResourceSummary
} from './types.js'

export class Collection {
  readonly spaceId: string
  readonly id: string

  private readonly _context: ClientContext
  private readonly _capability?: IZcap
  private readonly _encryptionOverride?: EncryptionOverride
  private _codecPromise?: Promise<ResourceCodec>

  /**
   * @param options {object}
   * @param options.context {ClientContext} - Shared context (serverUrl, ezcap
   *   client, controllerDid)
   * @param options.spaceId {string}
   * @param options.collectionId {string}
   * @param [options.capability] {IZcap} - capability attached to every request
   * @param [options.encryption] {EncryptionOverride} - per-handle encryption
   *   override; wins over the Collection's declared marker and skips the
   *   marker-discovery round-trip
   */
  constructor({
    context,
    spaceId,
    collectionId,
    capability,
    encryption
  }: {
    context: ClientContext
    spaceId: string
    collectionId: string
    capability?: IZcap
    encryption?: EncryptionOverride
  }) {
    this._context = context
    this.spaceId = spaceId
    this.id = collectionId
    this._capability = capability
    this._encryptionOverride = encryption
  }

  private get _path(): string {
    return collectionPath(this.spaceId, this.id)
  }

  private get _itemsPath(): string {
    return collectionItems(this.spaceId, this.id)
  }

  /**
   * Resolves (once, then caches) the codec for this collection's reads and
   * writes: the identity codec for a plaintext collection, or the encrypting
   * codec when this collection is declared encrypted -- by a per-handle override
   * or its `encryption` marker -- and the client's keystore supplies its keys.
   * An encrypted collection the client cannot key for fails closed (throws), and
   * a successful marker read happens at most once per handle (memoized here) -- a
   * fresh handle to the same collection re-reads it, so retain the handle to
   * reuse it. A failed resolution (e.g. a transient 500/network error during
   * marker discovery) is not memoized: the cache is cleared so the next call
   * retries rather than re-throwing the stale error forever.
   *
   * @returns {Promise<ResourceCodec>}
   */
  private _codec(): Promise<ResourceCodec> {
    if (this._codecPromise) {
      return this._codecPromise
    }
    const promise = resolveCodec(this._context, {
      spaceId: this.spaceId,
      collectionId: this.id,
      override: this._encryptionOverride,
      readMarker: async (): Promise<MarkerReadResult> => {
        const description = await this.describe()
        return description === null
          ? { readable: false }
          : { readable: true, encryption: description.encryption }
      }
    })
    // Memoize the in-flight promise so concurrent callers share one round-trip,
    // but drop it on rejection so a transient failure does not permanently
    // poison the handle. The identity guard avoids clobbering a newer promise.
    this._codecPromise = promise
    promise.catch((): void => {
      if (this._codecPromise === promise) {
        this._codecPromise = undefined
      }
    })
    return promise
  }

  /**
   * Reads the Collection Description. Returns `null` if the collection is
   * missing or not visible to you (WAS returns 404 for both not-found and
   * unauthorized).
   *
   * @returns {Promise<CollectionDescription | null>}
   */
  async describe(): Promise<CollectionDescription | null> {
    return describeCollection(this._context, {
      spaceId: this.spaceId,
      collectionId: this.id,
      capability: this._capability
    })
  }

  /**
   * Creates or updates the collection by id (upsert). Merges the given fields
   * over the current description.
   *
   * @param desc {object}
   * @param [desc.name] {string}
   * @param [desc.backend] {BackendReference}
   * @param [desc.encryption] {CollectionEncryption}   declare the client-side
   *   encryption marker. Set-once on the server: it may be added to a Collection
   *   that lacks one, but changing/clearing an existing marker is rejected
   *   (`ConflictError`, `encryption-immutable`).
   * @returns {Promise<CollectionDescription>}
   */
  async configure(desc: {
    name?: string
    backend?: BackendReference
    encryption?: CollectionEncryption
  }): Promise<CollectionDescription> {
    assertNotReserved(this.id, 'collection')
    const current = await this.describe()
    const name = desc.name ?? current?.name
    const body: Record<string, unknown> = { id: this.id, name }
    if (desc.backend) {
      body.backend = desc.backend
    }
    if (desc.encryption) {
      body.encryption = desc.encryption
    }
    await send(this._context, {
      path: this._path,
      method: 'PUT',
      capability: this._capability,
      json: body
    })
    // Adding the encryption marker flips this collection from plaintext to
    // encrypted server-side. Drop any codec memoized from the prior (plaintext)
    // marker so the next read/write re-resolves it -- otherwise a `put` would
    // reuse the cached identity codec and write server-visible plaintext into
    // the now-encrypted collection. Child resource handles share this codec via
    // their thunk, so resetting here propagates to them too.
    if (desc.encryption) {
      this._codecPromise = undefined
    }
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
      capability: options.capability ?? this._capability,
      // Share this collection's resolved codec so a resource handle does not
      // repeat the backend() round-trip.
      codec: () => this._codec()
    })
  }

  /**
   * Adds a resource with a server-generated id. JSON for plain objects/arrays,
   * binary for `Blob`/`Uint8Array`. Throws `NotFoundError` if the collection
   * does not exist (WAS does not auto-create parents).
   *
   * @param data {ResourceData}
   * @param options {object}
   * @param [options.contentType] {string}   content-type for binary data
   * @returns {Promise<AddResult>}
   */
  async add(
    data: ResourceData,
    options: { contentType?: string } = {}
  ): Promise<AddResult> {
    const codec = await this._codec()
    const encoded = await codec.encode({
      data,
      contentType: options.contentType
    })
    // A codec may attach a create-if-absent precondition for its minted id (the
    // EDV codec guards a fresh insert with `If-None-Match: *`); plaintext add
    // carries none.
    const headers = writeHeaders(encoded.contentType, {
      ifMatch: encoded.ifMatch,
      ifNoneMatch: encoded.ifNoneMatch
    })

    // A codec that mints its own id (e.g. the encrypting codec's EDV id) writes
    // by `PUT`; the identity codec returns no id and lets the server mint one
    // via `POST`.
    if (encoded.id !== undefined) {
      const path = resourcePath(this.spaceId, this.id, encoded.id)
      const response = await send(this._context, {
        path,
        method: 'PUT',
        capability: this._capability,
        json: encoded.json,
        body: encoded.body,
        headers
      })
      return {
        id: encoded.id,
        url: toUrl({ serverUrl: this._context.serverUrl, path }),
        contentType: encoded.contentType,
        etag: readEtag(response)
      }
    }

    const response = await send(this._context, {
      path: this._itemsPath,
      method: 'POST',
      capability: this._capability,
      json: encoded.json,
      body: encoded.body,
      headers
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
      contentType: created['content-type'],
      etag: readEtag(response)
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
    const codec = await this._codec()
    const response = await send(this._context, {
      path: resourcePath(this.spaceId, this.id, resourceId),
      method: 'GET',
      capability: this._capability,
      read: true
    })
    return response === null ? null : codec.decode(response)
  }

  /**
   * Creates or replaces a resource by id (upsert). Forwards the conditional-write
   * options (`ifMatch` / `ifNoneMatch`) to `Resource.put`; see it for the
   * `conditional-writes` semantics. Returns the stored resource's new `etag`.
   *
   * @param resourceId {string}
   * @param data {ResourceData}
   * @param options {object}
   * @param [options.contentType] {string}   content-type for binary data
   * @param [options.ifMatch] {string}       update only if the ETag matches
   * @param [options.ifNoneMatch] {boolean}  create only if absent
   * @returns {Promise<{ etag?: string }>}
   */
  async put(
    resourceId: string,
    data: ResourceData,
    options: {
      contentType?: string
      ifMatch?: string
      ifNoneMatch?: boolean
    } = {}
  ): Promise<{ etag?: string }> {
    return this.resource(resourceId).put(data, options)
  }

  /**
   * Reads the first page of the listing and packages the means to follow its
   * `next` links (each page fetched with the same authorization). Returns `null`
   * if the collection is missing or not visible to you (404 conflation caveat).
   *
   * @returns {Promise<PageWalk | null>}
   */
  private async _listWalk(): Promise<PageWalk | null> {
    const response = await send(this._context, {
      path: this._itemsPath,
      method: 'GET',
      capability: this._capability,
      read: true
    })
    if (response === null) {
      return null
    }
    return {
      first: response.data as CollectionResourcesList,
      firstUrl: toUrl({
        serverUrl: this._context.serverUrl,
        path: this._itemsPath
      }),
      fetchPage: async url => {
        const pageResponse = await send(this._context, {
          url,
          method: 'GET',
          capability: this._capability,
          read: true
        })
        return pageResponse === null
          ? null
          : (pageResponse.data as CollectionResourcesList)
      }
    }
  }

  /**
   * Lists the items in the collection. Transparently follows the server's `next`
   * pagination links, buffering every page into a single list (the returned
   * envelope omits `next`). Convenient, but holds the whole collection in memory
   * -- for a large collection prefer `listPages()` or `listItems()`, which stream
   * one page at a time and allow stopping early. Returns `null` if the collection
   * is missing or not visible to you (404 conflation caveat).
   *
   * @returns {Promise<CollectionResourcesList | null>}
   */
  async list(): Promise<CollectionResourcesList | null> {
    const walk = await this._listWalk()
    return walk === null ? null : collectPages(walk)
  }

  /**
   * Lazily yields the listing one page at a time, following the server's `next`
   * links on demand (each page fetched with the same authorization). Use this to
   * stream a large collection in constant memory or to stop early. Yields nothing
   * if the collection is missing or not visible to you (404 conflation caveat) --
   * unlike `list()`, the iterator does not distinguish that from an empty
   * collection.
   *
   * @returns {AsyncGenerator<CollectionResourcesList>}
   */
  async *listPages(): AsyncGenerator<CollectionResourcesList> {
    const walk = await this._listWalk()
    if (walk === null) {
      return
    }
    yield* walkPages(walk)
  }

  /**
   * Lazily yields each item across every page, flattening `listPages()`. Yields
   * the listing's `ResourceSummary` entries (id / url / contentType / name), not
   * the resource bodies -- call `get(id)` to read a body. Yields nothing if the
   * collection is missing or not visible to you (404 conflation caveat).
   *
   * @returns {AsyncGenerator<ResourceSummary>}
   */
  async *listItems(): AsyncGenerator<ResourceSummary> {
    for await (const page of this.listPages()) {
      yield* page.items
    }
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
   * The descriptor's optional `features` array advertises optional server
   * affordances (e.g. `conditional-writes`, `blinded-index-query`,
   * `chunked-streams`); an absent token means the backend makes no claim to it,
   * so treat it as unsupported rather than assuming a default. (Client-side
   * encryption is not a backend feature -- it is a per-collection client concern
   * gated on the client's keys.)
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
