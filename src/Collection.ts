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
import { ValidationError } from './errors.js'
import { delegateGrantAt } from './internal/grant.js'
import type { ClientContext } from './internal/request.js'
import { send, readData } from './internal/request.js'
import { CodecHolder, resolveCodec } from './internal/codec.js'
import {
  buildPageWalk,
  collectPages,
  walkPages
} from './internal/pagination.js'
import type { PageWalk } from './internal/pagination.js'
import { describeCollection } from './internal/describe.js'
import { readEtag } from './internal/conditional.js'
import { sendEncodedWrite } from './internal/write.js'
import { readPolicy, writePolicy, deletePolicy } from './internal/policy.js'
import { createdId, dataOrNull } from './internal/content.js'
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
  private readonly _codecHolder: CodecHolder

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
    // Guard the id against the Reserved Path Segment Registry up front
    // (mirroring the `Resource` constructor), so a reserved id from caller
    // input can never be mis-targeted at a space-level endpoint.
    // `collectionPath(s, 'policy')` is byte-identical to the space policy path,
    // so an unguarded `collection('policy').delete()` would silently wipe the
    // space's access-control policy; the same collision exists for `backends` /
    // `quotas` / `linkset` / `export` / `import` / `query`. Guarding in the
    // constructor covers every operation (describe, delete, list, grant, ...),
    // not just writes.
    assertNotReserved({ id: collectionId, kind: 'collection' })
    this._context = context
    this.spaceId = spaceId
    this.id = collectionId
    this._capability = capability
    this._encryptionOverride = encryption
    this._codecHolder = new CodecHolder(() =>
      resolveCodec(this._context, {
        spaceId: this.spaceId,
        collectionId: this.id,
        override: this._encryptionOverride,
        capability: this._capability
      })
    )
  }

  private get _path(): string {
    return collectionPath(this.spaceId, this.id)
  }

  private get _itemsPath(): string {
    return collectionItems(this.spaceId, this.id)
  }

  private get _policyPath(): string {
    return collectionPolicy(this.spaceId, this.id)
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
    return this._codecHolder.get()
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
   * The merge needs a readable current description to be lost-update-safe, and
   * `describe()` cannot distinguish "absent" from "unreadable" (WAS masks
   * unauthorized reads as 404). When it returns `null` and neither `backend`
   * nor `encryption` is supplied, this fails closed rather than sending a PUT
   * body that would silently drop an existing collection's `backend` (a
   * data-placement change) or trip `encryption-immutable` by clearing its
   * marker on a replace-semantics server. Pass `force: true` to proceed anyway
   * -- e.g. when creating a new collection through a handle (or use
   * `space.createCollection()`, which does not merge).
   *
   * @param desc {object}
   * @param [desc.name] {string}
   * @param [desc.backend] {BackendReference}
   * @param [desc.encryption] {CollectionEncryption}   declare the client-side
   *   encryption marker. Set-once on the server: it may be added to a Collection
   *   that lacks one, but changing/clearing an existing marker is rejected
   *   (`ConflictError`, `encryption-immutable`).
   * @param [desc.force] {boolean}   proceed even when the current description
   *   is unreadable and `backend`/`encryption` are omitted (see above)
   * @returns {Promise<CollectionDescription>}
   */
  async configure(desc: {
    name?: string
    backend?: BackendReference
    encryption?: CollectionEncryption
    force?: boolean
  }): Promise<CollectionDescription> {
    const current = await this.describe()
    if (
      current === null &&
      desc.backend === undefined &&
      desc.encryption === undefined &&
      !desc.force
    ) {
      throw new ValidationError(
        `Cannot configure collection "${this.id}": its current description ` +
          'is not readable with this capability (WAS returns 404 for both ' +
          'not-found and unauthorized), so merging forward could silently ' +
          "drop an existing collection's backend or encryption marker. " +
          'Supply `backend`/`encryption` explicitly, use a read-capable ' +
          'capability, or pass `force: true` if you are creating a new ' +
          'collection.'
      )
    }
    // Merge every current field forward (mirror `Space.configure`): a
    // replace-semantics server drops anything omitted from the PUT body, so
    // `configure({ name })` on an EDV collection would otherwise wipe its
    // `backend` or trip `encryption-immutable` by clearing the marker.
    const name = desc.name ?? current?.name
    const backend = desc.backend ?? current?.backend
    const encryption = desc.encryption ?? current?.encryption
    const body: Record<string, unknown> = { id: this.id, name }
    if (backend) {
      body.backend = backend
    }
    if (encryption) {
      body.encryption = encryption
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
      this._codecHolder.reset()
    }
    return {
      id: this.id,
      type: current?.type ?? ['Collection'],
      ...(name !== undefined ? { name } : {}),
      ...(backend !== undefined ? { backend } : {}),
      ...(encryption !== undefined ? { encryption } : {})
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
   * @param [options.encryption] {EncryptionOverride}   per-resource encryption
   *   override; wins over the Collection's codec and resolves a fresh one for
   *   this resource (see {@link EncryptionOverride})
   * @returns {Resource}
   */
  resource(resourceId: string, options: HandleOptions = {}): Resource {
    return new Resource({
      context: this._context,
      spaceId: this.spaceId,
      collectionId: this.id,
      resourceId,
      capability: options.capability ?? this._capability,
      // A per-resource encryption override resolves its own codec (honoring the
      // override); without one, share this collection's resolved codec so the
      // resource handle does not repeat the marker-discovery round-trip. The two
      // are mutually exclusive: the Resource ignores `encryption` when `codec`
      // is supplied.
      ...(options.encryption !== undefined
        ? { encryption: options.encryption }
        : { codec: () => this._codec() })
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
    const precondition = {
      ifMatch: encoded.ifMatch,
      ifNoneMatch: encoded.ifNoneMatch
    }

    // A codec that mints its own id (e.g. the encrypting codec's EDV id) writes
    // by `PUT`; the identity codec returns no id and lets the server mint one
    // via `POST`.
    if (encoded.id !== undefined) {
      const path = resourcePath(this.spaceId, this.id, encoded.id)
      const response = await sendEncodedWrite(this._context, {
        path,
        method: 'PUT',
        capability: this._capability,
        encoded,
        precondition
      })
      return {
        id: encoded.id,
        url: toUrl({ serverUrl: this._context.serverUrl, path }),
        // Report the plaintext resource type when the codec resolved one (the
        // EDV codec's `resourceContentType`); otherwise the wire `contentType`,
        // which for the identity codec already is the resource type.
        contentType: encoded.resourceContentType ?? encoded.contentType,
        etag: readEtag(response)
      }
    }

    const response = await sendEncodedWrite(this._context, {
      path: this._itemsPath,
      method: 'POST',
      capability: this._capability,
      encoded,
      precondition
    })
    // POST always returns a response (404/errors throw via send()). The id is
    // the body's `id`, or -- for a body-less 2xx -- the `Location` header.
    const id = createdId(response)
    const responseBody = (
      response as { data?: { 'content-type'?: string } } | null
    )?.data
    const location =
      (response as { headers: Headers }).headers.get('location') ?? undefined
    return {
      id,
      // RFC 9110 permits a relative `Location`; resolve it against the request
      // URL so `AddResult.url` is always absolute (consumers like
      // `was.publicRead({ resourceUrl })` require an absolute URL).
      url: location
        ? new URL(
            location,
            toUrl({ serverUrl: this._context.serverUrl, path: this._itemsPath })
          ).toString()
        : toUrl({
            serverUrl: this._context.serverUrl,
            path: resourcePath(this.spaceId, this.id, id)
          }),
      contentType: responseBody?.['content-type'],
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
    // Delegate to the resource handle (the way `put()` does) so the reserved-id
    // guard in the `Resource` constructor applies to reads and writes alike.
    return this.resource(resourceId).get()
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
    return buildPageWalk({
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
        return dataOrNull<CollectionResourcesList>(pageResponse)
      }
    })
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
    return delegateGrantAt(this._context, {
      path: this._path,
      options,
      capability: this._capability
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
    return readPolicy(this._context, {
      policyPath: this._policyPath,
      capability: this._capability
    })
  }

  /**
   * Sets (creates or replaces) the collection's access-control policy.
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
    return deletePolicy(this._context, {
      policyPath: this._policyPath,
      capability: this._capability
    })
  }

  /**
   * Reads the collection's linkset (RFC9264 policy discovery). Returns `null`
   * if the collection is missing or not visible to you.
   *
   * @returns {Promise<LinkSet | null>}
   */
  async linkset(): Promise<LinkSet | null> {
    return readData<LinkSet>(this._context, {
      path: collectionLinkset(this.spaceId, this.id),
      capability: this._capability
    })
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
    return readData<BackendDescriptor>(this._context, {
      path: collectionBackend(this.spaceId, this.id),
      capability: this._capability
    })
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
    return readData<BackendUsage>(this._context, {
      path: collectionQuota(this.spaceId, this.id),
      capability: this._capability
    })
  }
}
