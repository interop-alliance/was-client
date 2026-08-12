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
  collectionQuery,
  collectionMeta,
  resourcePath,
  toUrl
} from './internal/paths.js'
import { assertNotReserved } from './internal/reserved.js'
import { WasServerError } from './errors.js'
import { delegateGrantAt } from './internal/grant.js'
import type { ClientContext } from './internal/request.js'
import { send, readData } from './internal/request.js'
import { collectionCodecHolder } from './internal/codec.js'
import type { CodecHolder } from './internal/codec.js'
import { collectionBackendFeatures } from './internal/features.js'
import type { BackendFeatures } from './internal/features.js'
import {
  collectWalk,
  signedPageWalk,
  walkItems,
  walkPagesOrEmpty
} from './internal/pagination.js'
import type { PageWalk } from './internal/pagination.js'
import {
  collectionWritableFields,
  describeCollection,
  describeCollectionResponse,
  unreadableDescriptionError
} from './internal/describe.js'
import { readEtag, writeHeaders } from './internal/conditional.js'
import { insertResource } from './internal/write.js'
import {
  readPolicy,
  writePolicy,
  deletePolicy,
  isPublicPolicy,
  setPublicPolicy
} from './internal/policy.js'
import { createdResource, dataOrNull } from './internal/content.js'
import type { ResourceCodec } from './codec.js'
import { Resource } from './Resource.js'
import type { ChangesCheckpoint, ChangesPage } from '@interop/storage-core'
import type {
  AddResult,
  BackendDescriptor,
  BackendUsage,
  CollectionDescription,
  CollectionMetadata,
  CollectionWritableFields,
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
  ResourceMetadataCustom,
  ResourceSummary
} from './types.js'

export class Collection {
  readonly spaceId: string
  readonly id: string

  readonly #context: ClientContext
  readonly #capability?: IZcap
  readonly #codecHolder: CodecHolder
  /**
   * The shared backend-feature probe for this collection (memoized on a
   * definitive answer), consulted by the conditional-codec write path and
   * shared with child resource handles the way the codec is.
   */
  readonly #features: BackendFeatures

  /**
   * @param options {object}
   * @param options.context {ClientContext} - Shared context (serverUrl, ezcap
   *   client, controllerDid)
   * @param options.spaceId {string}
   * @param options.collectionId {string}
   * @param [options.capability] {IZcap} - capability attached to every request
   * @param [options.encryption] {EncryptionOverride} - per-handle encryption
   *   override; wins over the Collection's declared descriptor and skips the
   *   descriptor-discovery round-trip
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
    this.#context = context
    this.spaceId = spaceId
    this.id = collectionId
    this.#capability = capability
    this.#codecHolder = collectionCodecHolder(context, {
      spaceId,
      collectionId,
      override: encryption,
      capability
    })
    this.#features = collectionBackendFeatures(context, {
      spaceId,
      collectionId,
      capability
    })
  }

  get #path(): string {
    return collectionPath(this.spaceId, this.id)
  }

  get #itemsPath(): string {
    return collectionItems(this.spaceId, this.id)
  }

  get #policyPath(): string {
    return collectionPolicy(this.spaceId, this.id)
  }

  /**
   * Resolves (once, then caches) the codec for this collection's reads and
   * writes: the identity codec for a plaintext collection, or the encrypting
   * codec when this collection is declared encrypted -- by a per-handle
   * override or its `encryption` descriptor -- and the client's keystore
   * supplies its keys. An encrypted collection the client cannot key for fails
   * closed (throws), and a successful descriptor read happens at most once per
   * handle (memoized here) -- a fresh handle to the same collection re-reads
   * it, so retain the handle to reuse it. A failed resolution (e.g. a transient
   * 500/network error during descriptor discovery) is not memoized: the cache
   * is cleared so the next call retries rather than re-throwing the stale error
   * forever.
   *
   * @returns {Promise<ResourceCodec>}
   */
  #codec(): Promise<ResourceCodec> {
    return this.#codecHolder.get()
  }

  /**
   * Reads the Collection Description. Returns `null` if the collection is
   * missing or not visible to you (WAS returns 404 for both not-found and
   * unauthorized).
   *
   * @returns {Promise<CollectionDescription | null>}
   */
  async describe(): Promise<CollectionDescription | null> {
    return describeCollection(this.#context, {
      spaceId: this.spaceId,
      collectionId: this.id,
      capability: this.#capability
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
   * descriptor on a replace-semantics server. Pass `force: true` to proceed
   * anyway
   * -- e.g. when creating a new collection through a handle (or use
   * `space.createCollection()`, which does not merge).
   *
   * @param desc {CollectionWritableFields}   the fields to merge; `encryption`
   *   declares the client-side encryption descriptor, which is set-once on the
   *   server (it may be added to a Collection that lacks one, but
   *   changing/clearing an existing descriptor is rejected -- `ConflictError`,
   *   `encryption-immutable`)
   * @param [desc.force] {boolean}   proceed even when the current description
   *   is unreadable and `backend`/`encryption` are omitted (see above)
   * @returns {Promise<CollectionDescription>}
   */
  async configure(
    desc: CollectionWritableFields & { force?: boolean }
  ): Promise<CollectionDescription> {
    const current = await this.describe()
    if (
      current === null &&
      desc.backend === undefined &&
      desc.encryption === undefined &&
      !desc.force
    ) {
      throw unreadableDescriptionError({
        operation: `configure collection "${this.id}"`,
        consequence:
          "merging forward could silently drop an existing collection's " +
          'backend or encryption descriptor',
        advice:
          'Supply `backend`/`encryption` explicitly, use a read-capable ' +
          'capability, or pass `force: true` if you are creating a new ' +
          'collection.'
      })
    }
    // Merge every current field forward (mirror `Space.configure`): a
    // replace-semantics server drops anything omitted from the PUT body, so
    // `configure({ name })` on an EDV collection would otherwise wipe its
    // `backend` or trip `encryption-immutable` by clearing the descriptor.
    const name = desc.name ?? current?.name
    const backend = desc.backend ?? current?.backend
    const encryption = desc.encryption ?? current?.encryption
    // The app-attribution fields merge forward on the same terms, so a
    // `configure({ name })` does not erase a stored `generator`. They are
    // deliberately NOT part of the unreadable-description guard above: unlike
    // `backend` and `encryption`, they are freely re-writable attribution
    // (dropping one is cosmetic, not a data-placement change or an
    // `encryption-immutable` trip), and admitting them there would let a
    // `configure({ generator })` sail past the guard and blindly drop the two
    // fields it exists to protect.
    const generator = desc.generator ?? current?.generator
    const generatorOrigin = desc.generatorOrigin ?? current?.generatorOrigin
    const fields = collectionWritableFields({
      name,
      backend,
      encryption,
      generator,
      generatorOrigin
    })
    await send(this.#context, {
      path: this.#path,
      method: 'PUT',
      capability: this.#capability,
      json: { id: this.id, ...fields }
    })
    // Adding the encryption descriptor flips this collection from plaintext to
    // encrypted server-side. Drop any codec memoized from the prior (plaintext)
    // descriptor so the next read/write re-resolves it -- otherwise a `put`
    // would reuse the cached identity codec and write server-visible plaintext
    // into the now-encrypted collection. Child resource handles share this
    // codec via their thunk, so resetting here propagates to them too.
    if (desc.encryption) {
      this.#codecHolder.reset()
    }
    return {
      id: this.id,
      type: current?.type ?? ['Collection'],
      ...fields
    }
  }

  /**
   * Reads the Collection Description together with its `ETag` validator (the
   * server's `conditional-writes` / description-version support). The `ETag` is
   * the opaque validator to pass to {@link replaceDescription}'s `ifMatch` for a
   * lost-update-safe (compare-and-swap) description write. Returns `null` if the
   * collection is missing or not visible to you (404 conflation caveat); `etag`
   * is absent against a server that does not version the description.
   *
   * @returns {Promise<{ description: CollectionDescription; etag?: string } | null>}
   */
  async describeWithEtag(): Promise<{
    description: CollectionDescription
    etag?: string
  } | null> {
    // The same GET as `describe()` (via the shared request shape), keeping the
    // raw response so the ETag header can be read alongside the body.
    const response = await describeCollectionResponse(this.#context, {
      spaceId: this.spaceId,
      collectionId: this.id,
      capability: this.#capability
    })
    const description = dataOrNull<CollectionDescription>(response)
    if (response === null || description === null) {
      return null
    }
    return {
      description,
      etag: readEtag(response)
    }
  }

  /**
   * Writes (replaces) the Collection Description, optionally as a
   * compare-and-swap against a prior `ETag` (`ifMatch`, from {@link
   * describeWithEtag}) so a concurrent writer cannot be silently clobbered -- a
   * stale validator surfaces as `PreconditionFailedError` (412). Sends the
   * writable fields as the full body; omit a field to drop it (replace
   * semantics), so callers doing CAS pass every field forward. Returns the new
   * `ETag` and the fields written.
   *
   * This is the generic description-CAS primitive the key-epoch recipient
   * operations build on (add/remove a reader is a CAS of the `encryption`
   * descriptor); it is not epoch-specific.
   *
   * @param description {CollectionWritableFields}
   * @param options {object}
   * @param [options.ifMatch] {string}   the prior `ETag`; the write applies only
   *   if the description is unchanged
   * @returns {Promise<{ description: CollectionDescription; etag?: string }>}
   */
  async replaceDescription(
    description: CollectionWritableFields,
    options: { ifMatch?: string } = {}
  ): Promise<{ description: CollectionDescription; etag?: string }> {
    const fields = collectionWritableFields(description)
    const response = await send(this.#context, {
      path: this.#path,
      method: 'PUT',
      capability: this.#capability,
      json: { id: this.id, ...fields },
      headers: writeHeaders({ precondition: { ifMatch: options.ifMatch } })
    })
    // Writing the `encryption` descriptor can rotate the key epoch (the
    // recipient operations CAS this field) or flip the collection from
    // plaintext to encrypted. Drop any memoized codec -- bound at construction
    // to the prior descriptor's write key/epoch -- so the next read/write
    // re-resolves it under the new descriptor; otherwise a `put` on the same
    // handle would keep encrypting under the stale epoch, whose key a
    // just-removed reader still holds. Child resource handles share this codec
    // via their thunk, so resetting here propagates to them too.
    if (description.encryption !== undefined) {
      this.#codecHolder.reset()
    }
    return {
      description: {
        id: this.id,
        type: ['Collection'],
        ...fields
      },
      etag: readEtag(response)
    }
  }

  /**
   * Deletes the whole collection. Idempotent. To delete a single resource, use
   * `collection.resource(id).delete()`.
   *
   * @returns {Promise<void>}
   */
  async delete(): Promise<void> {
    await send(this.#context, {
      path: this.#path,
      method: 'DELETE',
      capability: this.#capability,
      idempotent: true
    })
  }

  get #metaPath(): string {
    return collectionMeta(this.spaceId, this.id)
  }

  /**
   * Reads the Collection's metadata object (server-managed timestamps,
   * `createdBy` and the encrypted-`custom` key `epoch`, plus the user-writable
   * `custom` object). Returns `null` if the collection is missing or not
   * visible to you (404 conflation caveat). A server without Collection
   * metadata support surfaces its 501 as `NotImplementedError`.
   *
   * On an encrypted collection the stored `custom` is an opaque envelope; this
   * decodes it (decrypts, via the codec) so a caller always sees plaintext
   * `{ name, tags }`. A collection with no user metadata reports `custom` as
   * `{}`.
   *
   * Against a backend with the `conditional-writes` feature the result also
   * carries the metadata's current `etag` (the `/meta` `metaVersion`
   * validator) -- pass it as `setMeta(meta, { ifMatch })` for a
   * lost-update-safe metadata update. That validator is independent of the
   * Collection Description's ETag ({@link describeWithEtag}) and of every
   * Resource's versions: writing one never bumps the other.
   *
   * @returns {Promise<(CollectionMetadata & { etag?: string }) | null>}
   */
  async meta(): Promise<(CollectionMetadata & { etag?: string }) | null> {
    // Overlapped like `Resource.meta()`: the metadata GET does not depend on
    // the codec (only its `custom` decode below does), the codec is awaited
    // first for error precedence, and the no-op handler keeps an abandoned read
    // from becoming an unhandled rejection.
    const codecPromise = this.#codec()
    const responsePromise = send(this.#context, {
      path: this.#metaPath,
      method: 'GET',
      capability: this.#capability,
      read: true
    })
    responsePromise.catch(() => {})
    const codec = await codecPromise
    const response = await responsePromise
    if (response === null) {
      return null
    }
    if (response.data === undefined) {
      // A 200 whose body `@interop/http-client` did not pre-parse into `.data`
      // (a non-JSON content-type, or an empty/204 body): a metadata document
      // always carries its server-managed fields as JSON, so an absent `.data`
      // is a malformed response. Fail with a typed error rather than
      // dereferencing `metadata.custom` off `undefined` as a raw `TypeError`.
      // (Kept distinct from the `null` return, which means the collection is
      // missing or not visible -- not that the server answered malformed.)
      throw new WasServerError(
        `Metadata response for collection "${this.id}" carried no JSON body ` +
          `(content-type ` +
          `"${response.headers.get('content-type') ?? 'unknown'}").`
      )
    }
    const metadata = response.data as CollectionMetadata
    // Decode the user-writable `custom` (decrypting it on an encrypted
    // collection) so callers uniformly see plaintext `{ name, tags }`. No
    // resource id is passed: this slot belongs to the collection itself, and
    // the encrypting codec refuses a resource-bound envelope served here.
    const custom = await codec.decodeMeta({ custom: metadata.custom })
    const decoded = { ...metadata, custom }
    const etag = readEtag(response)
    return etag !== undefined ? { ...decoded, etag } : decoded
  }

  /**
   * Replaces the Collection's user-writable metadata (`custom`). This is a full
   * replacement: any property omitted from `custom` is cleared, and an omitted
   * `custom` clears them all. Does not create the collection -- a `PUT` to the
   * metadata of a nonexistent collection throws `NotFoundError`. Servers
   * without Collection metadata support surface their 501 as
   * `NotImplementedError`.
   *
   * On an encrypted collection `custom` is encrypted into an opaque envelope by
   * the codec before it is sent, so `name` / `tags` are never stored as
   * server-visible plaintext -- transparently, the same call works on plaintext
   * and encrypted collections alike.
   *
   * Conditional metadata writes (the backend's `conditional-writes` feature):
   * pass `ifMatch` (the `etag` from a prior `meta()`) for an
   * update-if-unchanged, or `ifNoneMatch: true` for a
   * write-only-if-no-metadata. A failed precondition throws
   * `PreconditionFailedError` (412). The `/meta` ETag (`metaVersion`) is
   * independent of the Collection Description's ETag. Returns the new `etag`.
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
    const codec = await this.#codec()
    const { custom, epoch } = await codec.encodeMeta({
      custom: meta.custom ?? {}
    })
    const response = await send(this.#context, {
      path: this.#metaPath,
      method: 'PUT',
      capability: this.#capability,
      // The key epoch travels in the body here, not in the `Key-Epoch` header:
      // the header channel stamps a Resource's *content* write, while the
      // Collection metadata stamp describes the `custom` envelope itself and is
      // a top-level member of this PUT body. The server clears the stored stamp
      // when the member is omitted -- which is exactly right on a plaintext
      // collection, whose codec surfaces no epoch.
      json: epoch !== undefined ? { custom, epoch } : { custom },
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
   * The shared read-then-CAS body of {@link setName} / {@link setTags}: reads
   * the current metadata, merges `patch` over its `custom`, and writes it back
   * pinned to the read's `etag` (when the backend supports
   * `conditional-writes`), so a concurrent metadata write surfaces as
   * `PreconditionFailedError` instead of being silently erased by the
   * full-replacement write.
   *
   * @param patch {ResourceMetadataCustom}   the properties to merge over the
   *   current `custom`
   * @returns {Promise<void>}
   */
  async #patchCustom(patch: ResourceMetadataCustom): Promise<void> {
    const current = await this.meta()
    await this.setMeta(
      { custom: { ...current?.custom, ...patch } },
      { ifMatch: current?.etag }
    )
  }

  /**
   * Sets the Collection's metadata-level human-readable `name`, preserving any
   * existing `tags`. Convenience over `setMeta()`. The write is pinned to the
   * `etag` the `meta()` read returned (when the backend supports
   * `conditional-writes`), so a concurrent metadata write surfaces as
   * `PreconditionFailedError` instead of being silently erased by this
   * full-replacement write.
   *
   * On an encrypted collection this is the collection's client-encrypted name
   * surface: the codec seals it into the `custom` envelope, and by convention
   * the plaintext Description `name` is left unpopulated. On a plaintext
   * collection the two are separate labels -- space-level listings surface the
   * Description's `name` (set via `configure({ name })`), while this one is
   * metadata-level.
   *
   * @param name {string}
   * @returns {Promise<void>}
   */
  async setName(name: string): Promise<void> {
    return this.#patchCustom({ name })
  }

  /**
   * Sets the Collection's `tags`, preserving any existing `name`. Convenience
   * over `setMeta()`. Pinned to the `meta()` read's `etag` like
   * {@link setName}.
   *
   * @param tags {Record<string, string>}
   * @returns {Promise<void>}
   */
  async setTags(tags: Record<string, string>): Promise<void> {
    return this.#patchCustom({ tags })
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
      context: this.#context,
      spaceId: this.spaceId,
      collectionId: this.id,
      resourceId,
      capability: options.capability ?? this.#capability,
      // Share this collection's memoized feature probe so per-resource handles
      // do not each repeat the backend-descriptor round-trip.
      features: () => this.#features.get(),
      // A per-resource encryption override resolves its own codec (honoring the
      // override); without one, share this collection's resolved codec so the
      // resource handle does not repeat the descriptor-discovery round-trip.
      // The two are mutually exclusive: the Resource ignores `encryption` when
      // `codec` is supplied.
      ...(options.encryption !== undefined
        ? { encryption: options.encryption }
        : { codec: () => this.#codec() })
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
    const codec = await this.#codec()
    const itemsPath = this.#itemsPath
    const { encoded, path, response } = await insertResource(this.#context, {
      itemsPath,
      pathForId: mintedId => resourcePath(this.spaceId, this.id, mintedId),
      codec,
      data,
      contentType: options.contentType,
      capability: this.#capability
    })
    const etag = readEtag(response)

    // A codec that mints its own id (e.g. the encrypting codec's EDV id) was
    // written by `PUT` to that id's path, so the created id and URL are known
    // without consulting the response.
    if (encoded.id !== undefined) {
      return {
        id: encoded.id,
        url: toUrl({ serverUrl: this.#context.serverUrl, path }),
        // Report the plaintext resource type when the codec resolved one (the
        // EDV codec's `resourceContentType`); otherwise the wire `contentType`,
        // which for the identity codec already is the resource type.
        contentType: encoded.resourceContentType ?? encoded.contentType,
        etag
      }
    }

    // POST always returns a response (404/errors throw via send()). The id is
    // the body's `id`, or -- for a body-less 2xx -- the `Location` header, read
    // once here and reused for the URL below.
    const { id, location } = createdResource(response)
    const responseBody = response.data as
      { 'content-type'?: string } | undefined
    return {
      id,
      // RFC 9110 permits a relative `Location`; resolve it against the request
      // URL so `AddResult.url` is always absolute (consumers like
      // `was.publicRead({ resourceUrl })` require an absolute URL).
      url: location
        ? new URL(
            location,
            toUrl({ serverUrl: this.#context.serverUrl, path: itemsPath })
          ).toString()
        : toUrl({
            serverUrl: this.#context.serverUrl,
            path: resourcePath(this.spaceId, this.id, id)
          }),
      contentType:
        responseBody?.['content-type'] ??
        encoded.resourceContentType ??
        encoded.contentType,
      etag
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
   * Creates or replaces a resource by id (upsert). Forwards the
   * conditional-write options (`ifMatch` / `ifNoneMatch`) to `Resource.put`;
   * see it for the `conditional-writes` semantics. Returns the stored
   * resource's new `etag`.
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
  async #listWalk(): Promise<PageWalk | null> {
    return signedPageWalk(this.#context, {
      firstUrl: toUrl({
        serverUrl: this.#context.serverUrl,
        path: this.#itemsPath
      }),
      capability: this.#capability
    })
  }

  /**
   * Lists the items in the collection. Transparently follows the server's `next`
   * pagination links, buffering every page into a single list (the returned
   * envelope omits `next`). Convenient, but holds the whole collection in memory
   * -- for a large collection prefer `listPages()` or `listItems()`, which stream
   * one page at a time and allow stopping early. Returns `null` if the
   * collection is missing or not visible to you (404 conflation caveat).
   *
   * @returns {Promise<CollectionResourcesList | null>}
   */
  async list(): Promise<CollectionResourcesList | null> {
    return collectWalk(await this.#listWalk())
  }

  /**
   * Lazily yields the listing one page at a time, following the server's `next`
   * links on demand (each page fetched with the same authorization). Use this
   * to stream a large collection in constant memory or to stop early. Yields
   * nothing if the collection is missing or not visible to you (404 conflation
   * caveat) -- unlike `list()`, the iterator does not distinguish that from an
   * empty collection.
   *
   * @returns {AsyncGenerator<CollectionResourcesList>}
   */
  async *listPages(): AsyncGenerator<CollectionResourcesList> {
    yield* walkPagesOrEmpty(await this.#listWalk())
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
    yield* walkItems(this.listPages())
  }

  /**
   * Reads one page of the collection's replication change feed (the `changes`
   * query profile): the JSON-document resources and tombstones changed strictly
   * after `checkpoint`, in change order, at most `limit` of them. With no
   * `checkpoint` the feed starts from the beginning.
   *
   * This is deliberately a single page, not an iterator: it is shaped for an
   * RxDB `pull.handler(checkpoint, batchSize)`, which owns the iteration and
   * persists the checkpoint between batches. Resume by passing the returned
   * `checkpoint` back; a page shorter than `limit` means you have caught up.
   *
   * Requires the collection's backend to advertise the `changes-query` feature
   * (see `backend()`); a backend without it answers `501`. On an encrypted
   * collection the documents' `data` / `custom` are the scheme's opaque
   * envelopes (an EDV encrypted document under the v1 `edv` scheme) -- this
   * method does not decrypt them, unlike `get()`.
   *
   * @param [options] {object}
   * @param [options.checkpoint] {ChangesCheckpoint}   resume strictly after this
   * @param [options.limit] {number}   max documents; the server clamps its own maximum
   * @returns {Promise<ChangesPage>}
   */
  async changes(
    options: { checkpoint?: ChangesCheckpoint; limit?: number } = {}
  ): Promise<ChangesPage> {
    const { checkpoint, limit } = options
    const response = await send(this.#context, {
      path: collectionQuery(this.spaceId, this.id),
      method: 'POST',
      capability: this.#capability,
      json: {
        profile: 'changes',
        ...(checkpoint !== undefined && { checkpoint }),
        ...(limit !== undefined && { limit })
      }
    })
    // A `changes` query is a POST, so it never carries the null-on-404 `read`
    // flag: a missing or unauthorized collection throws, as every other write
    // -shaped call on this handle does.
    const page = dataOrNull<ChangesPage>(response)
    return page ?? { documents: [], checkpoint: null }
  }

  /**
   * Delegates access to this collection. Prefills the grant `target` with this
   * collection's URL (and the bound `capability`, if any, for re-delegation).
   *
   * @param options {GrantOptions}
   * @returns {Promise<IDelegatedZcap>}
   */
  async grant(options: GrantOptions): Promise<IDelegatedZcap> {
    return delegateGrantAt(this.#context, {
      path: this.#path,
      options,
      capability: this.#capability
    })
  }

  /**
   * Reads the collection's access-control policy. Returns `null` when no policy
   * is set (or it is not visible to you). Managing a policy is a
   * controller-level operation; a capability scoped to the collection does not
   * cover its policy sub-resource.
   *
   * @returns {Promise<PolicyDocument | null>}
   */
  async getPolicy(): Promise<PolicyDocument | null> {
    return readPolicy(this.#context, {
      policyPath: this.#policyPath,
      capability: this.#capability
    })
  }

  /**
   * Sets (creates or replaces) the collection's access-control policy.
   *
   * @param policy {PolicyDocument}
   * @returns {Promise<void>}
   */
  async setPolicy(policy: PolicyDocument): Promise<void> {
    return writePolicy(this.#context, {
      policyPath: this.#policyPath,
      policy,
      capability: this.#capability
    })
  }

  /**
   * Returns `true` when this collection's policy is `PublicCanRead`.
   *
   * @returns {Promise<boolean>}
   */
  async isPublic(): Promise<boolean> {
    return isPublicPolicy(this.#context, {
      policyPath: this.#policyPath,
      capability: this.#capability
    })
  }

  /**
   * Makes the collection world-readable: every resource in it becomes readable
   * without authorization (unless overridden by a more specific policy). Sugar
   * for `setPolicy({ type: 'PublicCanRead' })`.
   *
   * @returns {Promise<void>}
   */
  async setPublic(): Promise<void> {
    return setPublicPolicy(this.#context, {
      policyPath: this.#policyPath,
      capability: this.#capability
    })
  }

  /**
   * Removes the collection's access-control policy, reverting it to
   * capability-only access. Idempotent.
   *
   * @returns {Promise<void>}
   */
  async clearPolicy(): Promise<void> {
    return deletePolicy(this.#context, {
      policyPath: this.#policyPath,
      capability: this.#capability
    })
  }

  /**
   * Reads the collection's linkset (RFC9264 policy discovery). Returns `null`
   * if the collection is missing or not visible to you.
   *
   * @returns {Promise<LinkSet | null>}
   */
  async linkset(): Promise<LinkSet | null> {
    return readData<LinkSet>(this.#context, {
      path: collectionLinkset(this.spaceId, this.id),
      capability: this.#capability
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
    return readData<BackendDescriptor>(this.#context, {
      path: collectionBackend(this.spaceId, this.id),
      capability: this.#capability
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
    return readData<BackendUsage>(this.#context, {
      path: collectionQuota(this.spaceId, this.id),
      capability: this.#capability
    })
  }
}
