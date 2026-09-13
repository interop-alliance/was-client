/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A navigational handle to a Space. Exposes its own lifecycle
 * (`describe`/`configure`/`delete`/`deleteWithOutcome`), contained Collections
 * (`collection`/`createCollection`/`collections`), delegation (`grant`), and
 * whole-space `export`/`import`.
 *
 * The Space is an ordinary container: its canonical URL (`/space/{id}/`) lists
 * its Collections, creates one, and deletes the Space, while the Space's own
 * description -- the Space Metadata object -- is read and replaced at its
 * `meta` sub-resource.
 */
import type { HttpResponse } from '@interop/http-client'
import {
  spacePath,
  spaceMeta,
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
import {
  collectionWritableFields,
  unreadableDescriptionError
} from './internal/describe.js'
import { delegateGrantAt } from './internal/grant.js'
import { submitRevocation } from './internal/revoke.js'
import type { ClientContext } from './internal/request.js'
import { send, readData, readDataWithEtag } from './internal/request.js'
import { readEtag, writeHeaders } from './internal/conditional.js'
import {
  collectWalk,
  signedPageWalk,
  walkPagesOrEmpty
} from './internal/pagination.js'
import type { PageWalk } from './internal/pagination.js'
import { NotFoundError, WasServerError } from './errors.js'
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
  IDID,
  IDelegatedZcap,
  IZcap,
  ImportStats,
  LinkSet,
  PolicyDocument,
  SpaceMetadata,
  SpaceQuotaReport
} from './types.js'

/**
 * The Space Metadata PUT body: the one inclusion rule for its writable
 * members, shared by `configure` and `replaceDescription`. `name` and `type`
 * are sent only when set, since the server keeps the stored value for an
 * omitted member; `controller` is always sent.
 *
 * @param fields {object}
 * @param fields.id {string}
 * @param [fields.name] {string}
 * @param fields.controller {string}
 * @param [fields.type] {string[]}
 * @returns {{ id: string; name?: string; controller: string; type?: string[] }}
 */
function spaceMetadataBody({
  id,
  name,
  controller,
  type
}: {
  id: string
  name?: string
  controller: string
  type?: string[]
}) {
  return {
    id,
    ...(name !== undefined && { name }),
    controller,
    ...(type !== undefined && { type })
  }
}

export class Space {
  readonly id: string

  readonly #context: ClientContext
  readonly #capability?: IZcap

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
    this.#context = context
    this.id = spaceId
    this.#capability = capability
  }

  /**
   * The Space container in canonical (trailing-slash) form: the URL whose
   * `GET` lists the Space's Collections, whose `POST` creates one, and whose
   * `DELETE` removes the Space. It is also the target a Space root capability
   * names, so a grant prefilled from it covers the whole Space by prefix --
   * `meta` and every Collection included.
   */
  get #path(): string {
    return spacePath(this.id)
  }

  /**
   * The Space Metadata object: the Space's description, read and replaced at
   * the reserved `meta` segment rather than at the container URL.
   */
  get #metaPath(): string {
    return spaceMeta(this.id)
  }

  get #policyPath(): string {
    return spacePolicy(this.id)
  }

  /**
   * Reads the Space Metadata object -- the Space's description, at its `meta`
   * sub-resource. Returns `null` if the space is missing or not
   * visible to you (WAS returns 404 for both not-found and unauthorized).
   *
   * @returns {Promise<SpaceMetadata | null>}
   */
  async describe(): Promise<SpaceMetadata | null> {
    return readData<SpaceMetadata>(this.#context, {
      path: this.#metaPath,
      capability: this.#capability
    })
  }

  /**
   * Reads the Space Metadata object together with its `ETag` validator (the
   * server's `conditional-writes` support). The `ETag` is the opaque validator
   * to pass to {@link replaceDescription}'s `ifMatch` for a lost-update-safe
   * (compare-and-swap) description write. Returns `null` if the space is
   * missing or not visible to you (404 conflation caveat); `etag` is absent
   * against a server that does not version the Space Metadata object.
   *
   * @returns {Promise<{ description: SpaceMetadata; etag?: string } | null>}
   */
  async describeWithEtag(): Promise<{
    description: SpaceMetadata
    etag?: string
  } | null> {
    const read = await readDataWithEtag<SpaceMetadata>(this.#context, {
      path: this.#metaPath,
      capability: this.#capability
    })
    return read === null ? null : { description: read.data, etag: read.etag }
  }

  /**
   * Writes the Space Metadata object under an optional precondition: `ifMatch`
   * (the `ETag` from {@link describeWithEtag}) makes it a compare-and-swap so
   * a concurrent writer cannot be silently clobbered, and `ifNoneMatch: true`
   * makes it a guarded create that proceeds only while no Space exists under
   * this id. A failed precondition surfaces as `PreconditionFailedError`
   * (412). Unlike {@link configure}, nothing is read or merged on the client:
   * the body is sent as given, so `controller` is required (a default to the
   * signer's DID would let a delegated writer reassign ownership by omission).
   * The server applies the body over the stored description: an omitted
   * `name` keeps the stored name, and `type` is accepted at creation only and
   * immutable afterwards.
   *
   * Returns the new `ETag`, and on a create the description the server
   * answered with; an update answers with no body, so `description` is absent
   * there and the caller re-reads if it needs the merged result.
   *
   * @param description {object}
   * @param [description.name] {string}
   * @param description.controller {string}
   * @param [description.type] {string[]}   accepted by the server at creation
   *   only
   * @param options {object}
   * @param [options.ifMatch] {string}   the prior `ETag`; the write applies only
   *   if the description is unchanged
   * @param [options.ifNoneMatch] {boolean}   write only if the Space does not
   *   exist yet
   * @returns {Promise<{ description?: SpaceMetadata; etag?: string }>}
   */
  async replaceDescription(
    description: { name?: string; controller: string; type?: string[] },
    options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
  ): Promise<{ description?: SpaceMetadata; etag?: string }> {
    const response = await send(this.#context, {
      path: this.#metaPath,
      method: 'PUT',
      capability: this.#capability,
      json: spaceMetadataBody({ id: this.id, ...description }),
      headers: writeHeaders({
        precondition: {
          ifMatch: options.ifMatch,
          ifNoneMatch: options.ifNoneMatch
        }
      })
    })
    const created = dataOrNull<SpaceMetadata>(response)
    return {
      ...(created !== null && { description: created }),
      etag: readEtag(response)
    }
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
   * @param [desc.type] {string[]}   the Space Metadata object's `type` array (e.g.
   *   a typed auxiliary Space). The server accepts it at creation only and
   *   treats it as immutable afterwards, so pass it on the create; on an
   *   update the current description's `type` is re-sent unchanged
   * @param [desc.force] {boolean}   proceed even when the current description is
   *   unreadable and a full description is not supplied (see above)
   * @param [desc.current] {SpaceMetadata | null}   the current description,
   *   when the caller has already read it -- the merge and the fail-closed
   *   check then run against this instead of a second `describe()` round trip.
   *   `null` means the caller read it and found the Space absent or
   *   unreadable, which is a supplied answer; omitting the member entirely is
   *   what asks for the read. Supplying a description this handle's own writes
   *   have since superseded would merge stale fields forward, so pass only a
   *   read the caller itself made and has not written over
   * @returns {Promise<SpaceMetadata>}
   */
  async configure(desc: {
    name?: string
    controller?: string
    type?: string[]
    force?: boolean
    current?: SpaceMetadata | null
  }): Promise<SpaceMetadata> {
    const current =
      desc.current !== undefined ? desc.current : await this.describe()
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
      desc.controller ?? current?.controller ?? this.#context.controllerDid
    const type = desc.type ?? current?.type
    await send(this.#context, {
      path: this.#metaPath,
      method: 'PUT',
      capability: this.#capability,
      json: spaceMetadataBody({ id: this.id, name, controller, type })
    })
    return {
      id: this.id,
      type: type ?? ['Space'],
      ...(name !== undefined ? { name } : {}),
      // `controller` is a user-supplied DID string; assert it as the branded
      // `IDID` the wire type now uses (the server validates the DID form).
      controller: controller as SpaceMetadata['controller']
    }
  }

  /**
   * Deletes the space. Idempotent.
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

  /**
   * Deletes the space and reports the server's answer instead of treating a
   * 404 as success. `delete()` is the idempotent form; this one exists for a
   * caller that must know whether the DELETE actually removed anything. The
   * server answers 404 both for an absent Space and for an unauthorized
   * capability, so `'not-found'` means "absent or refused" and only a caller
   * with its own prior discovery may read it as absence.
   *
   * The capability is the one the handle was opened with
   * (`was.space(id, { capability })`), so a delegated DELETE-only capability
   * is supplied by opening the handle with it.
   *
   * @returns {Promise<{ outcome: 'deleted' | 'not-found' }>}
   */
  async deleteWithOutcome(): Promise<{ outcome: 'deleted' | 'not-found' }> {
    try {
      await send(this.#context, {
        path: this.#path,
        method: 'DELETE',
        capability: this.#capability
      })
    } catch (err) {
      if (err instanceof NotFoundError) {
        return { outcome: 'not-found' }
      }
      throw err
    }
    return { outcome: 'deleted' }
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
      context: this.#context,
      spaceId: this.id,
      collectionId,
      capability: options.capability ?? this.#capability,
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
   *   client-side encrypted. When the descriptor can route -- for the `'edv'`
   *   scheme that means it carries its epoch roster -- the returned handle is
   *   pre-seeded with it as an encryption override, so the immediate next
   *   write encrypts without a descriptor-discovery round-trip. A bare
   *   `{ scheme: 'edv' }` declares the collection encrypted but is not
   *   pre-seeded (the handle uses descriptor discovery instead); reads and
   *   writes are refused fail-closed until `ensureFirstEpoch` installs the
   *   epoch roster.
   * @param [desc.generator] {IDID}   DID of the application the collection is
   *   being provisioned for. Controller-asserted attribution: the server
   *   persists it without verifying it, and it stays writable afterwards
   *   (`configure`/`replaceDescription`), so an existing collection can be
   *   backfilled.
   * @param [desc.generatorOrigin] {string}   the Web origin the `generator`
   *   DID was bound to at provisioning time, on the same footing.
   * @returns {Promise<Collection>}
   */
  async createCollection(
    desc: {
      id?: string
      name?: string
      backend?: BackendReference
      encryption?: CollectionEncryption
      generator?: IDID
      generatorOrigin?: string
    } = {}
  ): Promise<Collection> {
    if (desc.id !== undefined) {
      assertNotReserved({ id: desc.id, kind: 'collection' })
    }
    // The writable fields follow the shared inclusion rule; only `id` (not part
    // of the writable description) is handled here.
    const body = {
      ...(desc.id !== undefined && { id: desc.id }),
      ...collectionWritableFields(desc)
    }
    const response = await send(this.#context, {
      path: this.#path,
      method: 'POST',
      capability: this.#capability,
      json: body
    })
    // Pre-seed the handle with the just-declared descriptor as its override so
    // the first write encrypts immediately (keys come from the keystore); no
    // describe() round-trip needed before the descriptor is locally known.
    // Only a descriptor the provider says it can route is pre-seeded: an
    // override is fixed at handle construction, so pinning one the provider
    // would refuse (an `edv` declaration whose epoch roster is not installed
    // yet) would leave the handle permanently fail-closed. Such a handle falls
    // back to descriptor discovery instead, which resolves the roster once
    // `ensureFirstEpoch` installs it. Whether a descriptor routes is the
    // provider's fact, not core's; a provider without `canRoute` routes all.
    const declared = desc.encryption
    const canRoute =
      declared !== undefined &&
      (this.#context.encryption?.canRoute?.({
        scheme: declared.scheme,
        encryption: declared
      }) ??
        true)
    return this.collection(createdId(response), {
      encryption: canRoute ? declared : undefined
    })
  }

  /**
   * Reads the first page of the collections listing -- the Space container
   * itself, the same URL {@link createCollection} posts to -- and packages the
   * means to follow its `next` links (each page fetched with the same
   * authorization).
   * Returns `null` if the space is missing or not visible to you (404 conflation
   * caveat).
   *
   * @returns {Promise<PageWalk<CollectionsList> | null>}
   */
  async #collectionsWalk(): Promise<PageWalk<CollectionsList> | null> {
    return signedPageWalk<CollectionsList>(this.#context, {
      firstUrl: toUrl({
        serverUrl: this.#context.serverUrl,
        path: this.#path
      }),
      capability: this.#capability
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
    return collectWalk(await this.#collectionsWalk())
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
    yield* walkPagesOrEmpty(await this.#collectionsWalk())
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
    return readData<BackendDescriptor[]>(this.#context, {
      path: spaceBackends(this.id),
      capability: this.#capability
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
   *   (`{ id, provider, connection: { kind, ... }, name?, storageMode?,
   *   features? }`)
   * @returns {Promise<BackendDescriptor>}   the sanitized descriptor of the
   *   newly registered backend
   */
  async registerBackend(
    registration: BackendRegistration
  ): Promise<BackendDescriptor> {
    const response = await send(this.#context, {
      path: spaceBackends(this.id),
      method: 'POST',
      capability: this.#capability,
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
    const response = await send(this.#context, {
      path: registeredBackend(this.id, registration.id),
      method: 'PUT',
      capability: this.#capability,
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
    await send(this.#context, {
      path: registeredBackend(this.id, backendId),
      method: 'DELETE',
      capability: this.#capability,
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
    return readData<SpaceQuotaReport>(this.#context, {
      path,
      capability: this.#capability
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
    return delegateGrantAt(this.#context, {
      path: this.#path,
      options,
      capability: this.#capability
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
   * `AlreadyRevokedError` (the server's 400, a `ValidationError` subclass
   * named for the `capability-already-revoked` problem type). A tampered,
   * expired, or foreign-rooted capability stays a plain `ValidationError`.
   * This method swallows none of them; catch `AlreadyRevokedError` if you want
   * revoking twice to be a no-op.
   *
   * @param zcap {IDelegatedZcap}   the delegated capability to revoke
   * @returns {Promise<void>}
   */
  async revoke(zcap: IDelegatedZcap): Promise<void> {
    return submitRevocation(this.#context, { spaceId: this.id, zcap })
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
  async #exportResponse(): Promise<HttpResponse> {
    const response = (await send(this.#context, {
      path: spaceExport(this.id),
      method: 'POST',
      capability: this.#capability
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
    const response = await this.#exportResponse()
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
    const blob = await (await this.#exportResponse()).blob()
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
    const response = await this.#exportResponse()
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
    const response = await send(this.#context, {
      path: spaceImport(this.id),
      method: 'POST',
      capability: this.#capability,
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
    return readPolicy(this.#context, {
      policyPath: this.#policyPath,
      capability: this.#capability
    })
  }

  /**
   * Sets (creates or replaces) the space's access-control policy.
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
   * Returns `true` when this space's policy is `PublicCanRead`.
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
   * Makes the whole space world-readable: every collection and resource under
   * it becomes readable without authorization (unless overridden by a more
   * specific policy). Sugar for `setPolicy({ type: 'PublicCanRead' })`.
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
   * Removes the space's access-control policy, reverting it to capability-only
   * access. Idempotent.
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
   * Reads the space's linkset (RFC9264 policy discovery). Returns `null` if the
   * space is missing or not visible to you.
   *
   * @returns {Promise<LinkSet | null>}
   */
  async linkset(): Promise<LinkSet | null> {
    return readData<LinkSet>(this.#context, {
      path: spaceLinkset(this.id),
      capability: this.#capability
    })
  }
}
