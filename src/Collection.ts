/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A navigational handle to a Collection within a Space. Exposes its own
 * lifecycle (`describe`/`configure`/`delete`) and contained-resource operations
 * (`add`/`get`/`put`/`list`, plus `resource(id)` for delete-by-id).
 *
 * The Collection's own "about it" document is the Collection Metadata object at
 * its `meta` sub-resource: one object under one validator, carrying the
 * configuration members beside the user-writable `custom`. `describe` and
 * `meta` are its two read projections (the second decodes `custom` through the
 * codec), and `configure` / `replaceDescription` / `setMeta` / `setName` are
 * full-replacement writes of it composed against a fresh read. The bare
 * Collection URL is the container: it lists and adds Resources, and `delete()`
 * removes the Collection.
 */
import {
  collectionPath,
  collectionPolicy,
  collectionLinkset,
  collectionBackend,
  collectionQuota,
  collectionQuery,
  collectionMeta,
  collectionLog,
  resourcePath,
  toUrl
} from './internal/paths.js'
import { assertNotReserved } from './internal/reserved.js'
import {
  NotFoundError,
  ValidationError,
  WasServerError,
  httpStatus
} from './errors.js'
import { delegateGrantAt } from './internal/grant.js'
import type { ClientContext } from './internal/request.js'
import { send, readData } from './internal/request.js'
import {
  codecForDescriptor,
  collectionCodecHolder,
  identityCodec
} from './internal/codec.js'
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
  ANNOTATION_MEMBERS,
  CONFIGURATION_MEMBERS,
  asCollectionMetadata,
  carriedForward,
  collectionWritableFields,
  isGovernedDescriptor,
  readCollectionMetadata,
  storedEncryption,
  unreadableDescriptionError
} from './internal/describe.js'
import type { StoredCollectionMetadata } from './internal/describe.js'
import { readEtag, writeHeaders } from './internal/conditional.js'
import { compareAndSwap } from './internal/cas.js'
import { readMeta, patchCustom } from './internal/meta.js'
import { codecRequestContext, insertResource } from './internal/write.js'
import {
  readPolicy,
  writePolicy,
  deletePolicy,
  isPublicPolicy,
  setPublicPolicy
} from './internal/policy.js'
import {
  ENCODER,
  LOG_CONTENT_TYPE,
  createdResource,
  dataOrNull,
  storedResponse
} from './internal/content.js'
import {
  INDEX_SCHEMA_PROPERTY,
  attributeKey,
  normalizeAttribute,
  readIndexSchema
} from './internal/indexSchema.js'
import type { CustomWithIndexSchema } from './internal/indexSchema.js'
import type {
  CodecIndexing,
  CodecRequestContext,
  IndexDeclaration,
  IndexSchema,
  ResourceCodec
} from './codec.js'
import { Resource } from './Resource.js'
import type {
  ChangeDocument,
  ChangesCheckpoint,
  ChangesPage
} from '@interop/storage-core'
import type {
  AddResult,
  BackendDescriptor,
  BackendUsage,
  CollectionEncryption,
  CollectionMetadata,
  CollectionWritableFields,
  EncryptionOverride,
  FindPage,
  GrantOptions,
  HandleOptions,
  IDelegatedZcap,
  IZcap,
  Json,
  ResourceData,
  LinkSet,
  PolicyDocument,
  CollectionResourcesList,
  ResourceMetadataCustomInput,
  ResourceSummary
} from './types.js'

/**
 * Merges a caller's configuration members over the Collection's current ones,
 * the mirror of the full-replacement `PUT`: a member the caller leaves out
 * keeps its stored value instead of being cleared. `configure({ name })` on an
 * EDV collection would otherwise wipe its `backend` or trip
 * `encryption-immutable` by clearing the descriptor, and erase a stored
 * `generator`.
 *
 * A log-governed `encryption` descriptor is the exception: it is the server's
 * projection of the history log's head, and a write carrying it is refused
 * (`encryption-history-log-governed`), so it is never merged forward. Omitting
 * the member leaves the derived descriptor in place.
 *
 * @param desc {CollectionWritableFields}   what the caller stated
 * @param current {CollectionMetadata | null}   the object this write is pinned
 *   to, or `null` when there is none
 * @returns {CollectionWritableFields}
 */
function mergedConfiguration(
  desc: CollectionWritableFields,
  current: CollectionMetadata | null
): CollectionWritableFields {
  const declared = desc.encryption ?? current?.encryption
  return collectionWritableFields({
    name: desc.name ?? current?.name,
    backend: desc.backend ?? current?.backend,
    ...(declared !== undefined &&
      !isGovernedDescriptor(declared) && { encryption: declared }),
    // The app-attribution members merge forward on the same terms, so a
    // `configure({ name })` does not erase a stored `generator`. They are
    // deliberately NOT part of `configure`'s unreadable-object guard: unlike
    // `backend` and `encryption`, they are freely re-writable attribution
    // (dropping one is cosmetic, not a data-placement change or an
    // `encryption-immutable` trip), and admitting them there would let a
    // `configure({ generator })` sail past the guard and blindly drop the two
    // members it exists to protect.
    generator: desc.generator ?? current?.generator,
    generatorOrigin: desc.generatorOrigin ?? current?.generatorOrigin
  })
}

export class Collection {
  readonly spaceId: string
  readonly id: string

  readonly #context: ClientContext
  readonly #capability?: IZcap
  readonly #codecHolder: CodecHolder
  /**
   * The per-handle encryption override, kept so a write that states its own
   * encryption state -- the guarded create in {@link setMeta} -- can honor it
   * without discovering a descriptor from stored state.
   */
  readonly #encryptionOverride?: EncryptionOverride
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
    this.#encryptionOverride = encryption
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

  /**
   * The Collection container in canonical (trailing-slash) form: the URL whose
   * `GET` lists the Collection's Resources, whose `POST` adds one, and whose
   * `DELETE` removes the Collection. A Collection's own description is not
   * here -- it is the Metadata object at the reserved `meta` segment.
   */
  get #path(): string {
    return collectionPath(this.spaceId, this.id)
  }

  get #policyPath(): string {
    return collectionPolicy(this.spaceId, this.id)
  }

  /**
   * The signed-request context handed to a codec that drives its own I/O (the
   * EDV codec reading a chunked blob back), bound to this handle's capability
   * and sharing its memoized feature probe.
   *
   * @returns {CodecRequestContext}
   */
  #codecContext(): CodecRequestContext {
    return codecRequestContext(this.#context, {
      features: this.#features,
      capability: this.#capability
    })
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
   * Reads the Collection Metadata object -- the Collection's configuration
   * (`name`, `backend`, `encryption`, `generator`) beside the server-managed
   * timestamps and the user-writable `custom`, as one object under one
   * validator. Returns `null` if the collection is missing or not visible to
   * you (WAS returns 404 for both not-found and unauthorized).
   *
   * This read never resolves the codec, so it is the configuration read: on an
   * encrypted Collection the served `custom` is the opaque envelope, exactly as
   * stored. {@link meta} is the same object with `custom` decoded.
   *
   * @returns {Promise<(CollectionMetadata & { etag?: string }) | null>}
   */
  async describe(): Promise<(CollectionMetadata & { etag?: string }) | null> {
    const read = await this.describeWithEtag()
    if (read === null) {
      return null
    }
    return {
      ...read.description,
      ...(read.etag !== undefined && { etag: read.etag })
    }
  }

  /**
   * {@link describe}, with the object and its `ETag` in separate members. The
   * `ETag` is the `metaVersion` validator to pass to
   * {@link replaceDescription}'s `ifMatch` for a lost-update-safe
   * (compare-and-swap) write. One validator covers the whole object, so it is
   * also what {@link setMeta} pins against. Returns `null` if the collection is
   * missing or not visible to you (404 conflation caveat); `etag` is absent
   * against a backend that does not version the object.
   *
   * @returns {Promise<{ description: CollectionMetadata; etag?: string } | null>}
   */
  async describeWithEtag(): Promise<{
    description: CollectionMetadata
    etag?: string
  } | null> {
    const read = await this.#readStored()
    if (read === null) {
      return null
    }
    return {
      description: asCollectionMetadata(read.metadata),
      ...(read.etag !== undefined && { etag: read.etag })
    }
  }

  /**
   * Reads the stored Collection Metadata object with its validator, in the wire
   * form the server served it -- `custom` undecoded. The one read behind
   * {@link describe} and behind every write's compose step.
   *
   * @returns {Promise<{ metadata: StoredCollectionMetadata; etag?: string } | null>}
   */
  async #readStored(): Promise<{
    metadata: StoredCollectionMetadata
    etag?: string
  } | null> {
    const read = await readCollectionMetadata(this.#context, {
      spaceId: this.spaceId,
      collectionId: this.id,
      capability: this.#capability
    })
    this.#remember(read)
    return read
  }

  /**
   * The object this handle read most recently, kept as the first baseline a
   * following write composes against so a read-then-write is one `GET` plus
   * one `PUT` rather than two `GET`s. Only a read carrying the backend's
   * validator is kept: the write is pinned to that validator, so a baseline
   * another client has since overwritten loses the compare-and-swap and is
   * re-read, while a backend serving no validator has nothing to lose the race
   * on and always reads fresh.
   */
  #recentRead?: { metadata: StoredCollectionMetadata; etag: string }

  /**
   * Records a read as the next write's baseline (see {@link #recentRead}).
   *
   * @param read {object | null}   the stored object and its validator
   * @returns {void}
   */
  #remember(
    read: { metadata: StoredCollectionMetadata; etag?: string } | null
  ): void {
    this.#recentRead =
      read !== null && read.etag !== undefined
        ? { metadata: read.metadata, etag: read.etag }
        : undefined
  }

  /**
   * Takes the remembered read, if it is usable as this write's baseline, and
   * drops it either way: it describes one point in time, so it is never handed
   * to a second write. A write pinned to the caller's own `ifMatch` reuses it
   * only when the two name the same version, which makes the reuse exact
   * rather than merely rebasable.
   *
   * @param [ifMatch] {string}   the caller's precondition, when it named one
   * @returns {{ metadata: StoredCollectionMetadata; etag: string } | undefined}
   */
  #takeRecentRead(
    ifMatch?: string
  ): { metadata: StoredCollectionMetadata; etag: string } | undefined {
    const recent = this.#recentRead
    this.#recentRead = undefined
    if (recent === undefined) {
      return undefined
    }
    return ifMatch === undefined || ifMatch === recent.etag ? recent : undefined
  }

  /**
   * Writes the Collection Metadata object: one `PUT` at `meta`, a full
   * replacement under the one `metaVersion` validator. Because it replaces the
   * whole object, `compose` is handed the stored object and returns the write
   * body, carrying forward every member this write is not about -- the
   * configuration members on an annotation write, the `custom` envelope and its
   * `epoch` stamp on a configuration write. `compose` runs against whichever
   * read the write is actually pinned to, so a merge it performs is never
   * applied over a version this write did not observe.
   *
   * The precondition decides how the read-modify-write is guarded:
   *
   * - `ifNoneMatch` is the guarded create ("only if the Collection does not
   *   exist"), and reads nothing: `compose` is handed `null`, since there is no
   *   stored object to carry forward.
   * - `ifMatch` pins the caller's own validator, so a lost race is the caller's
   *   to see as `PreconditionFailedError`.
   * - Neither: the write is pinned to the validator of the read it composed
   *   against, and a lost race re-reads and recomposes up to the shared
   *   compare-and-swap attempt limit. One validator covers configuration and
   *   annotations alike, so a configuration change now legitimately invalidates
   *   an in-flight annotation write; rebasing is the normal outcome, not an
   *   error. A backend without `conditional-writes` serves no validator, and
   *   the write stays the unconditional upsert it has always been.
   *
   * Limitation, on a backend without `conditional-writes` only: the body
   * re-sends the stored `encryption` descriptor, and with no validator to pin
   * the `PUT` to, a descriptor rotation landing between the compose read and
   * the write is re-sent as the older roster -- refused as a spurious
   * `invalid-request-body` ("epochs is append-only") by a server enforcing the
   * descriptor invariants, and rolled back by one that does not. There is no
   * client-side remedy without a validator or a partial-update form, neither of
   * which WAS v0.5 offers (WCL-99).
   *
   * The absent-object rule is the masked-404 fail-closed policy at write level:
   * a `null` read means "missing OR not visible to you", and composing against
   * an empty object would upsert a brand-new configuration-less Collection over
   * a Collection this capability simply cannot read. Only a write that states
   * its own absence -- the `ifNoneMatch` create, or a caller passing
   * `allowAbsent` because creating is what it is for -- may proceed from
   * nothing.
   *
   * @param options {object}
   * @param options.compose {function}   the stored object (`null` when there is
   *   none) to the write body, minus `id`
   * @param options.operation {string}   what the caller is doing, for the
   *   compare-and-swap exhaustion error
   * @param [options.current] {object}   an object the caller has already read,
   *   used as the first attempt's baseline instead of re-reading it: the write
   *   composes against it and pins to its validator, and a rebase re-reads. A
   *   baseline carrying no validator makes the first attempt unconditional,
   *   which is what a backend without `conditional-writes` offers anyway
   * @param [options.allowAbsent] {boolean}   compose against nothing (an
   *   upsert) instead of throwing `NotFoundError` when the object cannot be
   *   read
   * @param [options.ifMatch] {string}
   * @param [options.ifNoneMatch] {boolean}
   * @returns {Promise<{ metadata?: CollectionMetadata; etag?: string }>}   the
   *   new validator, and the object the server answered a create with
   */
  async #writeStored({
    compose,
    operation,
    current,
    allowAbsent,
    ifMatch,
    ifNoneMatch
  }: {
    compose: (
      stored: StoredCollectionMetadata | null
    ) => StoredCollectionMetadata | Promise<StoredCollectionMetadata>
    operation: string
    current?: { metadata: StoredCollectionMetadata; etag?: string } | null
    allowAbsent?: boolean
    ifMatch?: string
    ifNoneMatch?: boolean
  }): Promise<{ metadata?: CollectionMetadata; etag?: string }> {
    const put = async (
      body: StoredCollectionMetadata,
      precondition: { ifMatch?: string; ifNoneMatch?: boolean }
    ): Promise<{ metadata?: CollectionMetadata; etag?: string }> => {
      const response = await send(this.#context, {
        path: this.#metaPath,
        method: 'PUT',
        capability: this.#capability,
        json: { id: this.id, ...body },
        headers: writeHeaders({ precondition })
      })
      const created = dataOrNull<CollectionMetadata>(response)
      // The write superseded whatever this handle last read.
      this.#recentRead = undefined
      return {
        ...(created !== null && { metadata: created }),
        etag: readEtag(response)
      }
    }
    if (ifNoneMatch === true) {
      return put(await compose(null), { ifNoneMatch: true })
    }
    // The baseline for one attempt: the caller's own read, then this handle's
    // most recent read, then a fresh `GET`. Each is consumed once, so a rebase
    // always re-reads.
    let seed = current ?? undefined
    const baseline = async (): Promise<{
      metadata: StoredCollectionMetadata | null
      etag?: string
    }> => {
      const reused = seed ?? this.#takeRecentRead(ifMatch)
      seed = undefined
      if (reused !== undefined) {
        return reused
      }
      const read = await this.#readStored()
      this.#recentRead = undefined
      if (read !== null) {
        return read
      }
      if (allowAbsent !== true) {
        throw new NotFoundError(
          `Cannot ${operation.toLowerCase()} on collection "${this.id}": it ` +
            'does not exist, or is not visible with this capability (WAS ' +
            'returns 404 for both). Writing anyway would replace it with a ' +
            'configuration-less Collection. Create it with ' +
            '`space.createCollection()`, or pass `ifNoneMatch: true` to ' +
            'create it only if it is absent.'
        )
      }
      return { metadata: null }
    }
    if (ifMatch !== undefined) {
      const attempt = await baseline()
      return put(await compose(attempt.metadata), { ifMatch })
    }
    let written: { metadata?: CollectionMetadata; etag?: string } = {}
    await compareAndSwap<StoredCollectionMetadata | null>({
      store: {
        read: async () => {
          const attempt = await baseline()
          return {
            value: attempt.metadata,
            ...(attempt.etag !== undefined && { etag: attempt.etag })
          }
        },
        replace: async (body, { ifMatch: pinned }) => {
          written = await put(body ?? {}, { ifMatch: pinned })
        }
      },
      operation,
      mutate: compose
    })
    return written
  }

  /**
   * Creates or updates the collection by id (upsert). Merges the given
   * configuration members over the current ones; the annotations (`custom` and
   * its `epoch` stamp) are carried forward untouched, unless this write
   * changes the encryption scheme, in which case `custom` is re-sealed under
   * the incoming descriptor (see {@link replaceDescription}).
   *
   * The merge runs against the same read the write is pinned to, and rebases
   * with it: a rival configuration change landing in between is re-read and
   * merged over rather than re-applied stale.
   *
   * The merge needs a readable current object to be lost-update-safe, and the
   * read cannot distinguish "absent" from "unreadable" (WAS masks unauthorized
   * reads as 404). When it finds nothing and either `backend` or `encryption`
   * is left out, this fails closed rather than sending a PUT body that would
   * silently drop an existing collection's `backend` (a data-placement change)
   * or trip `encryption-immutable` by clearing its descriptor. Supplying only
   * one of the two does not cover the other: with nothing readable to merge
   * from, the omitted field is dropped either way. Pass `force: true` to
   * proceed anyway -- e.g. when creating a new collection through a handle (or
   * use `space.createCollection()`, which does not merge).
   *
   * @param desc {CollectionWritableFields}   the fields to merge; `encryption`
   *   declares the client-side encryption descriptor, which is set-once on the
   *   server (it may be added to a Collection that lacks one, but
   *   changing/clearing an existing descriptor is rejected -- `ConflictError`,
   *   `encryption-immutable`)
   * @param [desc.force] {boolean}   proceed even when the current object
   *   is unreadable and `backend`/`encryption` are omitted (see above)
   * @param [desc.current] {CollectionMetadata | null}   the current Collection
   *   Metadata object, when the caller has already read it -- the merge's first
   *   attempt then runs against this instead of a second read. It is used only
   *   while it carries the `etag` the write pins against, so a copy another
   *   client has since overwritten loses the compare-and-swap and is re-read
   *   rather than merged forward. `null` means the caller read it and found
   *   the collection absent or unreadable; omitting the member entirely is
   *   what asks for the read
   * @returns {Promise<CollectionMetadata>}
   */
  async configure(
    desc: CollectionWritableFields & {
      force?: boolean
      current?: (CollectionMetadata & { etag?: string }) | null
    }
  ): Promise<CollectionMetadata> {
    // What the last compose attempt merged, for the echoed return below (the
    // server answers an update with no body).
    let echoed: { type?: string[]; fields: CollectionWritableFields } = {
      fields: {}
    }
    if (desc.current === null) {
      // `current: null` is an answer the caller already read, not a request to
      // read: the guard fires on it without a round trip of this handle's own.
      this.#refuseBlindMerge(desc)
    }
    const { metadata } = await this.#writeStored({
      current:
        desc.current != null
          ? {
              metadata: desc.current as unknown as StoredCollectionMetadata,
              ...(desc.current.etag !== undefined && {
                etag: desc.current.etag
              })
            }
          : undefined,
      // The merge is the upsert: with nothing stored there is nothing to merge
      // forward, and the guard below decides whether that is safe.
      allowAbsent: true,
      compose: stored => {
        const current = stored === null ? null : asCollectionMetadata(stored)
        // Each protected field is checked on its own terms. Supplying one does
        // not make the other safe to omit: with no readable current object
        // there is nothing to merge the omitted one forward from, so
        // `configure({ backend })` on an EDV collection would send a body with
        // no `encryption` -- clearing the descriptor, or tripping
        // `encryption-immutable` -- which is the harm this guard exists to
        // prevent.
        if (current === null) {
          this.#refuseBlindMerge(desc)
        }
        const fields = mergedConfiguration(desc, current)
        echoed = {
          ...(current?.type !== undefined && { type: current.type }),
          fields
        }
        return this.#configurationBody(stored, fields)
      },
      operation: 'Collection configuration'
    })
    this.#resetCodecIfDeclared(desc.encryption)
    return (
      metadata ?? {
        id: this.id,
        type: echoed.type ?? ['Collection'],
        ...echoed.fields
      }
    )
  }

  /**
   * The fail-closed guard of {@link configure}: refuses a merge whose current
   * object could not be read, unless the caller stated both protected members
   * itself or passed `force`. Each is checked on its own terms. Supplying one
   * does not make the other safe to omit: with no readable current object
   * there is nothing to merge the omitted one forward from, so
   * `configure({ backend })` on an EDV collection would send a body with no
   * `encryption` -- clearing the descriptor, or tripping
   * `encryption-immutable` -- which is the harm this guard exists to prevent.
   *
   * @param desc {CollectionWritableFields}   what the caller stated
   * @param [desc.force] {boolean}
   * @returns {void}
   */
  #refuseBlindMerge(
    desc: CollectionWritableFields & { force?: boolean }
  ): void {
    if (
      (desc.backend === undefined || desc.encryption === undefined) &&
      !desc.force
    ) {
      throw unreadableDescriptionError({
        operation: `configure collection "${this.id}"`,
        consequence:
          "merging forward could silently drop an existing collection's " +
          'backend or encryption descriptor',
        advice:
          'Supply BOTH `backend` and `encryption` explicitly, use a ' +
          'read-capable capability, or pass `force: true` if you are ' +
          'creating a new collection.'
      })
    }
  }

  /**
   * Writes (replaces) the Collection's configuration members, optionally under
   * a precondition: `ifMatch` (the `ETag` from {@link describeWithEtag}) makes
   * it a compare-and-swap so a concurrent writer cannot be silently clobbered,
   * and `ifNoneMatch: true` makes it a guarded create that proceeds only while
   * no Collection exists under this id. A failed precondition surfaces as
   * `PreconditionFailedError` (412). Sends the writable configuration as the
   * full body; omit a member to drop it (replace semantics), so callers doing
   * CAS pass every member forward. Members this client does not model are
   * carried forward from the stored object rather than cleared.
   *
   * The annotations (`custom` and its `epoch` stamp) are carried forward
   * verbatim -- `custom` exactly as served, so an encrypted Collection's
   * envelope is never re-sealed by an ordinary configuration write. The one
   * exception is a write that changes the encryption scheme: the server
   * validates `custom` against the INCOMING descriptor, so a stored plaintext
   * `custom` cannot travel beside a newly declared `encryption` descriptor.
   * Such a write re-seals `custom` under the incoming descriptor's codec, and
   * drops `custom` (and its stamp) when this client cannot build that codec.
   * A Collection with no stored `custom` sends none, which clears an
   * already-empty value on an encrypted Collection just as on a plaintext one.
   * Returns the new `ETag`, and the object the server answers a create with.
   *
   * This is the generic compare-and-swap primitive the key-epoch recipient
   * operations build on (add/remove a reader is a CAS of the `encryption`
   * descriptor); it is not epoch-specific.
   *
   * @param description {CollectionWritableFields}
   * @param options {object}
   * @param [options.ifMatch] {string}   the prior `ETag`; the write applies only
   *   if the object is unchanged
   * @param [options.ifNoneMatch] {boolean}   write only if the Collection does
   *   not exist yet
   * @returns {Promise<{ description: CollectionMetadata; etag?: string }>}
   */
  async replaceDescription(
    description: CollectionWritableFields,
    options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
  ): Promise<{ description: CollectionMetadata; etag?: string }> {
    const fields = collectionWritableFields(description)
    const { metadata, etag } = await this.#writeStored({
      compose: stored => this.#configurationBody(stored, fields),
      operation: 'Collection configuration',
      // A caller pinning a validator is writing to an object it has read, so
      // an unreadable one is a lost Collection, not a create. An unconditional
      // call stays the upsert it has always been.
      allowAbsent: options.ifMatch === undefined,
      ifMatch: options.ifMatch,
      ifNoneMatch: options.ifNoneMatch
    })
    this.#resetCodecIfDeclared(description.encryption)
    return {
      description: metadata ?? {
        id: this.id,
        type: ['Collection'],
        ...fields
      },
      ...(etag !== undefined && { etag })
    }
  }

  /**
   * The write body of a configuration write: the caller's configuration
   * members over everything the stored object carries that this write is not
   * about -- the annotations, and any member this client does not model.
   * Shared by {@link configure} and {@link replaceDescription}, whose bodies
   * differ only in how the configuration members were arrived at.
   *
   * @param stored {StoredCollectionMetadata | null}
   * @param fields {CollectionWritableFields}   the configuration this write
   *   states in full
   * @returns {Promise<StoredCollectionMetadata>}
   */
  async #configurationBody(
    stored: StoredCollectionMetadata | null,
    fields: CollectionWritableFields
  ): Promise<StoredCollectionMetadata> {
    const base = stored ?? {}
    const resealed = await this.#resealedCustom(base, fields.encryption)
    const carried = carriedForward(base, {
      replacing:
        resealed === null
          ? CONFIGURATION_MEMBERS
          : [...CONFIGURATION_MEMBERS, ...ANNOTATION_MEMBERS]
    })
    return { ...carried, ...(resealed ?? {}), ...fields }
  }

  /**
   * The annotations a configuration write that CHANGES the encryption scheme
   * sends: the stored `custom` opened under the descriptor it was sealed with
   * and re-sealed under the incoming one, with the new key epoch stamped
   * beside it. The server validates `custom` against the incoming descriptor,
   * so forwarding a plaintext `custom` beside a newly declared descriptor is
   * refused (422, `encryption-scheme-mismatch`) -- and the spec states the same
   * rule: a change to `encryption` requires the envelope to be re-sealed.
   *
   * Resolves `null` when the write leaves the scheme as it is (the ordinary
   * case, an epoch rotation included), meaning "carry the stored annotations
   * forward untouched". Resolves `{}` -- drop `custom` and its stamp -- when
   * the re-seal is not possible here: this client cannot build a codec for one
   * of the two descriptors, or the stored envelope is one it cannot open. The
   * name and tags inside are lost in that case, which is why the re-seal is
   * attempted first.
   *
   * @param stored {StoredCollectionMetadata}
   * @param [encryption] {CollectionEncryption}   the descriptor this write
   *   states
   * @returns {Promise<{ custom?: unknown; epoch?: string } | null>}
   */
  async #resealedCustom(
    stored: StoredCollectionMetadata,
    encryption?: CollectionEncryption
  ): Promise<{ custom?: unknown; epoch?: string } | null> {
    const declared = storedEncryption(stored)
    if (encryption?.scheme === declared?.scheme) {
      return null
    }
    if (stored.custom === undefined) {
      return null
    }
    try {
      const [from, to] = await Promise.all([
        codecForDescriptor(this.#context, {
          spaceId: this.spaceId,
          collectionId: this.id,
          ...(declared !== undefined && { descriptor: declared })
        }),
        codecForDescriptor(this.#context, {
          spaceId: this.spaceId,
          collectionId: this.id,
          ...(encryption !== undefined && { descriptor: encryption })
        })
      ])
      if (from === null || to === null) {
        return {}
      }
      const slot = { kind: 'collection' } as const
      const opened = await from.decodeMeta({ custom: stored.custom }, slot)
      const { custom, epoch } = await to.encodeMeta({ custom: opened, slot })
      return { custom, ...(epoch !== undefined && { epoch }) }
    } catch {
      return {}
    }
  }

  /**
   * Drops any memoized codec when a write declared an `encryption` descriptor.
   * Writing it can rotate the key epoch (the recipient operations CAS this
   * member) or flip the collection from plaintext to encrypted, and a codec
   * memoized from the prior descriptor would keep encrypting under the stale
   * epoch -- whose key a just-removed reader still holds -- or write
   * server-visible plaintext into a now-encrypted collection. Child resource
   * handles share this codec via their thunk, so resetting here propagates to
   * them too.
   *
   * @param [encryption] {CollectionEncryption}   the descriptor the write
   *   declared, if any
   * @returns {void}
   */
  #resetCodecIfDeclared(encryption?: CollectionEncryption): void {
    if (encryption !== undefined) {
      this.#codecHolder.reset()
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
   * Reads the Collection Metadata object with its user-writable `custom`
   * decoded -- {@link describe} plus the codec. Returns `null` if the
   * collection is missing or not visible to you (404 conflation caveat). A
   * server without Collection metadata support surfaces its 501 as
   * `NotImplementedError`.
   *
   * On an encrypted collection the stored `custom` is an opaque envelope; this
   * decodes it (decrypts, via the codec) so a caller always sees plaintext
   * `{ name, tags }`. A collection with no user metadata reports `custom` as
   * `{}`. Resolving the codec can fail closed on a collection this client holds
   * no keys for, which is why {@link describe} -- the configuration read -- goes
   * without it.
   *
   * Against a backend with the `conditional-writes` feature the result also
   * carries the object's current `etag` (its `metaVersion` validator) -- pass it
   * as `setMeta(meta, { ifMatch })` for a lost-update-safe update. One
   * validator covers the whole object: a configuration write and an annotation
   * write advance the same counter, so a client holds one ETag for the
   * Collection rather than one per surface.
   *
   * @returns {Promise<(CollectionMetadata & { etag?: string }) | null>}
   */
  async meta(): Promise<(CollectionMetadata & { etag?: string }) | null> {
    // Resolving the codec on a blinded-index collection reads `meta` itself
    // (for the index schema). When this call is the one that started that
    // resolution, its snapshot is this read's answer -- take it rather than
    // GETting and decrypting the same document twice. Every other caller gets
    // no snapshot and reads for itself, so a `meta()` never serves a
    // point-in-time copy another client may have overwritten since.
    const { codec, meta } = await this.#codecHolder.resolve()
    if (meta !== undefined) {
      return meta
    }
    return readMeta<CollectionMetadata>(this.#context, {
      metaPath: this.#metaPath,
      codec: Promise.resolve(codec),
      subject: `collection "${this.id}"`,
      slot: { kind: 'collection' },
      capability: this.#capability,
      // `setName` / `setTags` / `declareIndex` write straight back through
      // `setMeta`, so this read is the baseline that write composes against
      // rather than a second `GET` of the same object.
      onStored: read => {
        this.#remember(read)
      }
    })
  }

  /**
   * Replaces the Collection's user-writable annotations (`custom`). This is a
   * full replacement of `custom`: any property omitted from it is cleared, and
   * an omitted `custom` clears them all. The Collection's configuration
   * members are carried forward -- the same `PUT` replaces the whole
   * Collection Metadata object, so they are read and re-sent rather than
   * dropped.
   *
   * On an encrypted collection `custom` is encrypted into an opaque envelope by
   * the codec before it is sent, so `name` / `tags` are never stored as
   * server-visible plaintext -- transparently, the same call works on plaintext
   * and encrypted collections alike. The key epoch the codec stamps the
   * envelope with travels as a top-level `epoch` member of the same body.
   *
   * Conditional writes (the backend's `conditional-writes` feature): pass
   * `ifMatch` (the `etag` from a prior {@link meta} or {@link describe}) for an
   * update-if-unchanged, and a failed precondition throws
   * `PreconditionFailedError` (412). Without one the write is pinned to the
   * version it composed the configuration from and rebases on a lost race.
   * `ifNoneMatch: true` is the guarded create: one validator covers the whole
   * object, which exists exactly as long as its Collection does, so it means
   * "create the Collection only if it does not exist" -- and creates it with no
   * configuration, the plaintext codec encoding its `custom` (nothing is
   * stored yet to declare encryption, and a per-handle override is the only
   * way to state it). Every other annotation write requires the Collection to
   * be there: one that cannot read the current object throws `NotFoundError`
   * rather than upserting a configuration-less Collection over one this
   * capability cannot see. Returns the new `etag`.
   *
   * @param meta {object}
   * @param [meta.custom] {ResourceMetadataCustomInput}   the user-writable
   *   properties; extra members beyond `name` / `tags` are admitted (this
   *   Collection-level `custom` also carries the persisted `indexSchema`)
   *   while `name` / `tags` themselves stay checked at their stored types
   * @param options {object}
   * @param [options.ifMatch] {string}       update only if the `ETag` matches
   * @param [options.ifNoneMatch] {boolean}  create only if the Collection does
   *   not exist
   * @returns {Promise<{ etag?: string }>}   the object's new ETag
   */
  async setMeta(
    meta: { custom?: ResourceMetadataCustomInput } = {},
    options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
  ): Promise<{ etag?: string }> {
    const codec = await this.#codecForWrite(options.ifNoneMatch === true)
    const { custom, epoch } = await codec.encodeMeta({
      custom: meta.custom ?? {},
      slot: { kind: 'collection' }
    })
    const { etag } = await this.#writeStored({
      // The configuration members come from the stored object and the
      // annotations from this call. The epoch stamp describes the `custom`
      // envelope itself, so it is re-stated with it; the server clears the
      // stored stamp when the member is omitted, which is exactly right on a
      // plaintext collection, whose codec surfaces no epoch.
      compose: stored => ({
        ...carriedForward(stored ?? {}, { replacing: ANNOTATION_MEMBERS }),
        custom,
        ...(epoch !== undefined && { epoch })
      }),
      operation: 'Collection metadata update',
      // The create states its own absence; every other annotation write is
      // about a Collection that exists, and an unreadable one is refused
      // rather than upserted over (see `#writeStored`).
      allowAbsent: false,
      ifMatch: options.ifMatch,
      ifNoneMatch: options.ifNoneMatch
    })
    return { etag }
  }

  /**
   * The codec an annotation write encodes `custom` with. The ordinary write
   * uses the handle's resolved codec, discovered from the Collection's stored
   * `encryption` descriptor. The guarded create cannot: there is nothing
   * stored to discover, and descriptor discovery on an absent Collection is
   * exactly the masked-404 an encryption-capable client fails closed on -- it
   * would refuse the create it was asked to make. So the create takes its
   * encryption state from what it is writing: a per-handle override when the
   * caller pinned one, and otherwise the plaintext codec, because the body it
   * sends declares no descriptor.
   *
   * @param creating {boolean}   whether this write is the guarded create
   * @returns {Promise<ResourceCodec>}
   */
  async #codecForWrite(creating: boolean): Promise<ResourceCodec> {
    if (creating && this.#encryptionOverride === undefined) {
      return identityCodec
    }
    return this.#codec()
  }

  /**
   * Sets the Collection's annotation-level human-readable `name`, preserving
   * any existing `tags`. Convenience over `setMeta()`. The write is pinned to
   * the `etag` the `meta()` read returned (when the backend supports
   * `conditional-writes`) and rebases on a lost race, so a concurrent write --
   * an annotation write or a configuration change, which share the one
   * validator -- is re-read and re-applied rather than silently erased by this
   * full-replacement write.
   *
   * On an encrypted collection this is the collection's client-encrypted name
   * surface: the codec seals it into the `custom` envelope, and by convention
   * the plaintext top-level `name` is left unpopulated. On a plaintext
   * collection the two are separate labels -- space-level listings surface the
   * top-level `name` (set via `configure({ name })`), while this one is inside
   * `custom`.
   *
   * @param name {string}
   * @returns {Promise<void>}
   */
  async setName(name: string): Promise<void> {
    return patchCustom(this, { name }, 'Collection name update')
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
    return patchCustom(this, { tags }, 'Collection tags update')
  }

  get #logPath(): string {
    return collectionLog(this.spaceId, this.id)
  }

  /**
   * The absolute URL of the Collection's governing history log, the `meta/log`
   * sub-resource {@link getHistoryLog} reads. A log-governed descriptor's
   * `history.resource` names this URL; a verifying reader compares the two
   * before opening the log.
   *
   * @returns {string}
   */
  get historyLogUrl(): string {
    return toUrl({ serverUrl: this.#context.serverUrl, path: this.#logPath })
  }

  /**
   * Reads the Collection's governing history log (the backend's
   * `governed-history-logs` feature): the JSON Lines body served at the
   * `/meta/log` sub-resource, verbatim, together with its `ETag`. The log is
   * not a Resource of the Collection (absent from listings and the `changes`
   * feed) and not part of the `/meta` object; it is versioned by its own
   * validator, which {@link putHistoryLog} takes as `ifMatch` for a
   * compare-and-swap append. Returns `null` when the Collection has no log,
   * or is missing or not visible to you (404 conflation caveat). A log served
   * under a JSON content type (whose body the HTTP client has already parsed)
   * is not a JSON Lines log and throws `ValidationError`.
   *
   * This is the raw transport read. The `@interop/was-client/log` subpath's
   * `resourceLogStore({ collection })` drives it as the store port of
   * `@interop/vh-resource-log`, which parses and verifies the entries.
   *
   * @returns {Promise<{ body: string; etag?: string } | null>}
   */
  async getHistoryLog(): Promise<{ body: string; etag?: string } | null> {
    const response = await send(this.#context, {
      path: this.#logPath,
      method: 'GET',
      capability: this.#capability,
      read: true
    })
    if (response === null) {
      return null
    }
    if (response.data !== undefined) {
      throw new ValidationError(
        `Cannot read the history log of collection "${this.id}": the server ` +
          'served it as JSON, not as a JSON Lines text body.'
      )
    }
    const body = await response.text()
    const etag = readEtag(response)
    return etag !== undefined ? { body, etag } : { body }
  }

  /**
   * Writes the Collection's governing history log as one JSON Lines body
   * (`text/jsonl`), replacing it whole under a precondition: `ifNoneMatch:
   * true` is the guarded create that declares the Collection log-governed
   * (refused with `ConflictError` on a Collection whose Description already
   * carries a client-written `encryption` descriptor), and `ifMatch` (the
   * `etag` of a prior {@link getHistoryLog}) is the compare-and-swap append,
   * whose body is the prior bytes verbatim plus the new line. A failed
   * precondition throws `PreconditionFailedError` (412). A body that breaks
   * the line contract, or whose head `state` violates an encryption
   * transition against the prior head, throws `ValidationError` (400).
   *
   * The write is always conditional: the profile forbids replacing a log
   * unguarded (the server checks the head-state transition, not chain
   * continuity, so an unconditional PUT could replace a longer verified log
   * wholesale). A call naming neither `ifMatch` nor `ifNoneMatch` throws
   * `ValidationError` before any request.
   *
   * From the guarded create on, the Collection's served `encryption` member
   * is derived by the server from the log head's `state`, and a direct
   * `encryption` write on the Description is refused with `ConflictError`.
   * Returns the log's new `etag`.
   *
   * @param body {string}   the complete JSON Lines log
   * @param options {object}
   * @param [options.ifMatch] {string}       append only if the log ETag matches
   * @param [options.ifNoneMatch] {boolean}  create only if no log exists
   * @returns {Promise<{ etag?: string }>}   the log's new ETag
   */
  async putHistoryLog(
    body: string,
    options: { ifMatch?: string; ifNoneMatch?: boolean }
  ): Promise<{ etag?: string }> {
    if (options.ifMatch === undefined && !options.ifNoneMatch) {
      throw new ValidationError(
        `Cannot write the history log of collection "${this.id}": pass ` +
          '`ifMatch` (the prior log ETag) or `ifNoneMatch: true`; an ' +
          'unconditional write is forbidden.'
      )
    }
    const response = await send(this.#context, {
      path: this.#logPath,
      method: 'PUT',
      capability: this.#capability,
      body: ENCODER.encode(body),
      headers: writeHeaders({
        contentType: LOG_CONTENT_TYPE,
        precondition: {
          ifMatch: options.ifMatch,
          ifNoneMatch: options.ifNoneMatch
        }
      })
    })
    // From the guarded create on, the served `encryption` member IS a
    // projection of this log's head state, so every write here can rotate the
    // key epoch or flip the collection from plaintext to encrypted -- exactly
    // what `replaceDescription` resets for, reached by the other route. Drop
    // the memoized codec so the next read/write re-resolves it against the
    // new head; otherwise a `put` on this handle after a `removeRecipient`
    // would keep encrypting under the rotated-out epoch (whose key the
    // just-removed reader still holds), and a `put` after a guarded create
    // would write server-visible plaintext through the identity codec the
    // pre-governed description resolved.
    this.#codecHolder.reset()
    return { etag: readEtag(response) }
  }

  /**
   * The codec's search capability, or a typed refusal when this collection is
   * not searchable this way -- a plaintext collection (whose contents the
   * server can index itself) or an encrypted collection provisioned without a
   * blinded-index key (which is installed at provisioning or never, since
   * retro-fitting one would leave every already-written document unindexed).
   *
   * @param operation {string}   what the caller was trying to do, for the message
   * @returns {Promise<CodecIndexing>}
   */
  async #indexing(operation: string): Promise<CodecIndexing> {
    return (await this.#resolveIndexing(operation)).indexing
  }

  /**
   * {@link Collection.#indexing}, plus the metadata snapshot the codec
   * resolution read when this call is the one that started it (see
   * {@link CodecHolder.resolve}). `declareIndex` uses it for its first read;
   * `meta` is `undefined` whenever there is no snapshot to reuse.
   *
   * @param operation {string}   what the caller was trying to do, for the message
   * @returns {Promise<{ indexing: CodecIndexing; meta?: (CollectionMetadata & { etag?: string }) | null }>}
   */
  async #resolveIndexing(operation: string): Promise<{
    indexing: CodecIndexing
    meta?: (CollectionMetadata & { etag?: string }) | null
  }> {
    const { codec, meta } = await this.#codecHolder.resolve()
    if (!codec.indexing) {
      throw new ValidationError(
        `Cannot ${operation} on collection "${this.id}": it carries no ` +
          'client-side search index. Only an encrypted collection provisioned ' +
          'with a blinded-index key is searchable this way (install it at ' +
          'creation with ensureFirstEpoch({ blindedIndex: true }) -- it cannot ' +
          'be added later). A plaintext collection is queried server-side ' +
          'instead.'
      )
    }
    return meta !== undefined
      ? { indexing: codec.indexing, meta }
      : { indexing: codec.indexing }
  }

  /**
   * Reads the Collection's persisted index schema: which attributes its
   * documents are searchable by, whether each index is unique, and the schema
   * revision each was added in. Any recipient that can decrypt the collection
   * can read it, which is the point of persisting it -- an app granted access
   * to an existing collection learns what is queryable with no out-of-band
   * coordination (the stored index tokens cannot teach it, being blinded).
   *
   * `addedIn` is the partial-coverage marker: documents written before an
   * attribute was declared carry no token for it, so they do not match a search
   * on it until they are rewritten.
   *
   * @returns {Promise<IndexDeclaration[]>}
   */
  async indexes(): Promise<IndexDeclaration[]> {
    const indexing = await this.#indexing('read the index schema')
    return indexing.schema().indexes
  }

  /**
   * Declares an attribute searchable, persisting it in the Collection's
   * encrypted index schema and installing it on this handle's codec.
   * Idempotent: re-declaring an attribute already in the schema on the same
   * terms is a no-op write.
   *
   * Declarations are collection state, not app state: they are stored inside
   * the encrypted `/meta` envelope, so every recipient discovers them (see
   * {@link indexes}). Concurrent declarations from two clients are reconciled
   * with a compare-and-swap against the metadata's own `metaVersion` ETag and a
   * bounded retry, so neither is silently erased.
   *
   * A declaration is prospective: documents already written carry no token for
   * the new attribute and do not match a search on it until they are rewritten
   * (the backfill is a re-encrypt sweep of the collection).
   *
   * Pass an array of attribute names for a compound index. A compound index can
   * be searched by a leading prefix of its attributes; `unique` is enforced
   * only when a document carries the whole combination.
   *
   * @param options {object}
   * @param options.attribute {string | string[]}   a dotted attribute path
   *   rooted at `content` or `meta` (e.g. `content.type`), or an array of them
   *   for a compound index
   * @param [options.unique] {boolean}   reject a second document that carries
   *   the same value (the server answers a colliding write with `409`)
   * @returns {Promise<IndexSchema>}   the schema now in force
   */
  async declareIndex({
    attribute,
    unique
  }: {
    attribute: string | string[]
    unique?: boolean
  }): Promise<IndexSchema> {
    const { indexing, meta: snapshot } =
      await this.#resolveIndexing('declare an index')
    const declared = normalizeAttribute(attribute)
    const key = attributeKey(declared)
    // Read, reconcile, conditionally write. A 412 means another client wrote
    // the metadata between the read and the write, so the shared loop re-reads
    // and re-applies rather than clobbering its declaration with ours.
    //
    // The first read reuses the metadata the codec resolution above already
    // read (when this call is what triggered it); every retry re-reads, since
    // a 412 means the document changed.
    let reusable = snapshot
    const custom = await compareAndSwap<CustomWithIndexSchema>({
      store: {
        read: async () => {
          const current = reusable !== undefined ? reusable : await this.meta()
          reusable = undefined
          return {
            value: (current?.custom ?? {}) as CustomWithIndexSchema,
            etag: current?.etag
          }
        },
        // The schema shares the `custom` object with the user's own `name` /
        // `tags`, which are carried forward untouched.
        replace: async (next, { ifMatch }) => {
          await this.setMeta({ custom: next }, { ifMatch })
        }
      },
      operation: 'Index declaration',
      mutate: current => {
        const schema = readIndexSchema(current)
        const existing = schema.indexes.find(
          entry => attributeKey(entry.attribute) === key
        )
        if (existing) {
          if ((existing.unique === true) !== (unique === true)) {
            throw new ValidationError(
              `Cannot declare index "${key}" as ` +
                `${unique === true ? 'unique' : 'non-unique'}: this ` +
                'collection already declares it as ' +
                `${existing.unique === true ? 'unique' : 'non-unique'}. An ` +
                'index cannot change uniqueness in place -- already-stored ' +
                'documents were indexed under the old terms.'
            )
          }
          // Already declared: nothing to write.
          return null
        }
        const revision = schema.revision + 1
        return {
          ...current,
          [INDEX_SCHEMA_PROPERTY]: {
            revision,
            indexes: [
              ...schema.indexes,
              {
                attribute: declared,
                ...(unique === true && { unique: true as const }),
                addedIn: revision
              }
            ]
          }
        }
      }
    })
    const schema = readIndexSchema(custom)
    indexing.applySchema(schema)
    return schema
  }

  /**
   * Searches the collection's encrypted documents by indexed attribute. The
   * terms are blinded client-side before they are sent, so the server matches
   * opaque tokens and learns neither the attribute names nor the values; the
   * documents it returns are decrypted here, exactly as `get()` decrypts one.
   *
   * Give either `equals` (attribute/value pairs a document must match -- an
   * array of objects is an OR of alternatives) or `has` (attribute names a
   * document must carry), not both. Every attribute named must already be in
   * the collection's schema ({@link declareIndex}); an undeclared one is
   * refused with `ValidationError` rather than silently matching nothing.
   *
   * Pass `count: true` for just the number of matches. Otherwise the result is
   * one page: `limit` caps its size (the server clamps its own maximum), and a
   * `hasMore` page carries the `cursor` to pass back for the next one.
   *
   * Requires the collection's backend to advertise the `blinded-index-query`
   * feature; a backend without it answers `501` (`NotImplementedError`).
   *
   * @param options {object}
   * @param [options.equals] {object | object[]}   attribute/value pairs to match
   * @param [options.has] {string | string[]}   attribute names to require
   * @param [options.count] {boolean}   return `{ count }` instead of documents
   * @param [options.limit] {number}   maximum documents in the page
   * @param [options.cursor] {string}   continue from a previous page
   * @returns {Promise<FindPage | { count: number }>}
   */
  async find(options: {
    equals?: Record<string, unknown> | Array<Record<string, unknown>>
    has?: string | string[]
    count?: boolean
    limit?: number
    cursor?: string
  }): Promise<FindPage | { count: number }> {
    const { equals, has, count, limit, cursor } = options
    const indexing = await this.#indexing('search')
    const codec = await this.#codec()
    const query = await indexing.buildQuery({ equals, has })
    const response = await send(this.#context, {
      path: collectionQuery(this.spaceId, this.id),
      method: 'POST',
      capability: this.#capability,
      // The profile is bound here the way `changes()` binds its own: same
      // endpoint, no client-side feature probe -- a backend that does not
      // implement the profile answers 501, which is a clearer signal than a
      // guess made from the backend descriptor.
      json: {
        profile: 'blinded-index',
        ...query,
        ...(count === true && { count: true }),
        ...(limit !== undefined && { limit }),
        ...(cursor !== undefined && { cursor })
      }
    })
    const result = dataOrNull<{
      documents?: unknown[]
      hasMore?: boolean
      cursor?: string
      count?: number
    }>(response)
    if (result === null) {
      throw new WasServerError(
        `Search response for collection "${this.id}" carried no JSON body.`
      )
    }
    if (count === true) {
      return { count: typeof result.count === 'number' ? result.count : 0 }
    }
    const documents = Array.isArray(result.documents) ? result.documents : []
    // Each envelope is an independent JWE open with nothing carried between
    // them, so the page decrypts concurrently. `Promise.all` preserves order,
    // so `items` still matches the server's ranking.
    const codecContext = this.#codecContext()
    const items: FindPage['items'] = await Promise.all(
      documents.map(async envelope => {
        // Restrict-mode ids make the stored document's own id the WAS resource
        // id, so it is also the id the codec verifies the envelope's
        // AEAD-authenticated binding against -- a server that returns one
        // document under another's id is caught here, not trusted.
        const id = (envelope as { id?: unknown }).id
        if (typeof id !== 'string') {
          throw new WasServerError(
            `Search response for collection "${this.id}" returned a document ` +
              'with no id.'
          )
        }
        return {
          id,
          data: await codec.decode(storedResponse(envelope), id, codecContext)
        }
      })
    )
    return {
      items,
      hasMore: result.hasMore === true,
      ...(result.cursor !== undefined && { cursor: result.cursor })
    }
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
      features: this.#features,
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
   * On an encrypted collection a binary payload above the codec's
   * single-document threshold is auto-routed to the chunked-stream path, which
   * needs the backend's `chunked-streams` feature (`NotSupportedError` without
   * it, raised before anything is written).
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
    const itemsPath = this.#path
    const outcome = await insertResource(this.#context, {
      itemsPath,
      pathForId: mintedId => resourcePath(this.spaceId, this.id, mintedId),
      codec,
      data,
      features: this.#features,
      contentType: options.contentType,
      capability: this.#capability
    })

    // A codec's multi-request plan wrote to an id it minted itself, and
    // reported back whatever validator its last write surfaced.
    if (outcome.chunked === true) {
      return {
        id: outcome.id,
        url: toUrl({ serverUrl: this.#context.serverUrl, path: outcome.path }),
        contentType: outcome.contentType,
        etag: outcome.etag
      }
    }

    const { encoded, path, response } = outcome
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
        path: this.#path
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
   * `checkpoint` back. Only a `null` checkpoint (an empty page) means you have
   * caught up: a page shorter than `limit` does not, since the server reduces
   * `limit` to its own maximum, so a short page can still be a full server
   * page.
   *
   * Requires the collection's backend to advertise the `changes-query` feature
   * (see `backend()`); a backend without it answers `501`. On an encrypted
   * collection the documents' `data` / `custom` are the scheme's opaque
   * envelopes (an EDV encrypted document under the v1 `edv` scheme) -- this
   * method does not decrypt them, unlike `get()`.
   *
   * Malformed responses fail the call with a `WasServerError` instead of
   * passing through as a page: a 2xx response with no JSON body
   * (indistinguishable from an end-of-feed page otherwise), a body with no
   * `documents` array or with a non-object entry in it, and a live entry with
   * no `data` (the server could not read or parse that resource's body).
   *
   * @param [options] {object}
   * @param [options.checkpoint] {ChangesCheckpoint}   resume strictly after this
   * @param [options.limit] {number}   max documents; the server reduces it to its own maximum
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
    // -shaped call on this handle does. A `null` here is therefore a 2xx whose
    // body did not parse as JSON, which must not masquerade as the end-of-feed
    // page `{ documents: [], checkpoint: null }`.
    const page = dataOrNull<ChangesPage>(response)
    if (page === null) {
      throw new WasServerError(
        `The changes feed of collection "${this.id}" answered with no JSON ` +
          `body (content-type ` +
          `"${response?.headers.get('content-type') ?? 'unknown'}").`
      )
    }
    // A 2xx body that parsed but carries no `documents` array is the same
    // class of server fault as a bodiless one: reported as a typed
    // `WasServerError`, not as a `TypeError` from iterating `undefined`.
    if (!Array.isArray(page.documents)) {
      throw new WasServerError(
        `The changes feed of collection "${this.id}" answered with no ` +
          '`documents` array.'
      )
    }
    for (const doc of page.documents) {
      // `Array.isArray` accepts `[null]`; a non-object entry is the same class
      // of server fault, reported as a typed `WasServerError` rather than as a
      // `TypeError` from reading `_deleted` off it.
      if (doc === null || typeof doc !== 'object') {
        throw new WasServerError(
          `The changes feed of collection "${this.id}" served a non-object ` +
            'entry in its `documents` array.'
        )
      }
      if (!doc._deleted && doc.data === undefined) {
        throw new WasServerError(
          `The changes feed of collection "${this.id}" served resource ` +
            `"${doc.id}" with no body: the server could not read it.`
        )
      }
    }
    return page
  }

  /**
   * Reads the collection's current live JSON documents, bodies included, by
   * walking the `changes` feed from its beginning to its end. One request per
   * page rather than one per resource, so a reader with no local replica
   * snapshots a collection in a handful of round trips.
   *
   * The feed is in ascending `(updatedAt, id)` order and carries tombstones,
   * so the pages reduce to the latest state per id: a later entry for an id
   * replaces an earlier one (a resource rewritten while the walk was in
   * flight) and a tombstone drops it. Each surviving entry is returned as the
   * feed served it, so `data` is the raw stored body (the scheme's opaque
   * envelope on an encrypted collection; this method does not decrypt) and
   * `epoch`, `version`, and `createdBy` ride along. Feed order is preserved.
   *
   * The walk ends only on the feed's `checkpoint: null`; a short page is not
   * the end (see `changes()`). Returns `null` if the collection is missing or
   * not visible to you (404 conflation caveat) on the first page, like
   * `list()`. Unlike `list()`, a 404 on a later page throws: the collection
   * vanished mid-walk, and the pages already read are not a snapshot of
   * anything. The server faults `changes()` rejects on (a bodiless 2xx, a
   * live entry with no `data`, or a `501` from a backend without the
   * `changes-query` feature) fail the walk with the same `WasServerError`, as
   * does a server that repeats a checkpoint instead of advancing.
   *
   * @param [options] {object}
   * @param [options.limit] {number}   max documents per request (default 1000, the teaching server's maximum); the server reduces it to its own maximum
   * @returns {Promise<ChangeDocument[] | null>}
   */
  async documents(
    options: { limit?: number } = {}
  ): Promise<ChangeDocument[] | null> {
    const { limit = 1000 } = options
    const latest = new Map<string, ChangeDocument>()
    // Every checkpoint the walk has resumed from, keyed by its wire position.
    // A server that hands one back again would otherwise loop forever.
    const seen = new Set<string>()
    let checkpoint: ChangesCheckpoint | undefined
    for (;;) {
      let page: ChangesPage
      try {
        page = await this.changes({ checkpoint, limit })
      } catch (err) {
        if (checkpoint === undefined && httpStatus(err) === 404) {
          return null
        }
        throw err
      }
      for (const doc of page.documents) {
        // Delete first so a rewritten resource takes its new feed position.
        latest.delete(doc.id)
        if (!doc._deleted) {
          latest.set(doc.id, doc)
        }
      }
      // A terminal page is one with no checkpoint to resume from, whether the
      // server spelled that as an explicit `null` or by omitting the member.
      if (!page.checkpoint) {
        return [...latest.values()]
      }
      const position = `${page.checkpoint.updatedAt}\u0000${page.checkpoint.id}`
      if (seen.has(position)) {
        throw new WasServerError(
          `The changes feed of collection "${this.id}" repeated checkpoint ` +
            `${JSON.stringify(page.checkpoint)} instead of advancing.`
        )
      }
      seen.add(position)
      checkpoint = page.checkpoint
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
