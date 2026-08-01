/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The marker-store seam: where a `CollectionEncryption` marker lives and how it
 * is compare-and-swapped. The recipient primitives (`initRecipients` /
 * `addRecipient` / `removeRecipient`) mutate a marker only through this port,
 * so the same key-epoch machinery manages a Collection's own `encryption`
 * marker (the classic host) or a marker hosted as a plain JSON Resource (e.g. a
 * per-user-key roster in a private collection).
 *
 * Two adapters:
 *
 * - {@link collectionMarkerStore} -- the Collection Description's `encryption`
 *   member, read with `describeWithEtag` and written back with
 *   `replaceDescription` + `If-Match`. The server enforces the marker
 *   invariants (append-only epochs, monotone `currentEpoch`, non-decreasing
 *   `version`) on this path.
 * - {@link resourceMarkerStore} -- a marker stored verbatim as a JSON Resource.
 *   The server treats the resource as opaque content and enforces NO marker
 *   invariants there; integrity rests on the client-side `epochsMac` (verified
 *   by writers before encrypting) plus client-side epoch pinning. Both the
 *   compare-and-swap and the create-if-absent guard ride the backend's
 *   `conditional-writes` feature. The hosting collection must be plaintext: on
 *   an encrypted collection the EDV codec computes the write preconditions
 *   itself and the store's `ifMatch` would not be honored.
 */
import type { Collection } from '../Collection.js'
import type { Resource } from '../Resource.js'
import { unreadableDescriptionError } from '../internal/describe.js'
import { ValidationError } from '../errors.js'
import type {
  CollectionDescription,
  CollectionEncryption,
  JsonObject
} from '../types.js'

/**
 * Where a `CollectionEncryption` marker lives: a read-with-validator plus a
 * compare-and-swap write, the two operations the recipient primitives' CAS
 * loop needs. Implementations host the marker anywhere a versioned JSON value
 * can live; the two shipped adapters are {@link collectionMarkerStore} and
 * {@link resourceMarkerStore}.
 */
export interface MarkerStore {
  /**
   * Reads the current marker together with the opaque `etag` validator the
   * next {@link replace} must be compare-and-swapped against. Resolves `null`
   * when no marker exists yet AND this store can create one (the resource
   * adapter before the first `initRecipients`); a store whose host must
   * already exist (the description adapter) throws instead of resolving
   * `null`. Throws when the hosted value is not an `edv`-scheme marker.
   *
   * @returns {Promise<{ marker: CollectionEncryption; etag?: string } | null>}
   */
  read(): Promise<{ marker: CollectionEncryption; etag?: string } | null>

  /**
   * Replaces the marker, compare-and-swapped against `ifMatch` (the validator
   * from {@link read}); a stale validator throws `PreconditionFailedError`
   * (412). Must follow a {@link read} on the same store instance -- an adapter
   * may forward sibling state observed by its most recent read (the
   * description adapter forwards the description's `name` / `backend`).
   *
   * @param marker {CollectionEncryption}
   * @param options {object}
   * @param [options.ifMatch] {string}   the validator from the prior read;
   *   absent against a host that does not version its writes
   * @returns {Promise<void>}
   */
  replace(
    marker: CollectionEncryption,
    options: { ifMatch?: string }
  ): Promise<void>

  /**
   * Creates the FIRST marker where {@link read} resolved `null`, guarded
   * create-if-absent (`If-None-Match: *`); throws `PreconditionFailedError`
   * (412) when a concurrent writer created one first. Absent on stores whose
   * host always exists (the description adapter).
   *
   * @param marker {CollectionEncryption}
   * @returns {Promise<void>}
   */
  create?(marker: CollectionEncryption): Promise<void>
}

/**
 * The Collection Description adapter: the marker is the Description's
 * `encryption` member. Read fails closed when the Description is unreadable
 * (WAS masks unauthorized reads as 404) or the collection is not declared
 * encrypted with the `edv` scheme; the CAS write forwards the description's
 * sibling fields (`name` / `backend`) observed by the most recent read, so
 * the replace-semantics PUT does not drop them. No `create`: a Collection
 * Description always exists, so a first marker is declared via
 * `collection.configure({ encryption })`, never through this store.
 *
 * @param options {object}
 * @param options.collection {Collection}
 * @returns {MarkerStore}
 */
export function collectionMarkerStore({
  collection
}: {
  collection: Collection
}): MarkerStore {
  // The sibling description fields observed by the most recent read, forwarded
  // verbatim by the CAS write (the server's replace semantics would otherwise
  // drop them). Safe to forward even if stale: the write is pinned to the same
  // read's ETag, so a concurrent description change fails the CAS instead.
  let described: CollectionDescription | undefined
  return {
    async read() {
      const current = await collection.describeWithEtag()
      if (current === null) {
        throw unreadableDescriptionError({
          operation: 'manage recipients',
          advice: 'Use a capability that can read the Collection Description.'
        })
      }
      const marker = current.description.encryption
      if (!marker || marker.scheme !== 'edv') {
        throw new ValidationError(
          'Cannot manage recipients: this collection is not declared ' +
            "encrypted with the 'edv' scheme."
        )
      }
      described = current.description
      return { marker, etag: current.etag }
    },
    async replace(marker, { ifMatch }) {
      await collection.replaceDescription(
        {
          name: described?.name,
          backend: described?.backend,
          encryption: marker
        },
        { ifMatch }
      )
    }
  }
}

/**
 * The plain-JSON-Resource adapter: the marker is the resource's entire
 * content, stored verbatim. Read resolves `null` when the resource is absent
 * (the pre-`initRecipients` state -- `create` then writes the first marker
 * with `If-None-Match: *`), and throws when the resource holds something other
 * than an `edv`-scheme marker object.
 *
 * The server enforces no marker invariants on a resource (unlike a Collection
 * Description): rollback/tamper detection rests on the marker's `epochsMac`
 * and client-side epoch pinning, and the CAS/create guards ride the backend's
 * `conditional-writes` feature. Host the resource in a plaintext collection --
 * on an encrypted collection the EDV codec computes the write preconditions
 * itself, so this store's `ifMatch` would not be honored.
 *
 * @param options {object}
 * @param options.resource {Resource}
 * @returns {MarkerStore}
 */
export function resourceMarkerStore({
  resource
}: {
  resource: Resource
}): MarkerStore {
  return {
    async read() {
      const current = await resource.getWithEtag()
      if (current === null) {
        return null
      }
      const marker = current.data
      if (
        marker === null ||
        typeof marker !== 'object' ||
        Array.isArray(marker) ||
        marker instanceof Blob ||
        (marker as { scheme?: unknown }).scheme !== 'edv'
      ) {
        throw new ValidationError(
          `Cannot manage recipients: the resource "${resource.id}" does not ` +
            "hold a CollectionEncryption marker with the 'edv' scheme."
        )
      }
      return {
        marker: marker as unknown as CollectionEncryption,
        etag: current.etag
      }
    },
    async replace(marker, { ifMatch }) {
      await resource.put(markerAsJson(marker), { ifMatch })
    },
    async create(marker) {
      await resource.put(markerAsJson(marker), { ifNoneMatch: true })
    }
  }
}

/**
 * Casts a marker to the `JsonObject` a resource write takes. The marker types
 * are interfaces without index signatures, so they do not structurally satisfy
 * `JsonObject` -- but a marker is plain JSON by construction (it round-trips
 * through the Collection Description on the classic host), so this is sound.
 *
 * @param marker {CollectionEncryption}
 * @returns {JsonObject}
 */
function markerAsJson(marker: CollectionEncryption): JsonObject {
  return marker as unknown as JsonObject
}
