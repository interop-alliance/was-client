/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The descriptor-store seam: where a `CollectionEncryption` descriptor lives
 * and how it is compare-and-swapped. The recipient primitives (`initRecipients`
 * / `addRecipient` / `removeRecipient`) mutate a descriptor only through this
 * port, so the same key-epoch machinery manages a Collection's own `encryption`
 * descriptor (the classic host) or a descriptor hosted as a plain JSON Resource
 * (e.g. a per-user-key roster in a private collection).
 *
 * Two adapters:
 *
 * - {@link collectionDescriptorStore} -- the Collection Description's `encryption`
 *   member, read with `describeWithEtag` and written back with
 *   `replaceDescription` + `If-Match`. The server enforces the descriptor
 *   invariants (append-only epochs, monotone `currentEpoch`, non-decreasing
 *   `version`) on this path.
 * - {@link resourceDescriptorStore} -- a descriptor stored verbatim as a JSON Resource.
 *   The server treats the resource as opaque content and enforces NO descriptor
 *   invariants there; rollback/tamper detection rests on client-side epoch
 *   pinning plus whatever governance the hosting profile adds -- for a
 *   log-governed descriptor (the Resource Log Profile), the verified entry
 *   proofs and the chain-head pin. Both the compare-and-swap and the
 *   create-if-absent guard ride the backend's `conditional-writes` feature.
 *   The hosting collection must be plaintext: on an encrypted collection the
 *   EDV codec computes the write preconditions itself and the store's
 *   `ifMatch` would not be honored.
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
 * Where a `CollectionEncryption` descriptor lives: a read-with-validator plus a
 * compare-and-swap write, the two operations the recipient primitives' CAS loop
 * needs. Implementations host the descriptor anywhere a versioned JSON value
 * can live; the two shipped adapters are {@link collectionDescriptorStore} and
 * {@link resourceDescriptorStore}.
 */
export interface EncryptionDescriptorStore {
  /**
   * Reads the current descriptor together with the opaque `etag` validator the
   * next {@link replace} must be compare-and-swapped against. Resolves `null`
   * when no descriptor exists yet AND this store can create one (the resource
   * adapter before the first `initRecipients`); a store whose host must
   * already exist (the description adapter) throws instead of resolving
   * `null`. Throws when the hosted value is not an `edv`-scheme descriptor.
   *
   * @returns {Promise<{ descriptor: CollectionEncryption; etag?: string } | null>}
   */
  read(): Promise<{ descriptor: CollectionEncryption; etag?: string } | null>

  /**
   * Replaces the descriptor, compare-and-swapped against `ifMatch` (the
   * validator from {@link read}); a stale validator throws
   * `PreconditionFailedError` (412). Must follow a {@link read} on the same
   * store instance -- an adapter may forward sibling state observed by its most
   * recent read (the description adapter forwards the description's `name` /
   * `backend`).
   *
   * @param descriptor {CollectionEncryption}
   * @param options {object}
   * @param [options.ifMatch] {string}   the validator from the prior read;
   *   absent against a host that does not version its writes
   * @returns {Promise<void>}
   */
  replace(
    descriptor: CollectionEncryption,
    options: { ifMatch?: string }
  ): Promise<void>

  /**
   * Creates the FIRST descriptor where {@link read} resolved `null`, guarded
   * create-if-absent (`If-None-Match: *`); throws `PreconditionFailedError`
   * (412) when a concurrent writer created one first. Absent on stores whose
   * host always exists (the description adapter).
   *
   * @param descriptor {CollectionEncryption}
   * @returns {Promise<void>}
   */
  create?(descriptor: CollectionEncryption): Promise<void>
}

/**
 * The Collection Description adapter: the descriptor is the Description's
 * `encryption` member. Read fails closed when the Description is unreadable
 * (WAS masks unauthorized reads as 404) or the collection is not declared
 * encrypted with the `edv` scheme; the CAS write forwards the description's
 * sibling fields (`name` / `backend`) observed by the most recent read, so
 * the replace-semantics PUT does not drop them. No `create`: a Collection
 * Description always exists, so a first descriptor is declared via
 * `collection.configure({ encryption })`, never through this store.
 *
 * @param options {object}
 * @param options.collection {Collection}
 * @returns {EncryptionDescriptorStore}
 */
export function collectionDescriptorStore({
  collection
}: {
  collection: Collection
}): EncryptionDescriptorStore {
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
      const descriptor = current.description.encryption
      if (!descriptor || descriptor.scheme !== 'edv') {
        throw new ValidationError(
          'Cannot manage recipients: this collection is not declared ' +
            "encrypted with the 'edv' scheme."
        )
      }
      described = current.description
      return { descriptor, etag: current.etag }
    },
    async replace(descriptor, { ifMatch }) {
      await collection.replaceDescription(
        {
          name: described?.name,
          backend: described?.backend,
          encryption: descriptor
        },
        { ifMatch }
      )
    }
  }
}

/**
 * The plain-JSON-Resource adapter: the descriptor is the resource's entire
 * content, stored verbatim. Read resolves `null` when the resource is absent
 * (the pre-`initRecipients` state -- `create` then writes the first descriptor
 * with `If-None-Match: *`), and throws when the resource holds something other
 * than an `edv`-scheme descriptor object.
 *
 * The server enforces no descriptor invariants on a resource (unlike a
 * Collection Description): rollback/tamper detection rests on client-side
 * epoch pinning plus whatever governance the hosting profile adds (for a
 * log-governed descriptor, the Resource Log Profile's verified entry proofs
 * and chain-head pin), and the CAS/create guards ride the backend's
 * `conditional-writes` feature. Host the resource in a plaintext
 * collection -- on an encrypted collection the EDV codec computes the write
 * preconditions itself, so this store's `ifMatch` would not be honored.
 *
 * @param options {object}
 * @param options.resource {Resource}
 * @returns {EncryptionDescriptorStore}
 */
export function resourceDescriptorStore({
  resource
}: {
  resource: Resource
}): EncryptionDescriptorStore {
  return {
    async read() {
      const current = await resource.getWithEtag()
      if (current === null) {
        return null
      }
      const descriptor = current.data
      if (
        descriptor === null ||
        typeof descriptor !== 'object' ||
        Array.isArray(descriptor) ||
        descriptor instanceof Blob ||
        (descriptor as { scheme?: unknown }).scheme !== 'edv'
      ) {
        throw new ValidationError(
          `Cannot manage recipients: the resource "${resource.id}" does not ` +
            "hold a CollectionEncryption descriptor with the 'edv' scheme."
        )
      }
      return {
        descriptor: descriptor as unknown as CollectionEncryption,
        etag: current.etag
      }
    },
    async replace(descriptor, { ifMatch }) {
      await resource.put(descriptorAsJson(descriptor), { ifMatch })
    },
    async create(descriptor) {
      await resource.put(descriptorAsJson(descriptor), { ifNoneMatch: true })
    }
  }
}

/**
 * Casts a descriptor to the `JsonObject` a resource write takes. The descriptor
 * types are interfaces without index signatures, so they do not structurally
 * satisfy `JsonObject` -- but a descriptor is plain JSON by construction (it
 * round-trips through the Collection Description on the classic host), so this
 * is sound.
 *
 * @param descriptor {CollectionEncryption}
 * @returns {JsonObject}
 */
function descriptorAsJson(descriptor: CollectionEncryption): JsonObject {
  return descriptor as unknown as JsonObject
}
