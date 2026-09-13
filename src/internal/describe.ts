/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Reads a Collection Metadata object with a single GET of the Collection's
 * `meta` sub-resource, in the wire form the server serves it: `custom` is
 * whatever is stored there (an opaque envelope on an encrypted Collection),
 * left undecoded, because the codec that would decode it is itself resolved
 * from this object's `encryption` member. Shared by `Collection`'s read and
 * write paths and by the codec resolver's descriptor discovery, so the request
 * shape (path, capability, null-unwrap, validator) lives in one place.
 *
 * Also owns the masked-404 fail-closed policy: WAS returns 404 for both
 * not-found and unauthorized, so a `null` read is ambiguous and an operation
 * that must know the current state fails closed via
 * `unreadableDescriptionError` rather than guessing. `collectionWritableFields`
 * lives here too: it is the one inclusion rule for the writable configuration
 * members a caller supplies, beside `carriedForward`, the rule for the stored
 * members a full-replacement write re-sends unchanged.
 */
import type { ClientContext } from './request.js'
import { readDataWithEtag } from './request.js'
import { collectionMeta } from './paths.js'
import { ValidationError } from '../errors.js'
import type { WasError } from '../errors.js'
import type {
  CollectionEncryption,
  CollectionMetadata,
  CollectionWritableFields,
  IZcap
} from '../types.js'

/**
 * A Collection Metadata object exactly as the server served it. Typed as an
 * open record rather than as `CollectionMetadata`, because `custom` here is the
 * stored value (an opaque encryption envelope on an encrypted Collection) and
 * because a write forwards members this client does not model verbatim rather
 * than dropping them (see {@link carriedForward}).
 */
export type StoredCollectionMetadata = Record<string, unknown>

/**
 * Reads a stored Collection Metadata object as the `CollectionMetadata` wire
 * type. The stored form is typed as an open record -- `custom` is the stored
 * value and a write forwards members this client does not model -- while the
 * server guarantees the object's shape, so the assertion lives here once
 * instead of at each reader.
 *
 * @param stored {StoredCollectionMetadata}
 * @returns {CollectionMetadata}
 */
export function asCollectionMetadata(
  stored: StoredCollectionMetadata
): CollectionMetadata {
  return stored as unknown as CollectionMetadata
}

/**
 * Whether a served encryption descriptor is the server-derived projection of
 * a Collection governed by its history log (it carries the `history` pointer)
 * rather than a client-written descriptor. The one place this distinction is
 * drawn, shared by provisioning and the log-governed descriptor store.
 *
 * @param descriptor {CollectionEncryption}
 * @returns {boolean}
 */
export function isGovernedDescriptor(
  descriptor: CollectionEncryption
): descriptor is CollectionEncryption & {
  history: { method: string; resource: string }
} {
  return descriptor.history !== undefined
}

/**
 * Picks the writable Collection configuration members that are set. The one
 * inclusion rule (`!== undefined`) behind every Collection Metadata write body
 * -- the `configure` / `replaceDescription` request bodies and their echoed
 * returns, and `Space.createCollection`'s create body -- so the paths cannot
 * drift and a new writable member is added in one place.
 *
 * @param fields {CollectionWritableFields}
 * @returns {CollectionWritableFields}
 */
export function collectionWritableFields(
  fields: CollectionWritableFields
): CollectionWritableFields {
  return {
    ...(fields.name !== undefined && { name: fields.name }),
    ...(fields.backend !== undefined && { backend: fields.backend }),
    ...(fields.encryption !== undefined && { encryption: fields.encryption }),
    ...(fields.generator !== undefined && { generator: fields.generator }),
    ...(fields.generatorOrigin !== undefined && {
      generatorOrigin: fields.generatorOrigin
    })
  }
}

/**
 * The members of a Collection Metadata object the server owns: it ignores them
 * in a request body and re-derives them on every write, so a write never
 * echoes them back. `id` is stated by the write path itself, `type` is the
 * server's classification, and the rest are server-observed (the spec's
 * "server-managed members are read-only" rule).
 */
const SERVER_MANAGED_MEMBERS: readonly string[] = [
  'id',
  'type',
  // Not a stored member at all: the client-side projection of the validator
  // that `describe()` returns beside the object, which must not travel back.
  'etag',
  'url',
  'linkset',
  'createdAt',
  'updatedAt',
  'createdBy'
]

/**
 * The Collection's configuration members: what a configuration write
 * (`configure`, `replaceDescription`) states in full and an annotation write
 * carries forward.
 */
export const CONFIGURATION_MEMBERS: readonly string[] = [
  'name',
  'backend',
  'encryption',
  'generator',
  'generatorOrigin'
]

/**
 * The Collection's annotation members: the user-writable `custom` and the key
 * epoch its envelope was sealed under. What an annotation write (`setMeta` and
 * its sugar) states and a configuration write carries forward.
 */
export const ANNOTATION_MEMBERS: readonly string[] = ['custom', 'epoch']

/**
 * Reads a stored `encryption` descriptor at its wire type. The one place the
 * open stored record is narrowed to `CollectionEncryption`, shared by the
 * compose paths and the codec resolver so the assertion is not repeated.
 *
 * @param stored {StoredCollectionMetadata}
 * @returns {CollectionEncryption | undefined}
 */
export function storedEncryption(
  stored: StoredCollectionMetadata
): CollectionEncryption | undefined {
  return stored.encryption as CollectionEncryption | undefined
}

/**
 * Picks the stored members a full-replacement write carries forward: every
 * member except the ones the server manages and the ones this write states
 * itself. A denylist rather than an allowlist, so a member this client does
 * not model -- `plaintext`, or one a newer server serves -- survives a write
 * it is not about instead of being silently cleared.
 *
 * A governed `encryption` descriptor is deliberately dropped: on a
 * log-governed Collection the served descriptor is the server's projection of
 * the history log's head, and a write that carries it is refused
 * (`encryption-history-log-governed`). Omitting the member leaves the derived
 * descriptor in place.
 *
 * @param stored {StoredCollectionMetadata}
 * @param options {object}
 * @param options.replacing {readonly string[]}   the members this write states
 *   itself (`CONFIGURATION_MEMBERS` on a configuration write,
 *   `ANNOTATION_MEMBERS` on an annotation write)
 * @returns {StoredCollectionMetadata}
 */
export function carriedForward(
  stored: StoredCollectionMetadata,
  { replacing }: { replacing: readonly string[] }
): StoredCollectionMetadata {
  const carried: StoredCollectionMetadata = {}
  for (const [member, value] of Object.entries(stored)) {
    if (value === undefined) {
      continue
    }
    if (SERVER_MANAGED_MEMBERS.includes(member) || replacing.includes(member)) {
      continue
    }
    carried[member] = value
  }
  const encryption = storedEncryption(stored)
  if (encryption !== undefined && isGovernedDescriptor(encryption)) {
    delete carried.encryption
  }
  return carried
}

/**
 * Reads the Collection Metadata object with its `metaVersion` validator, in the
 * stored wire form. Returns `null` if the collection is missing or not visible
 * to you (WAS returns 404 for both not-found and unauthorized); `etag` is
 * absent against a backend that does not version the object.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param [options.capability] {IZcap}   capability attached to the request
 * @returns {Promise<{ metadata: StoredCollectionMetadata; etag?: string } | null>}
 */
export async function readCollectionMetadata(
  context: ClientContext,
  options: { spaceId: string; collectionId: string; capability?: IZcap }
): Promise<{ metadata: StoredCollectionMetadata; etag?: string } | null> {
  const read = await readDataWithEtag<StoredCollectionMetadata>(context, {
    path: collectionMeta(options.spaceId, options.collectionId),
    capability: options.capability
  })
  if (read === null) {
    return null
  }
  return {
    metadata: read.data,
    ...(read.etag !== undefined && { etag: read.etag })
  }
}

/**
 * Builds the fail-closed error for an operation that needs a Collection
 * Metadata object it could not read. The one owner of the masked-404 policy
 * statement ("WAS returns 404 for both not-found and unauthorized, so a null
 * read is ambiguous -- fail closed"); callers supply the operation, its
 * consequence, and the recovery advice.
 *
 * @param options {object}
 * @param options.operation {string}      what was refused, continuing "Cannot ..."
 * @param [options.consequence] {string}   what proceeding could silently do,
 *   continuing "..., so "
 * @param [options.advice] {string}        recovery guidance, appended verbatim
 * @param [options.ErrorClass] {Function}  the `WasError` subclass to build
 *   (defaults to `ValidationError`; the codec resolver passes
 *   `EncryptionError` so fail-closed encryption handling still catches it)
 * @returns {WasError}
 */
export function unreadableDescriptionError({
  operation,
  consequence,
  advice,
  ErrorClass = ValidationError
}: {
  operation: string
  consequence?: string
  advice?: string
  ErrorClass?: new (message: string) => WasError
}): WasError {
  return new ErrorClass(
    `Cannot ${operation}: the current description is not readable with this ` +
      'capability (WAS returns 404 for both not-found and unauthorized)' +
      (consequence !== undefined ? `, so ${consequence}` : '') +
      '.' +
      (advice !== undefined ? ` ${advice}` : '')
  )
}
