/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Reads a Collection Description with a single GET. Shared by
 * `Collection.describe()` and the standalone-resource codec's marker discovery
 * so the request shape (path, capability, null-unwrap) lives in one place.
 * Also owns the masked-404 fail-closed policy: WAS returns 404 for both
 * not-found and unauthorized, so a `null` description is ambiguous and an
 * operation that must know the current state fails closed via
 * `unreadableDescriptionError` rather than guessing.
 */
import type { HttpResponse } from '@interop/http-client'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { dataOrNull } from './content.js'
import { collectionPath } from './paths.js'
import { ValidationError } from '../errors.js'
import type { WasError } from '../errors.js'
import type { CollectionDescription, IZcap } from '../types.js'

/**
 * Sends the Collection Description GET, returning the raw response -- or
 * `null` if the collection is missing or not visible to you (WAS returns 404
 * for both not-found and unauthorized). The one request shape shared by
 * {@link describeCollection} and `Collection.describeWithEtag` (which also
 * needs the response's `ETag` header).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param [options.capability] {IZcap}   capability attached to the request
 * @returns {Promise<HttpResponse | null>}
 */
export async function describeCollectionResponse(
  context: ClientContext,
  {
    spaceId,
    collectionId,
    capability
  }: { spaceId: string; collectionId: string; capability?: IZcap }
): Promise<HttpResponse | null> {
  return send(context, {
    path: collectionPath(spaceId, collectionId),
    method: 'GET',
    capability,
    read: true
  })
}

/**
 * Reads the Collection Description. Returns `null` if the collection is missing
 * or not visible to you (WAS returns 404 for both not-found and unauthorized).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param [options.capability] {IZcap}   capability attached to the request
 * @returns {Promise<CollectionDescription | null>}
 */
export async function describeCollection(
  context: ClientContext,
  options: { spaceId: string; collectionId: string; capability?: IZcap }
): Promise<CollectionDescription | null> {
  return dataOrNull<CollectionDescription>(
    await describeCollectionResponse(context, options)
  )
}

/**
 * Builds the fail-closed error for an operation that needs a description it
 * could not read. The one owner of the masked-404 policy statement ("WAS
 * returns 404 for both not-found and unauthorized, so a null description is
 * ambiguous -- fail closed"); callers supply the operation, its consequence,
 * and the recovery advice.
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
