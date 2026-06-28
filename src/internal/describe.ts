/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Reads a Collection Description with a single GET. Shared by
 * `Collection.describe()` and the standalone-resource codec's marker discovery
 * so the request shape (path, capability, null-unwrap) lives in one place.
 */
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { collectionPath } from './paths.js'
import type { CollectionDescription, IZcap } from '../types.js'

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
  {
    spaceId,
    collectionId,
    capability
  }: { spaceId: string; collectionId: string; capability?: IZcap }
): Promise<CollectionDescription | null> {
  const response = await send(context, {
    path: collectionPath(spaceId, collectionId),
    method: 'GET',
    capability,
    read: true
  })
  return response === null ? null : (response.data as CollectionDescription)
}
