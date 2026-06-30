/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Reserved path-segment registry and the client-side id-collision guard.
 * Rejecting reserved ids up front (with a clear `ValidationError`) is friendlier
 * than letting the server answer `409 Conflict`.
 */
import { ValidationError } from '../errors.js'

/**
 * Path segments reserved at the Collection level by the spec's Reserved Path
 * Segment Registry. A collection id that collides with one of these would shadow
 * the reserved route at that position (e.g. a collection named `export` would
 * shadow `/space/{id}/export`), so it is rejected before the request is sent.
 * Mirrors the reference server's `RESERVED_COLLECTION_IDS` (including its
 * non-spec `import` endpoint).
 */
export const RESERVED_COLLECTION_IDS: readonly string[] = [
  'backends',
  'collections',
  'export',
  'import',
  'linkset',
  'policy',
  'query',
  'quotas'
]

/**
 * Path segments reserved at the Resource level by the spec's Reserved Path
 * Segment Registry. Mirrors the reference server's `RESERVED_RESOURCE_IDS`. Note
 * that the reserved set differs by kind: e.g. `backend` is reserved for
 * resources while `backends`/`collections`/`export` are reserved for
 * collections.
 */
export const RESERVED_RESOURCE_IDS: readonly string[] = [
  'backend',
  'linkset',
  'policy',
  'query',
  'quota'
]

/**
 * Throws a `ValidationError` if the given id collides with a reserved path
 * segment for its kind.
 *
 * @param id {string}     the proposed collection or resource id
 * @param kind {string}   'collection' or 'resource', selects the reserved set
 *                        and is used in the message
 * @returns {void}
 */
export function assertNotReserved(
  id: string,
  kind: 'collection' | 'resource'
): void {
  const reserved =
    kind === 'collection' ? RESERVED_COLLECTION_IDS : RESERVED_RESOURCE_IDS
  if (reserved.includes(id)) {
    throw new ValidationError(
      `Cannot use reserved path segment "${id}" as a ${kind} id.`
    )
  }
}
