/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Reserved path-segment registry and the client-side id-collision guard.
 * Rejecting reserved ids up front (with a clear `ValidationError`) is friendlier
 * than letting the server answer `409 Conflict`.
 *
 * The reserved sets themselves are single-sourced from `@interop/storage-core`
 * (the spec's Reserved Path Segment Registry) and re-exported here. This module
 * only adds the client-side `ValidationError`-throwing guard.
 */
import {
  RESERVED_COLLECTION_IDS,
  RESERVED_RESOURCE_IDS
} from '@interop/storage-core'

import { ValidationError } from '../errors.js'

/**
 * Throws a `ValidationError` if the given id collides with a reserved path
 * segment for its kind.
 *
 * @param options {object}
 * @param options.id {string}     the proposed collection or resource id
 * @param options.kind {string}   'collection' or 'resource', selects the
 *   reserved set and is used in the message
 * @returns {void}
 */
export function assertNotReserved({
  id,
  kind
}: {
  id: string
  kind: 'collection' | 'resource'
}): void {
  const reserved =
    kind === 'collection' ? RESERVED_COLLECTION_IDS : RESERVED_RESOURCE_IDS
  if (reserved.has(id)) {
    throw new ValidationError(
      `Cannot use reserved path segment "${id}" as a ${kind} id.`
    )
  }
}
