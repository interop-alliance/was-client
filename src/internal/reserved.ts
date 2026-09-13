/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Reserved path-segment registry and the client-side id-collision guard.
 * Rejecting reserved ids up front (with a clear `ValidationError`) is friendlier
 * than letting the server answer `409 Conflict`.
 *
 * The reserved sets themselves are single-sourced from `@interop/storage-core`
 * (the spec's Reserved Path Segment Registry). This module adds the
 * client-side `ValidationError`-throwing guard and the two membership
 * predicates the path grammar asks with.
 */
import {
  RESERVED_COLLECTION_IDS,
  RESERVED_RESOURCE_IDS
} from '@interop/storage-core'

import { ValidationError } from '../errors.js'

/**
 * Whether `id` is a reserved Collection-id path segment.
 *
 * @param id {string}
 * @returns {boolean}
 */
export function isReservedCollectionId(id: string): boolean {
  return RESERVED_COLLECTION_IDS.has(id)
}

/**
 * Whether `id` is a reserved Resource-id path segment.
 *
 * @param id {string}
 * @returns {boolean}
 */
export function isReservedResourceId(id: string): boolean {
  return RESERVED_RESOURCE_IDS.has(id)
}

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
  const isReserved =
    kind === 'collection' ? isReservedCollectionId : isReservedResourceId
  if (isReserved(id)) {
    throw new ValidationError(
      `Cannot use reserved path segment "${id}" as a ${kind} id.`
    )
  }
}
