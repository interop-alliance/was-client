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
 * Path segments reserved by the spec's Reserved Path Segment Registry. A
 * collection or resource id that collides with one of these is rejected before
 * the request is sent.
 */
export const RESERVED_SEGMENTS: readonly string[] = [
  'policy',
  'backends',
  'backend',
  'collections',
  'export',
  'linkset',
  'query',
  'quota',
  'quotas',
  'meta'
]

/**
 * Throws a `ValidationError` if the given id collides with a reserved path
 * segment.
 *
 * @param id {string}     the proposed collection or resource id
 * @param kind {string}   'collection' or 'resource', used in the message
 * @returns {void}
 */
export function assertNotReserved(
  id: string,
  kind: 'collection' | 'resource'
): void {
  if (RESERVED_SEGMENTS.includes(id)) {
    throw new ValidationError(
      `Cannot use reserved path segment "${id}" as a ${kind} id.`
    )
  }
}
