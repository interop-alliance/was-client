/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The point-state projection write: the descriptor document a non-verifying
 * consumer reads, written from the verified head entry's `state` plus the
 * `history` dispatch hint, after a log append has succeeded and been
 * confirmed. The log is the source of truth and the projection follows it --
 * a consumer that needs trust verifies the log and acts on the projection
 * only where it equals the verified head's `state` (after removing
 * `history`); a mismatch is an integrity failure, not a race resolved in the
 * projection's favor. Because the log settles every race, the write is
 * deliberately unconditional: a stale projection left behind by a lost race
 * is repaired by the next writer's projection, and never trusted meanwhile.
 */
import type { ResourceLogEntry } from '@interop/storage-core'
import type { Resource } from '../Resource.js'
import type { JsonObject } from '../types.js'
import { ValidationError } from '../errors.js'

/**
 * Writes a log's point-state projection: the resource's content becomes the
 * head entry's `state` with the `history: { method, resource }` dispatch hint
 * added. Refuses a `state` that already carries a `history` member (the
 * profile forbids one inside a log entry, so its presence means the caller is
 * projecting something that was never a valid entry state).
 *
 * @param options {object}
 * @param options.resource {Resource}   the point-state document's resource
 * @param options.state {ResourceLogEntry['state']}   the VERIFIED head
 *   entry's state -- callers project only what chain verification returned
 * @param options.history {object}   the dispatch hint
 * @param options.history.method {string}   the log's format identifier (the
 *   genesis `parameters.method`, which the log itself must confirm)
 * @param options.history.resource {string}   the log resource's URL
 * @returns {Promise<void>}
 */
export async function writeLogProjection({
  resource,
  state,
  history
}: {
  resource: Resource
  state: ResourceLogEntry['state']
  history: { method: string; resource: string }
}): Promise<void> {
  if ('history' in state) {
    throw new ValidationError(
      'Cannot write log projection: the head state already carries a ' +
        '`history` member (a log entry state must not have one).'
    )
  }
  const projection = { ...state, history }
  await resource.put(projection as unknown as JsonObject, {})
}
