/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Builds `changes` feed entries for unit tests. Every entry shares one write
 * stamp, since the feed's order does not depend on it; checkpoints are
 * arbitrary opaque strings.
 */
import type { ChangeDocument } from '../../src/index.js'

export const FEED_UPDATED_AT = '2026-01-01T00:00:00.000Z'

/**
 * One feed entry. `kind` defaults to a JSON Resource; any other kind is the
 * Collection's own record (or one this client does not know), named by its
 * URL, with no `contentType` and no body. A live JSON Resource with no `data`
 * models the server's own read-fault shape.
 *
 * @param options {object}
 * @param options.id {string}
 * @param options.checkpoint {string}   the opaque checkpoint that resumes after it
 * @param [options.kind] {string}   defaults to `resource`
 * @param [options.contentType] {string}   defaults to `application/json` on a Resource
 * @param [options.deleted] {boolean}   a tombstone
 * @param [options.data] {unknown}
 * @returns {ChangeDocument}
 */
export function feedEntry({
  id,
  checkpoint,
  kind = 'resource',
  contentType = 'application/json',
  deleted = false,
  data
}: {
  id: string
  checkpoint: string
  kind?: string
  contentType?: string
  deleted?: boolean
  data?: unknown
}): ChangeDocument {
  return {
    kind,
    id,
    deleted,
    ...(kind === 'resource' && { contentType }),
    updatedAt: FEED_UPDATED_AT,
    updatedAtCounter: 0,
    originId: 'origin-a',
    checkpoint,
    ...(data !== undefined && { data })
  } as ChangeDocument
}

/**
 * A feed entry for one of the Collection's own records, named by URL.
 *
 * @param kind {string}   `collection-metadata`, `log`, or an unknown kind
 * @param checkpoint {string}
 * @returns {ChangeDocument}
 */
export function recordEntry(kind: string, checkpoint: string): ChangeDocument {
  return feedEntry({
    kind,
    id: `https://was.example/space/s/notes/${kind}`,
    checkpoint
  })
}
