/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The WAS binding of `@interop/vh-resource-log`'s store port, over either of
 * the two places a WAS server keeps a resource log. A log may be a WAS
 * Resource's entire body (the user key roster's `key-map/user-key.jsonl`), or
 * a Collection's governing history log at the `/meta/log` sub-resource (the
 * backend's `governed-history-logs` feature, from which the server derives
 * the Collection's served `encryption` member). Either way the log is stored
 * as `text/jsonl`, with the port's read-with-etag, compare-and-swap append,
 * and guarded genesis create mapped onto the target's conditional writes.
 *
 * A Resource-hosted log's collection may be plaintext or encrypted: a
 * conditional codec pins the write to the `ifMatch` this store passes rather
 * than to the ETag its own pre-read observed, so the append profile's
 * compare-and-swap holds either way. On an encrypted host the resource id
 * must be one the codec mints, since the EDV codec refuses to create a
 * document under a human-readable id. A Collection's history log is never
 * encrypted and runs no codec: the server reads its head itself.
 *
 * Both the append and the create ride the backend's `conditional-writes`
 * feature -- the profile requires it (without the precondition, concurrent
 * appends silently overwrite one another instead of failing into the caller's
 * rebase-and-retry loop). A lost race -- a stale `ifMatch`, or a guarded
 * create against a log that already exists -- is rethrown as the library's
 * `ResourceLogConflictError` with the transport's `PreconditionFailedError`
 * as `cause`, which is the port's one conflict signal and what the library's
 * rebase loop catches (by `name`, never `instanceof` -- the error crosses the
 * adapter-to-library package boundary).
 */
import {
  ResourceLogConflictError,
  parseResourceLog,
  serializeResourceLog,
  serializeResourceLogEntry,
  type ResourceLogStore
} from '@interop/vh-resource-log'
import type { Collection } from '../Collection.js'
import type { Resource } from '../Resource.js'
import { PreconditionFailedError, ValidationError } from '../errors.js'
import { blobText } from '../internal/blob.js'
import { ENCODER, LOG_CONTENT_TYPE, isBlob } from '../internal/content.js'

export { LOG_CONTENT_TYPE }

/**
 * The one shape the store drives, behind which the two hosts differ: a raw
 * read of the log's text body with its validator, and a whole-body
 * conditional write.
 */
interface LogTarget {
  read(): Promise<{ body: string; etag?: string } | null>
  put(
    body: string,
    precondition: { ifMatch?: string; ifNoneMatch?: true }
  ): Promise<void>
}

/**
 * The Resource host: `getWithEtag` (so the codec runs and a text body is
 * decoded as a Blob or a string) and `put` with the log content type.
 * `read` keeps the Blob / text body handling (a React Native Blob has no
 * `text()`; `blobText` falls back to `FileReader`).
 *
 * @param resource {Resource}
 * @returns {LogTarget}
 */
function resourceTarget(resource: Resource): LogTarget {
  return {
    async read() {
      const current = await resource.getWithEtag()
      if (current === null) {
        return null
      }
      const body = isBlob(current.data)
        ? await blobText(current.data)
        : typeof current.data === 'string'
          ? current.data
          : undefined
      if (body === undefined) {
        throw new ValidationError(
          `Cannot read resource log: the resource "${resource.id}" does not ` +
            'hold a text body (is it stored as JSON instead of JSON Lines?).'
        )
      }
      return { body, etag: current.etag }
    },
    async put(body, precondition) {
      await resource.put(ENCODER.encode(body), {
        contentType: LOG_CONTENT_TYPE,
        ...precondition
      })
    }
  }
}

/**
 * The Collection host: the governing history log at `/meta/log`, read and
 * written verbatim through the handle's own transport methods.
 *
 * @param collection {Collection}
 * @returns {LogTarget}
 */
function collectionTarget(collection: Collection): LogTarget {
  return {
    read: () => collection.getHistoryLog(),
    async put(body, precondition) {
      await collection.putHistoryLog(body, precondition)
    }
  }
}

/**
 * The WAS adapter implementing the library's `ResourceLogStore` port, over
 * one of two hosts: `resource`, a WAS Resource whose whole body is the log,
 * or `collection`, whose governing history log at `/meta/log` is the log.
 * `append` carries the prior entries' bytes forward verbatim from the most
 * recent read (an append never re-serializes history), and both `append` and
 * `create` translate the transport's 412 into the library's conflict error.
 *
 * @param options {object}
 * @param [options.resource] {Resource}       the Resource holding the log
 * @param [options.collection] {Collection}   the Collection whose history log
 *   is the log; exactly one of the two is given
 * @returns {ResourceLogStore}
 */
export function resourceLogStore(
  options:
    | { resource: Resource; collection?: undefined }
    | { collection: Collection; resource?: undefined }
): ResourceLogStore {
  const target =
    options.resource !== undefined
      ? resourceTarget(options.resource)
      : collectionTarget(options.collection)
  // The raw body observed by the most recent read; an append extends these
  // bytes verbatim instead of re-serializing the parsed entries. Safe to carry
  // even if stale: the append is pinned to the same read's ETag, so a
  // concurrent append fails the CAS instead.
  let lastReadBody: string | undefined
  return {
    async read() {
      const current = await target.read()
      if (current === null) {
        return null
      }
      const entries = parseResourceLog(current.body)
      lastReadBody = current.body
      return { entries, etag: current.etag }
    },
    async append(entry, { ifMatch }) {
      if (lastReadBody === undefined) {
        throw new ValidationError(
          'Cannot append to resource log: append must follow a read on the ' +
            'same store instance.'
        )
      }
      const separator = lastReadBody.endsWith('\n') ? '' : '\n'
      const extended =
        lastReadBody + separator + serializeResourceLogEntry(entry) + '\n'
      await putOrConflict({
        body: extended,
        precondition: { ifMatch },
        conflict:
          'Resource-log append lost its compare-and-swap: the validator ' +
          'is stale.'
      })
      lastReadBody = extended
    },
    async create(entry) {
      const serialized = serializeResourceLog([entry])
      await putOrConflict({
        body: serialized,
        precondition: { ifNoneMatch: true },
        conflict:
          'Resource-log create lost its guarded-create race: the log ' +
          'already exists.'
      })
      lastReadBody = serialized
    }
  }

  /**
   * Writes the log body under the given precondition, translating a 412 into
   * a {@link ResourceLogConflictError}. However the 412 was minted (problem
   * type or status fallback), and including the WasSyncConflictError subtype,
   * it is the port's CAS conflict, not an error: the library's rebase loop
   * re-reads, re-verifies, and retries on it.
   */
  async function putOrConflict({
    body,
    precondition,
    conflict
  }: {
    body: string
    precondition: { ifMatch?: string; ifNoneMatch?: true }
    conflict: string
  }): Promise<void> {
    try {
      await target.put(body, precondition)
    } catch (err) {
      if (err instanceof PreconditionFailedError) {
        throw new ResourceLogConflictError(conflict, { cause: err })
      }
      throw err
    }
  }
}
