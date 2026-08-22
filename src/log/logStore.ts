/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The WAS binding of `@interop/vh-resource-log`'s store port: the log is a
 * WAS Resource's entire body, stored as `text/jsonl`, with the port's
 * read-with-etag, compare-and-swap append, and guarded genesis create mapped
 * onto the resource's conditional writes. The hosting collection may be
 * plaintext or encrypted: a conditional codec pins the write to the `ifMatch`
 * this store passes rather than to the ETag its own pre-read observed, so the
 * append profile's compare-and-swap holds either way. On an encrypted host
 * the resource id must be one the codec mints, since the EDV codec refuses to
 * create a document under a human-readable id.
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
import type { Resource } from '../Resource.js'
import { PreconditionFailedError, ValidationError } from '../errors.js'
import { blobText } from '../internal/blob.js'
import { ENCODER, isBlob } from '../internal/content.js'

/**
 * The content type a resource log is stored under (JSON Lines, not JSON --
 * load-bearing: a JSON content type would have the request layer parse and
 * re-serialize the body, losing the line framing).
 */
export const LOG_CONTENT_TYPE = 'text/jsonl'

/**
 * The WAS Resource adapter implementing the library's `ResourceLogStore`
 * port. `read` keeps the Blob / text body handling (a React Native Blob has
 * no `text()`; `blobText` falls back to `FileReader`), `append` carries the
 * prior entries' bytes forward verbatim from the most recent read (an append
 * never re-serializes history), and both `append` and `create` translate the
 * transport's 412 into the library's conflict error.
 *
 * @param options {object}
 * @param options.resource {Resource}
 * @returns {ResourceLogStore}
 */
export function resourceLogStore({
  resource
}: {
  resource: Resource
}): ResourceLogStore {
  // The raw body observed by the most recent read; an append extends these
  // bytes verbatim instead of re-serializing the parsed entries. Safe to carry
  // even if stale: the append is pinned to the same read's ETag, so a
  // concurrent append fails the CAS instead.
  let lastReadBody: string | undefined
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
      const entries = parseResourceLog(body)
      lastReadBody = body
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
      try {
        await resource.put(ENCODER.encode(extended), {
          contentType: LOG_CONTENT_TYPE,
          ifMatch
        })
      } catch (err) {
        // However the 412 was minted (problem type or status fallback), and
        // including the WasSyncConflictError subtype, it is the port's CAS
        // conflict, not an error: the library's rebase loop re-reads,
        // re-verifies, and retries on it.
        if (err instanceof PreconditionFailedError) {
          throw new ResourceLogConflictError(
            'Resource-log append lost its compare-and-swap: the validator ' +
              'is stale.',
            { cause: err }
          )
        }
        throw err
      }
      lastReadBody = extended
    },
    async create(entry) {
      try {
        await resource.put(ENCODER.encode(serializeResourceLog([entry])), {
          contentType: LOG_CONTENT_TYPE,
          ifNoneMatch: true
        })
      } catch (err) {
        if (err instanceof PreconditionFailedError) {
          throw new ResourceLogConflictError(
            'Resource-log create lost its guarded-create race: the log ' +
              'already exists.',
            { cause: err }
          )
        }
        throw err
      }
      lastReadBody = serializeResourceLog([entry])
    }
  }
}
