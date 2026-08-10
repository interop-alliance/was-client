/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The log-store seam: where a resource log lives and how it is extended --
 * read-with-etag of the full log, compare-and-swap append conditioned on that
 * etag, and the guarded create of a genesis entry. The seam is transport only,
 * the log-side sibling of the descriptor-store seam (`edv/descriptorStore.ts`):
 * chain verification (SCID, entry hashes, proofs, authorization, the chain-head
 * pin) lives in the consuming verifier, which reads through this seam, verifies
 * the parsed entries, builds the next entry against the verified head, and
 * appends through it.
 *
 * Both the append and the create ride the backend's `conditional-writes`
 * feature -- the profile requires it (without the precondition, concurrent
 * appends silently overwrite one another instead of failing into the caller's
 * rebase-and-retry loop). `confirmAppend` is the profile's "acknowledgement is
 * a promise" rule: after an acked append, read the log back and check the
 * entry is actually in the served history before treating the append -- or any
 * ceremony step gated on it -- as durable.
 */
import { canonicalize } from 'json-canonicalize'
import type { ResourceLogEntry } from '@interop/storage-core'
import type { Resource } from '../Resource.js'
import { LogNotConfirmedError, ValidationError } from '../errors.js'
import { ENCODER } from '../internal/content.js'
import {
  parseResourceLog,
  serializeResourceLog,
  serializeResourceLogEntry
} from './jsonl.js'

/**
 * The content type a resource log is stored under (JSON Lines, not JSON --
 * load-bearing: a JSON content type would have the request layer parse and
 * re-serialize the body, losing the line framing).
 */
export const LOG_CONTENT_TYPE = 'text/jsonl'

/**
 * Where a resource log lives: a read-with-validator, a compare-and-swap
 * append, and a guarded genesis create. Implementations host the log anywhere
 * a versioned text resource can live; the shipped adapter is
 * {@link resourceLogStore}.
 */
export interface ResourceLogStore {
  /**
   * Reads the full log together with the opaque `etag` validator the next
   * {@link append} must be compare-and-swapped against. Resolves `null` when
   * the log resource does not exist yet (the pre-genesis state -- see
   * {@link create}); throws on a body that does not parse as strict JSON
   * Lines. `etag` is absent against a backend that does not version resources
   * -- a caller MUST NOT append without one (the profile forbids falling back
   * to an unconditional write).
   *
   * @returns {Promise<{ entries: ResourceLogEntry[]; etag?: string } | null>}
   */
  read(): Promise<{ entries: ResourceLogEntry[]; etag?: string } | null>

  /**
   * Appends one entry to the log read by the most recent {@link read} on this
   * store instance, compare-and-swapped against `ifMatch` (the validator that
   * read returned); a stale validator throws `PreconditionFailedError` (412),
   * and the caller re-reads, re-verifies, rebases the entry on the new head,
   * and retries. The prior entries' bytes are carried forward verbatim from
   * the read, with the new entry's line appended -- an append never
   * re-serializes history.
   *
   * @param entry {ResourceLogEntry}   the entry extending the log
   * @param options {object}
   * @param options.ifMatch {string}   the validator from the prior read
   * @returns {Promise<void>}
   */
  append(entry: ResourceLogEntry, options: { ifMatch: string }): Promise<void>

  /**
   * Creates the log with its genesis entry where {@link read} resolved `null`,
   * guarded create-if-absent (`If-None-Match: *`); throws
   * `PreconditionFailedError` (412) when a concurrent writer created the log
   * first.
   *
   * @param entry {ResourceLogEntry}   the genesis entry
   * @returns {Promise<void>}
   */
  create(entry: ResourceLogEntry): Promise<void>
}

/**
 * The WAS Resource adapter: the log is the resource's entire body, stored as
 * `text/jsonl`. Host the resource in a plaintext collection -- on an encrypted
 * collection the EDV codec computes the write preconditions itself, so this
 * store's `ifMatch` / create guard would not be honored.
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
      const body =
        current.data instanceof Blob
          ? await current.data.text()
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
      await resource.put(ENCODER.encode(extended), {
        contentType: LOG_CONTENT_TYPE,
        ifMatch
      })
      lastReadBody = extended
    },
    async create(entry) {
      await resource.put(ENCODER.encode(serializeResourceLog([entry])), {
        contentType: LOG_CONTENT_TYPE,
        ifNoneMatch: true
      })
      lastReadBody = serializeResourceLog([entry])
    }
  }
}

/**
 * The profile's "acknowledgement is a promise" rule, mechanically: after an
 * acked {@link ResourceLogStore.append} (or `create`), reads the log back and
 * checks the served history actually contains the written entry at its
 * ordinal, throwing {@link LogNotConfirmedError} when it does not (the log is
 * missing, shorter than the entry's ordinal, or holds a different entry
 * there). Returns the read-back log so the caller can run full chain
 * verification over exactly what was confirmed -- containment here is a
 * byte-level check (JCS equality), not a verification.
 *
 * @param options {object}
 * @param options.store {ResourceLogStore}
 * @param options.entry {ResourceLogEntry}   the entry the append wrote
 * @returns {Promise<{ entries: ResourceLogEntry[]; etag?: string }>}   the
 *   read-back log containing the entry
 */
export async function confirmAppend({
  store,
  entry
}: {
  store: ResourceLogStore
  entry: ResourceLogEntry
}): Promise<{ entries: ResourceLogEntry[]; etag?: string }> {
  const ordinal = Number.parseInt(entry.versionId, 10)
  if (!Number.isInteger(ordinal) || ordinal < 1) {
    throw new ValidationError(
      `Cannot confirm append: the entry's versionId "${entry.versionId}" ` +
        'does not start with a 1-based ordinal.'
    )
  }
  const current = await store.read()
  if (current === null) {
    throw new LogNotConfirmedError(
      'Resource-log append not confirmed: the log resource is missing on ' +
        'read-back.'
    )
  }
  const served = current.entries[ordinal - 1]
  if (served === undefined || canonicalize(served) !== canonicalize(entry)) {
    throw new LogNotConfirmedError(
      `Resource-log append not confirmed: the served log does not contain ` +
        `the appended entry at ordinal ${ordinal}.`
    )
  }
  return current
}
