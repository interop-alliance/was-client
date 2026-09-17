/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Helpers for conditional writes (a baseline WAS server requirement):
 * assembling a write's request headers from an optional content-type plus the
 * `If-Match` / `If-None-Match: *` preconditions, reading the `ETag` a write
 * response returns, checking a caller's precondition against the document a
 * conditional codec's write path pre-read, and refusing a write whose pin the
 * read it is based on never supplied.
 */
import type { EncodedWrite, ResponseLike } from '../codec.js'
import {
  NotSupportedError,
  PreconditionFailedError,
  ValidationError
} from '../errors.js'

/**
 * The request header the server reads a content write's key-epoch id from,
 * stamping it onto the Resource's metadata (an absent header clears any prior
 * stamp). HTTP header names are case-insensitive; the wire form is `Key-Epoch`.
 */
export const KEY_EPOCH_HEADER = 'Key-Epoch'

/**
 * A conditional-write precondition: `ifMatch` is the quoted ETag an
 * update-if-unchanged write must match; `ifNoneMatch` requests a create-if-absent
 * (`If-None-Match: *`). At most one may be set; {@link assertSinglePrecondition}
 * rejects both.
 */
export interface WritePrecondition {
  ifMatch?: string
  ifNoneMatch?: boolean
}

/**
 * Extracts the conditional-write precondition a codec attached to its encoded
 * write (`EncodedWrite.ifMatch` / `ifNoneMatch`). The one mapping shared by
 * the two write entry points (`Collection.add` and `upsertResource`), so they
 * cannot diverge.
 *
 * @param encoded {EncodedWrite}
 * @returns {WritePrecondition}
 */
export function encodedPrecondition(encoded: EncodedWrite): WritePrecondition {
  return { ifMatch: encoded.ifMatch, ifNoneMatch: encoded.ifNoneMatch }
}

/**
 * The caller's precondition, or `undefined` when it names neither member. A
 * handle's `put` builds its precondition object from optional arguments
 * unconditionally, so an empty one means "no baseline named", not "pin to
 * nothing": a conditional codec must then fall back to the pin its own
 * pre-read supplies, or a racing update would go out with no `If-Match` at
 * all.
 *
 * @param [precondition] {WritePrecondition}
 * @returns {WritePrecondition | undefined}
 */
export function namedPrecondition(
  precondition?: WritePrecondition
): WritePrecondition | undefined {
  return precondition !== undefined &&
    (precondition.ifMatch !== undefined || precondition.ifNoneMatch)
    ? precondition
    : undefined
}

/**
 * Throws `ValidationError` when a precondition names both `ifMatch` and
 * `ifNoneMatch`. `If-Match` needs a current representation and
 * `If-None-Match: *` needs none, so no server state satisfies the pair. Every
 * write route checks this before acting on either member, so the caller bug
 * surfaces as itself rather than as a create that dropped `ifMatch` or as a
 * 412 that looks like a lost race.
 *
 * @param [precondition] {WritePrecondition}
 * @returns {void}
 */
export function assertSinglePrecondition(
  precondition?: WritePrecondition
): void {
  if (precondition?.ifMatch !== undefined && precondition.ifNoneMatch) {
    throw new ValidationError(
      'A write cannot name both `ifMatch` and `ifNoneMatch`: an update pinned ' +
        'to a version and a create-if-absent can never both hold. Pass ' +
        '`ifMatch` to update or `ifNoneMatch: true` to create.'
    )
  }
}

/**
 * Builds the headers for a write request: the content-type (when present) and
 * the conditional-write precondition headers (`If-Match` / `If-None-Match: *`).
 * Returns `undefined` when no header is needed, matching the request layer's
 * optional `headers`. Throws `ValidationError` when the precondition names both
 * `ifMatch` and `ifNoneMatch`, a pair no server state can satisfy.
 *
 * @param options {object}
 * @param [options.contentType] {string}          the body content-type, if any
 * @param [options.precondition] {WritePrecondition}   the conditional-write
 *   precondition
 * @param [options.epoch] {string}   the key-epoch id an encrypting codec
 *   encrypted this write under; emitted as the `Key-Epoch` header so the
 *   server stamps the Resource's epoch. Omitted when absent (which clears any
 *   prior stamp on the server).
 * @returns {Record<string, string> | undefined}
 */
export function writeHeaders({
  contentType,
  precondition = {},
  epoch
}: {
  contentType?: string
  precondition?: WritePrecondition
  epoch?: string
}): Record<string, string> | undefined {
  assertSinglePrecondition(precondition)
  const headers: Record<string, string> = {}
  if (contentType) {
    headers['content-type'] = contentType
  }
  if (precondition.ifMatch !== undefined) {
    headers['if-match'] = precondition.ifMatch
  }
  if (precondition.ifNoneMatch) {
    headers['if-none-match'] = '*'
  }
  if (epoch !== undefined) {
    // This record keys every header in lower case; the name is case-insensitive.
    headers[KEY_EPOCH_HEADER.toLowerCase()] = epoch
  }
  return Object.keys(headers).length > 0 ? headers : undefined
}

/**
 * The refusal for a guarded write whose pin the read it is based on never
 * supplied: the read returned no `ETag` validator, so the write would go out
 * with no `If-Match` at all. Every such gate builds its error here, so the
 * messages do not drift apart.
 *
 * A WAS server versions every resource, so a missing validator is a transport
 * or deployment problem, not a server declining to version. Most often it is a
 * browser client whose CORS configuration does not expose `ETag` to script.
 *
 * @param options {object}
 * @param options.operation {string}   what was refused, as the message's
 *   opening clause (e.g. `Cannot append to the resource log`)
 * @returns {NotSupportedError}
 */
export function unenforcedPreconditionError({
  operation
}: {
  operation: string
}): NotSupportedError {
  return new NotSupportedError(
    `${operation}: the read it is pinned to returned no ETag validator, so ` +
      'the write would go out unconditionally, and a concurrent change could ' +
      'be silently overwritten instead of failing with a 412. A WAS server ' +
      'serves an ETag on every resource read; check that the response is not ' +
      'losing the header on the way (a browser client needs `ETag` in the ' +
      "server's `Access-Control-Expose-Headers`)."
  )
}

/**
 * Reads the strong `ETag` validator a write/read response returned, or
 * `undefined` when none reached the client (a WAS server serves one on every
 * resource; a browser client can still be denied it by a CORS configuration
 * that does not expose the header).
 *
 * @param response {ResponseLike | null}
 * @returns {string | undefined}
 */
export function readEtag(response: ResponseLike | null): string | undefined {
  return response?.headers.get('etag') ?? undefined
}

/**
 * Checks a caller-supplied precondition against the document the conditional
 * write path just pre-read, throwing `PreconditionFailedError` when the two
 * already disagree.
 *
 * A conditional codec pre-reads the current document to advance its sequence,
 * which means the caller's compare-and-swap baseline can be compared with
 * server state locally: a caller whose `ifMatch` names a validator the current
 * document no longer carries has lost the race, and a caller asking for
 * create-if-absent has lost it too when a document is already there. Failing
 * here costs no round trip and, more importantly, avoids encoding a sequence
 * advance from a revision the caller never saw.
 *
 * The thrown error is the same `PreconditionFailedError` (412) the server
 * would answer with, so a compare-and-swap retry loop needs no special case
 * for an encrypted collection. A pre-read that carried no `ETag` leaves
 * nothing to compare against locally, and the caller's `ifMatch` is left to
 * the server.
 *
 * @param options {object}
 * @param options.path {string}                       the resource path written
 * @param options.current {ResponseLike | null}       the pre-read document
 * @param [options.precondition] {WritePrecondition}  the caller's precondition
 * @returns {void}
 */
export function assertPreconditionAgainstPreRead({
  path,
  current,
  precondition
}: {
  path: string
  current: ResponseLike | null
  precondition?: WritePrecondition
}): void {
  if (precondition === undefined) {
    return
  }
  if (precondition.ifNoneMatch && current !== null) {
    throw new PreconditionFailedError(
      `Cannot create the document at "${path}": create-if-absent was ` +
        'requested (ifNoneMatch), but a document is already stored there. ' +
        'Re-read it and write an update instead.',
      { status: 412 }
    )
  }
  if (precondition.ifMatch === undefined) {
    return
  }
  if (current === null) {
    throw new PreconditionFailedError(
      `Cannot update the document at "${path}": an ifMatch validator was ` +
        'supplied, but no current document is readable there -- it was ' +
        'deleted, or it is not readable with this capability (WAS masks ' +
        'unauthorized reads as 404). Re-read the resource before retrying.',
      { status: 412 }
    )
  }
  const etag = readEtag(current)
  if (etag !== undefined && etag !== precondition.ifMatch) {
    throw new PreconditionFailedError(
      `Cannot update the document at "${path}": its current version ` +
        `(${etag}) is not the one the write was pinned to ` +
        `(${precondition.ifMatch}) -- another writer changed it. Re-read the ` +
        'resource, rebase the change, and retry.',
      { status: 412 }
    )
  }
}
