/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Helpers for conditional writes (the server's `conditional-writes` feature):
 * assembling a write's request headers from an optional content-type plus the
 * `If-Match` / `If-None-Match: *` preconditions, and reading the `ETag` a write
 * response returns.
 */
import type { HttpResponse } from '@interop/http-client'

/**
 * A conditional-write precondition: `ifMatch` is the quoted ETag an
 * update-if-unchanged write must match; `ifNoneMatch` requests a create-if-absent
 * (`If-None-Match: *`). At most one is normally set.
 */
export interface WritePrecondition {
  ifMatch?: string
  ifNoneMatch?: boolean
}

/**
 * Builds the headers for a write request: the content-type (when present) and
 * the conditional-write precondition headers (`If-Match` / `If-None-Match: *`).
 * Returns `undefined` when no header is needed, matching the request layer's
 * optional `headers`.
 *
 * @param options {object}
 * @param [options.contentType] {string}          the body content-type, if any
 * @param [options.precondition] {WritePrecondition}   the conditional-write
 *   precondition
 * @returns {Record<string, string> | undefined}
 */
export function writeHeaders({
  contentType,
  precondition = {}
}: {
  contentType?: string
  precondition?: WritePrecondition
}): Record<string, string> | undefined {
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
  return Object.keys(headers).length > 0 ? headers : undefined
}

/**
 * Reads the strong `ETag` validator a write/read response returned, or
 * `undefined` when the backend sent none (it does not advertise the
 * `conditional-writes` feature).
 *
 * @param response {HttpResponse | null}
 * @returns {string | undefined}
 */
export function readEtag(response: HttpResponse | null): string | undefined {
  return response?.headers.get('etag') ?? undefined
}
