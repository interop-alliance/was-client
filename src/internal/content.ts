/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * JSON-vs-binary detection and body coercion for resource writes, plus
 * content-type-aware parsing for resource reads. A plain object/array is sent
 * as JSON; a `Blob`/`Uint8Array`/`Buffer` is sent as binary, with the
 * content-type taken from `options.contentType`, the `Blob.type`, or
 * `application/octet-stream`.
 */
import type { HttpResponse } from '@interop/http-client'
import { ValidationError } from '../errors.js'
import type { Json } from '../types.js'

const OCTET_STREAM = 'application/octet-stream'

/**
 * A write body resolved into either a JSON payload (passed to ezcap as `json`)
 * or a binary payload with its content-type (passed as `body` + header).
 */
export interface PreparedBody {
  json?: object
  body?: Uint8Array | Blob
  contentType?: string
}

function isBlob(value: unknown): value is Blob {
  return typeof Blob !== 'undefined' && value instanceof Blob
}

/**
 * Coerces a `Uint8Array` (including a Node `Buffer`, which is a subclass) to a
 * plain `Uint8Array` view, as ezcap's `body` type expects.
 *
 * @param bytes {Uint8Array}
 * @returns {Uint8Array}
 */
function toPlainBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.constructor === Uint8Array) {
    return bytes
  }
  return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
}

/**
 * Inspects write data and resolves it to a JSON or binary payload.
 *
 * @param data {Json | Blob | Uint8Array}   the resource content
 * @param options {object}
 * @param [options.contentType] {string}    overrides the inferred content-type
 *   for binary data
 * @returns {PreparedBody}
 */
export function prepareBody(
  data: Json | Blob | Uint8Array,
  options: { contentType?: string } = {}
): PreparedBody {
  if (isBlob(data)) {
    return {
      body: data,
      contentType: options.contentType ?? data.type ?? OCTET_STREAM
    }
  }

  if (data instanceof Uint8Array) {
    return {
      body: toPlainBytes(data),
      contentType: options.contentType ?? OCTET_STREAM
    }
  }

  if (data !== null && typeof data === 'object') {
    // Plain object or array -- send as JSON.
    return { json: data as object }
  }

  throw new ValidationError(
    'Resource data must be a plain object/array (JSON) or a ' +
      'Blob/Uint8Array (binary).'
  )
}

/**
 * Reads a JSON response body, preferring the http-client's pre-parsed `data`
 * and falling back to `response.json()` when it is absent.
 *
 * @param response {HttpResponse}
 * @returns {Promise<unknown>}
 */
export async function readJsonData(response: HttpResponse): Promise<unknown> {
  return response.data ?? (await response.json())
}

/**
 * Parses a resource GET response: returns the parsed object when the stored
 * content-type is JSON, otherwise a `Blob` whose `.type` carries the
 * content-type. A `null` response (404) passes through as `null`.
 *
 * @param response {HttpResponse | null}
 * @returns {Promise<Json | Blob | null>}
 */
export async function parseResource(
  response: HttpResponse | null
): Promise<Json | Blob | null> {
  if (response === null) {
    return null
  }
  const contentType = response.headers.get('content-type') ?? ''
  if (contentType.includes('json')) {
    return (await readJsonData(response)) as Json
  }
  return response.blob()
}
