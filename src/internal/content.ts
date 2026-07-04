/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * JSON-vs-binary detection and body coercion for resource writes, plus
 * content-type-aware parsing for resource reads. A plain object/array is sent
 * as JSON; a `Blob`/`Uint8Array`/`Buffer` is sent as binary, with the
 * content-type taken from `options.contentType`, the `Blob.type`, a guess from
 * the resource id's file extension (`options.filename`), or
 * `application/octet-stream`.
 */
import type { HttpResponse } from '@interop/http-client'
import { ValidationError, WasServerError } from '../errors.js'
import type { Json, ResourceData } from '../types.js'

const OCTET_STREAM = 'application/octet-stream'

/**
 * A shared `TextEncoder` for serializing an explicitly-typed JSON write to
 * bytes (stateless, so one instance is reused).
 */
const ENCODER = new TextEncoder()

/**
 * Whether a content-type denotes JSON -- `application/json` or any
 * `application/<prefix>+json` structured-suffix variant (e.g.
 * `application/ld+json`, `application/jose+json`), each optionally followed by
 * parameters (`; charset=utf-8`). The `json` token is anchored to the end of the
 * media type, so a non-JSON type that merely contains the substring `json` --
 * `application/jsonl`, `application/json-seq`, `application/json5` -- is NOT
 * treated as JSON and is read back as binary (a `Blob`) instead of being
 * JSON-parsed.
 *
 * @param contentType {string}
 * @returns {boolean}
 */
export function isJsonContentType(contentType: string): boolean {
  return /^application\/([^+\s;]+\+)?json\s*(;.*)?$/i.test(contentType)
}

/**
 * Whether a content type denotes UTF-8-safe text that should be stored inline as
 * a plain string (legible, no ~33% base64 inflation) rather than as opaque
 * binary -- `text/*`, plus the XML/SVG family that is textual despite an
 * `application/` or `image/` prefix (`application/xml`, any `+xml` structured
 * suffix such as `image/svg+xml` / `application/atom+xml`). Kept deliberately
 * narrow: an unlisted type is treated as binary (base64), which is always
 * byte-safe, and the caller additionally gates on valid UTF-8 before choosing
 * text. Any `; charset=…` parameter is ignored.
 *
 * @param contentType {string}
 * @returns {boolean}
 */
export function isTextContentType(contentType: string): boolean {
  const type = (contentType.split(';')[0] ?? '').trim().toLowerCase()
  return (
    type.startsWith('text/') ||
    type === 'application/xml' ||
    type.endsWith('+xml')
  )
}

/**
 * Extension-to-content-type fallbacks for the common static-web file types --
 * the only case where guessing a content-type from a resource id pays off
 * (e.g. serving an HTML site out of a public Collection). Deliberately tiny and
 * inline: an explicit `contentType` (or a non-empty `Blob.type`) always wins,
 * and an unknown extension yields no guess -- so this never needs the breadth
 * (or the `mime-db`-sized weight) of a full media-type library. `.js`/`.mjs`
 * are pinned to `text/javascript` (the WHATWG-preferred form).
 */
const WEB_CONTENT_TYPES: Record<string, string> = {
  html: 'text/html',
  css: 'text/css',
  js: 'text/javascript',
  mjs: 'text/javascript',
  json: 'application/json',
  svg: 'image/svg+xml',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  ico: 'image/x-icon',
  woff2: 'font/woff2',
  txt: 'text/plain',
  wasm: 'application/wasm'
}

/**
 * Guesses a content-type from a resource id's file extension, limited to the
 * static-web types in `WEB_CONTENT_TYPES`. Returns `undefined` when the id has
 * no extension, is a leading-dot dotfile (e.g. `.gitignore`), or carries an
 * unrecognized extension -- never a generic fallback, so the caller stays in
 * control of a miss.
 *
 * @param id {string}   the resource id (often a filename like `index.html`)
 * @returns {string | undefined}
 */
export function guessContentTypeFromId(id: string): string | undefined {
  const lastDot = id.lastIndexOf('.')
  if (lastDot < 1) {
    return undefined
  }
  const extension = id.slice(lastDot + 1).toLowerCase()
  return WEB_CONTENT_TYPES[extension]
}

/**
 * A write body resolved into either a JSON payload (passed to ezcap as `json`)
 * or a binary payload with its content-type (passed as `body` + header).
 */
export interface PreparedBody {
  json?: object
  body?: Uint8Array | Blob
  contentType?: string
}

/**
 * Whether a value is a `Blob`, guarding for environments where `Blob` is
 * undefined.
 *
 * @param value {unknown}
 * @returns {boolean}
 */
export function isBlob(value: unknown): value is Blob {
  return typeof Blob !== 'undefined' && value instanceof Blob
}

/**
 * Coerces a `Uint8Array` (including a Node `Buffer`, which is a subclass) to a
 * plain `Uint8Array` view, as ezcap's `body` type expects.
 *
 * @param bytes {Uint8Array}
 * @returns {Uint8Array}
 */
export function toPlainBytes(bytes: Uint8Array): Uint8Array {
  if (bytes.constructor === Uint8Array) {
    return bytes
  }
  return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
}

/**
 * Write data classified by `resolvePayload`: binary (a `Blob`/`Uint8Array`
 * with its resolved content-type), JSON (a plain object/array), or invalid (a
 * bare primitive -- the caller throws its own error message).
 */
export type ResolvedPayload =
  | { kind: 'binary'; data: Blob | Uint8Array; contentType: string }
  | { kind: 'json' }
  | { kind: 'invalid' }

/**
 * Classifies write data as binary or JSON and resolves the binary
 * content-type -- the single source of the detection and precedence rules
 * shared by the plaintext `prepareBody` and the EDV codec's document builder.
 *
 * The binary content-type resolves in precedence order: an explicit
 * `contentType`, then a non-empty `Blob.type`, then a guess from the resource
 * `id`'s extension, then `application/octet-stream`. (Coalescing with `||`
 * rather than `??` so an empty-string `Blob.type` -- a typeless Blob -- falls
 * through to the guess instead of becoming an empty content-type.)
 *
 * @param options {object}
 * @param options.data {ResourceData}       the resource content
 * @param [options.contentType] {string}    overrides the inferred content-type
 *   for binary data
 * @param [options.id] {string}             resource id used to guess a
 *   content-type by extension when none is given (binary data only)
 * @returns {ResolvedPayload}
 */
export function resolvePayload({
  data,
  contentType,
  id
}: {
  data: ResourceData
  contentType?: string
  id?: string
}): ResolvedPayload {
  const guessed = id ? guessContentTypeFromId(id) : undefined
  if (isBlob(data)) {
    return {
      kind: 'binary',
      data,
      contentType: contentType || data.type || guessed || OCTET_STREAM
    }
  }
  if (data instanceof Uint8Array) {
    return {
      kind: 'binary',
      data,
      contentType: contentType || guessed || OCTET_STREAM
    }
  }
  if (data !== null && typeof data === 'object') {
    return { kind: 'json' }
  }
  return { kind: 'invalid' }
}

/**
 * Inspects write data and resolves it to a JSON or binary payload, using
 * {@link resolvePayload} for the detection and content-type precedence rules.
 *
 * @param data {ResourceData}                the resource content
 * @param options {object}
 * @param [options.contentType] {string}    overrides the inferred content-type
 *   for binary data
 * @param [options.filename] {string}       resource id used to guess a
 *   content-type by extension when none is given (binary data only)
 * @returns {PreparedBody}
 */
export function prepareBody(
  data: ResourceData,
  options: { contentType?: string; filename?: string } = {}
): PreparedBody {
  const payload = resolvePayload({
    data,
    contentType: options.contentType,
    id: options.filename
  })

  if (payload.kind === 'binary') {
    return {
      body: isBlob(payload.data) ? payload.data : toPlainBytes(payload.data),
      contentType: payload.contentType
    }
  }

  if (payload.kind === 'json') {
    // Plain object or array -- send as JSON. An explicit `contentType` (e.g.
    // `application/ld+json`) is honored by serializing the value ourselves and
    // sending it with that content-type header; the bare `json` shorthand
    // would silently store it as `application/json`, losing the declared media
    // type (which the encrypted path preserves).
    if (options.contentType !== undefined) {
      return {
        body: ENCODER.encode(JSON.stringify(data)),
        contentType: options.contentType
      }
    }
    return { json: data as object }
  }

  throw new ValidationError(
    'Resource data must be a plain object/array (JSON) or a ' +
      'Blob/Uint8Array (binary).'
  )
}

/**
 * Extracts the id of a just-created resource from a create response. Prefers
 * the response body's `id`; for a body-less 2xx falls back to the last path
 * segment of the `Location` header (decoded, since the server emits a
 * percent-encoded path). Throws a `WasServerError` when the response carries
 * neither -- a malformed create response -- rather than letting an absent body
 * surface as a raw `TypeError` on `data.id`.
 *
 * @param response {HttpResponse | null}
 * @returns {string}
 */
export function createdId(response: HttpResponse | null): string {
  const data = (response as { data?: unknown } | null)?.data as
    { id?: unknown } | undefined
  if (
    data !== null &&
    typeof data === 'object' &&
    typeof data.id === 'string'
  ) {
    return data.id
  }
  const location = response?.headers.get('location')
  const segment = location
    ? location.split('/').filter(Boolean).pop()
    : undefined
  if (segment) {
    return decodeURIComponent(segment)
  }
  throw new WasServerError(
    'Create response carried no resource id: the body has no `id` and there ' +
      'is no `Location` header.'
  )
}

/**
 * Unwraps a read response's pre-parsed JSON `data` as `T`, mapping a `null`
 * response (a 404 that a `read` request resolved to `null`) to `null`. The
 * http-client leaves `data` undefined for a non-JSON content-type or a 204;
 * that is also mapped to `null`, so the declared `T | null` is honest and a
 * caller never dereferences `undefined` cast as `T`.
 *
 * @param response {HttpResponse | null}
 * @returns {T | null}
 */
export function dataOrNull<T>(response: HttpResponse | null): T | null {
  return response === null || response.data === undefined
    ? null
    : (response.data as T)
}

/**
 * Reads a JSON response body, preferring the http-client's pre-parsed `data`
 * and falling back to `response.json()` when it is absent.
 *
 * `@interop/http-client` pre-consumes the body into `.data` for JSON
 * content-types, so a stored top-level `null` arrives as `.data === null`.
 * Test for `undefined` rather than using `??`; otherwise the nullish fallback
 * would re-invoke `.json()` on the already-consumed stream and throw.
 *
 * @param response {HttpResponse}
 * @returns {Promise<unknown>}
 */
export async function readJsonData(response: HttpResponse): Promise<unknown> {
  return response.data === undefined ? await response.json() : response.data
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
  if (isJsonContentType(contentType)) {
    return (await readJsonData(response)) as Json
  }
  return response.blob()
}
