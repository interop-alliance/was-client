/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The load-bearing transport layer: wraps `zcapClient.request(...)`, resolving
 * paths against the server URL and defaulting the capability `action` to the
 * HTTP method (never ezcap's `read`/`write`). `send()` adds the typed-error
 * mapping and the null-on-404 read translation; `rawRequest()` is the
 * unmapped escape hatch used by `was.request()`. Every signed request first
 * awaits the context's memoized service discovery, so no request reaches a
 * server whose protocol version this client does not speak.
 */
import type { ZcapClient } from '@interop/ezcap'
import type { HttpResponse } from '@interop/http-client'
import { WasError, mapError, httpStatus } from '../errors.js'
import { toUrl } from './paths.js'
import { dataOrNull } from './content.js'
import { readEtag } from './conditional.js'
import type { EncryptionProvider } from '../codec.js'
import type { IZcap, RequestInput, ServiceInfo } from '../types.js'

/**
 * The shared context threaded through every handle: the server base URL, the
 * wrapped ezcap client, the controller DID of its signer, the optional
 * encryption provider that supplies an encrypting codec for the collections
 * the client holds keys for, and the memoized service discovery every signed
 * request waits on.
 *
 * `controllerDid` is a lazy read, not a stored string: `WasClient` backs it
 * with a getter so that building a context (and therefore a handle) never
 * requires an invocation signer. A client that holds only a delegation signer
 * reads it as a `ValidationError`, at the two operations that actually need
 * it (`createSpace`'s controller default and `rootCapability`'s client-side
 * controller) rather than at construction.
 */
export interface ClientContext {
  serverUrl: string
  zcapClient: ZcapClient
  controllerDid: string
  encryption?: EncryptionProvider
  service: () => Promise<ServiceInfo>
}

/**
 * A single signed request: the public `RequestInput` shape (either `path`,
 * resolved against `serverUrl`, or an absolute `url` must be given) plus the
 * `send()`-level 404 translations.
 */
export interface SendInput extends RequestInput {
  /**
   * When true, a 404 response resolves to `null` instead of throwing.
   */
  read?: boolean
  /**
   * When true, a 404 response resolves to `null` instead of throwing, so a
   * delete of an already-absent target succeeds (idempotent delete).
   */
  idempotent?: boolean
}

function resolveRequestUrl(context: ClientContext, input: SendInput): string {
  if (input.url !== undefined) {
    return input.url
  }
  if (input.path === undefined) {
    throw new TypeError('Either "path" or "url" is required.')
  }
  return toUrl({ serverUrl: context.serverUrl, path: input.path })
}

/**
 * Signs and sends a request via the wrapped ezcap client, returning the raw
 * `HttpResponse` and throwing the raw ky/ezcap error. Does not apply error
 * mapping or null-on-404 -- this is the escape-hatch primitive. It waits on
 * the context's service discovery first, and rejects with that discovery's
 * error (such as `IncompatibleServerError`) before anything is signed.
 *
 * @param context {ClientContext}
 * @param input {SendInput}
 * @returns {Promise<HttpResponse>}
 */
export async function rawRequest(
  context: ClientContext,
  input: SendInput
): Promise<HttpResponse> {
  const url = resolveRequestUrl(context, input)
  await context.service()
  const method = input.method ?? 'GET'
  return context.zcapClient.request({
    url,
    capability: input.capability,
    method,
    // Default the capability action to the HTTP method (never `read`/`write`).
    action: input.action ?? method,
    headers: input.headers,
    json: input.json,
    body: input.body
  })
}

/**
 * A plain unsigned `fetch` that maps a network failure to a `WasError`, the
 * way the rest of the transport does. The response is returned as is,
 * whatever its status.
 *
 * @param url {string}
 * @param init {RequestInit}
 * @returns {Promise<Response>}
 */
export async function fetchMapped(
  url: string,
  init: RequestInit
): Promise<Response> {
  try {
    return await fetch(url, init)
  } catch (err) {
    throw mapError(err)
  }
}

/**
 * Sends an **unsigned** request (a plain `fetch`, no capability invocation), for
 * reading public (`PublicCanRead`) resources that need no authorization. Applies
 * the same typed-error mapping and null-on-404 read translation as `send()`.
 * Takes an absolute `url` -- public reads address a resource by its link, not by
 * a server-relative path.
 *
 * @param input {object}
 * @param input.url {string}                    absolute URL to read
 * @param [input.method] {string}               HTTP method (defaults to `GET`)
 * @param [input.headers] {Record<string,string>}
 * @param [input.read] {boolean}                when true, a 404/401/403 resolves to `null`
 * @returns {Promise<HttpResponse | null>}
 */
export async function unsignedRequest(input: {
  url: string
  method?: string
  headers?: Record<string, string>
  read?: boolean
}): Promise<HttpResponse | null> {
  const response = await fetchMapped(input.url, {
    method: input.method ?? 'GET',
    headers: input.headers
  })
  if (response.ok) {
    return response as HttpResponse
  }
  // A public read resolves to `null` for any "not readable by you" status, not
  // just 404: a conformant WAS masks unauthorized as 404, but a server that
  // answers a missing capability with 401/403 should honor the same
  // null-if-not-publicly-readable contract rather than throw.
  if (
    input.read &&
    (response.status === 404 ||
      response.status === 401 ||
      response.status === 403)
  ) {
    return null
  }
  // Reconstruct a problem+json-shaped error so mapError can dispatch on it.
  let data: unknown
  try {
    data = await response.json()
  } catch {
    data = undefined
  }
  throw mapError({ status: response.status, requestUrl: input.url, data })
}

/**
 * Signs and sends a request, applying the typed-error mapping. When `read` is
 * set, a 404 resolves to `null` (MongoDB `findOne` semantics); otherwise every
 * non-2xx maps to a `WasError` subclass.
 *
 * @param context {ClientContext}
 * @param input {SendInput}
 * @returns {Promise<HttpResponse | null>}
 */
export async function send(
  context: ClientContext,
  input: SendInput
): Promise<HttpResponse | null> {
  try {
    return await rawRequest(context, input)
  } catch (err) {
    // Only a raw transport error translates: a `WasError` (such as a discovery
    // refusal) is already an answer and passes through whatever its status.
    if (
      (input.read || input.idempotent) &&
      !(err instanceof WasError) &&
      httpStatus(err) === 404
    ) {
      return null
    }
    throw mapError(err)
  }
}

/**
 * The GET-a-JSON-description read shared across the handles: a signed
 * null-on-404 `GET` of `path` whose pre-parsed body is unwrapped as `T`. Both
 * a missing/unauthorized target (404) and a bodyless/non-JSON response resolve
 * to `null` (see `dataOrNull`).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.path {string}          the path to read
 * @param [options.capability] {IZcap}   capability attached to the request
 * @returns {Promise<T | null>}
 */
export async function readData<T>(
  context: ClientContext,
  { path, capability }: { path: string; capability?: IZcap }
): Promise<T | null> {
  const response = await send(context, {
    path,
    method: 'GET',
    capability,
    read: true
  })
  return dataOrNull<T>(response)
}

/**
 * {@link readData} keeping the response's `ETag` validator beside the body:
 * the read-with-validator shape a description compare-and-swap starts from.
 * `null` on the same conditions as `readData`; `etag` is absent against a
 * server that does not version the target.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.path {string}          the path to read
 * @param [options.capability] {IZcap}   capability attached to the request
 * @returns {Promise<{ data: T; etag?: string } | null>}
 */
export async function readDataWithEtag<T>(
  context: ClientContext,
  { path, capability }: { path: string; capability?: IZcap }
): Promise<{ data: T; etag?: string } | null> {
  const response = await send(context, {
    path,
    method: 'GET',
    capability,
    read: true
  })
  const data = dataOrNull<T>(response)
  if (data === null) {
    return null
  }
  return { data, etag: readEtag(response) }
}
