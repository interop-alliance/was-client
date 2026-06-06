/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The load-bearing transport layer: wraps `zcapClient.request(...)`, resolving
 * paths against the server URL and defaulting the capability `action` to the
 * HTTP method (never ezcap's `read`/`write`). `send()` adds the typed-error
 * mapping and the null-on-404 read translation; `rawRequest()` is the
 * unmapped escape hatch used by `was.request()`.
 */
import type { ZcapClient } from '@interop/ezcap'
import type { HttpResponse } from '@interop/http-client'
import { mapError } from '../errors.js'
import { toUrl } from './paths.js'
import type { IZcap } from '../types.js'

/**
 * The shared context threaded through every handle: the server base URL, the
 * wrapped ezcap client, and the cached controller DID of its signer.
 */
export interface ClientContext {
  serverUrl: string
  zcapClient: ZcapClient
  controllerDid: string
}

/**
 * A single signed request. Either `path` (resolved against `serverUrl`) or
 * `url` (absolute) must be given.
 */
export interface SendInput {
  // Mutually exclusive - either path (resolved against serverUrl) or full url.
  path?: string
  url?: string
  // HTTP Method (get, post, delete, etc.)
  method?: string
  // Action (if different from http method). If absent, defaults to http method.
  action?: string
  // HTTP Headers
  headers?: Record<string, string>
  json?: object
  body?: Blob | Uint8Array
  capability?: IZcap
  /** When true, a 404 response resolves to `null` instead of throwing. */
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
 * mapping or null-on-404 -- this is the escape-hatch primitive.
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
    const status = (err as { status?: number; response?: { status?: number } })
      ?.status
    const responseStatus = (err as { response?: { status?: number } })?.response
      ?.status
    if (
      (input.read || input.idempotent) &&
      (status === 404 || responseStatus === 404)
    ) {
      return null
    }
    throw mapError(err)
  }
}
