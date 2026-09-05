/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A `WasClient` over a stub `ZcapClient`, for unit tests that drive a handle
 * without a server. The stub hands every `request(...)` call to the test's
 * own handler, which returns a canned `HttpResponse` (see `jsonResponse`) or
 * throws the error the test wants `mapError` to see.
 */
import type { HttpResponse } from '@interop/http-client'
import { WasClient } from '../../src/index.js'

/**
 * The subset of `ZcapClient.request()` arguments the stubs record.
 */
export interface RequestArgs {
  url?: string
  method?: string
  action?: string
  json?: unknown
  headers?: Record<string, string>
  capability?: {
    '@context'?: string
    id?: string
    invocationTarget?: string
    controller?: string
  }
}

/**
 * Builds a `WasClient` whose `ZcapClient` answers each request through
 * `request`.
 *
 * @param request {function}   `(args: RequestArgs) => HttpResponse` (may
 *   throw, or return a promise)
 * @returns {WasClient}
 */
export function clientWithStub(
  request: (args: RequestArgs) => HttpResponse | Promise<HttpResponse>
): WasClient {
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    request
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  return new WasClient({ serverUrl: 'https://was.example', zcapClient })
}

/**
 * A canned response as `@interop/http-client` would pre-parse it: `data` is
 * the JSON body (leave it out for a bodiless 204).
 *
 * @param [options] {object}
 * @param [options.data] {unknown}   the parsed JSON body
 * @param [options.status] {number}   default 200 with a body, 204 without
 * @param [options.headers] {Record<string, string>}
 * @returns {HttpResponse}
 */
export function jsonResponse({
  data,
  status = data === undefined ? 204 : 200,
  headers = {}
}: {
  data?: unknown
  status?: number
  headers?: Record<string, string>
} = {}): HttpResponse {
  return {
    status,
    headers: new Headers(headers),
    data,
    async json() {
      return data
    }
  } as unknown as HttpResponse
}
