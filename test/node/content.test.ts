/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for JSON-vs-binary detection on writes (`prepareBody`) and
 * content-type-aware parsing on reads (`parseResource`). The read path is
 * exercised against a minimal `HttpResponse` stub so no server is needed.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { ValidationError } from '../../src/index.js'
import { prepareBody, parseResource } from '../../src/internal/content.js'

/**
 * Builds a minimal `HttpResponse`-shaped stub for `parseResource`.
 *
 * @param options {object}
 * @param options.contentType {string}
 * @param [options.data] {unknown}     pre-parsed JSON body, if any
 * @param [options.blob] {Blob}        blob body, for non-JSON responses
 * @returns {HttpResponse}
 */
function responseStub({
  contentType,
  data,
  blob
}: {
  contentType: string
  data?: unknown
  blob?: Blob
}): HttpResponse {
  return {
    headers: new Headers({ 'content-type': contentType }),
    data,
    async json() {
      return data
    },
    async blob() {
      return blob ?? new Blob([])
    }
  } as unknown as HttpResponse
}

describe('prepareBody', () => {
  it('sends a plain object as JSON', () => {
    expect(prepareBody({ name: 'Sample', value: 42 })).toEqual({
      json: { name: 'Sample', value: 42 }
    })
  })

  it('sends an array as JSON', () => {
    expect(prepareBody([1, 2, 3])).toEqual({ json: [1, 2, 3] })
  })

  it('sends a Blob as binary, defaulting the content-type to its type', () => {
    const blob = new Blob(['hello'], { type: 'text/plain' })
    const prepared = prepareBody(blob)
    expect(prepared.body).toBe(blob)
    expect(prepared.contentType).toBe('text/plain')
  })

  it('lets options.contentType override the Blob type', () => {
    const blob = new Blob(['hello'], { type: 'text/plain' })
    expect(
      prepareBody(blob, { contentType: 'application/json' }).contentType
    ).toBe('application/json')
  })

  it('sends a Uint8Array as octet-stream by default', () => {
    const bytes = new TextEncoder().encode('line 1\n')
    const prepared = prepareBody(bytes)
    expect(prepared.contentType).toBe('application/octet-stream')
    expect(prepared.body).toEqual(bytes)
  })

  it('honors options.contentType for a Uint8Array', () => {
    const bytes = new TextEncoder().encode('line 1\n')
    expect(prepareBody(bytes, { contentType: 'text/plain' }).contentType).toBe(
      'text/plain'
    )
  })

  it('throws a ValidationError for unsupported data (e.g. a primitive)', () => {
    expect(() => prepareBody('not allowed' as never)).toThrow(ValidationError)
    expect(() => prepareBody(null as never)).toThrow(ValidationError)
  })
})

describe('parseResource', () => {
  it('passes a null response (404) straight through as null', async () => {
    expect(await parseResource(null)).toBeNull()
  })

  it('returns the parsed object for a JSON content-type', async () => {
    const response = responseStub({
      contentType: 'application/json',
      data: { message: 'hello' }
    })
    expect(await parseResource(response)).toEqual({ message: 'hello' })
  })

  it('returns a Blob for a non-JSON content-type', async () => {
    const blob = new Blob(['raw bytes'], { type: 'text/plain' })
    const response = responseStub({ contentType: 'text/plain', blob })
    const parsed = await parseResource(response)
    expect(parsed).toBeInstanceOf(Blob)
    expect(await (parsed as Blob).text()).toBe('raw bytes')
  })
})
