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
import { ValidationError, WasServerError } from '../../src/index.js'
import {
  prepareBody,
  parseResource,
  guessContentTypeFromId,
  createdId,
  dataOrNull
} from '../../src/internal/content.js'

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

  it('honors an explicit content-type for JSON data (e.g. JSON-LD)', () => {
    // The bare `json` shorthand carries no content-type header, so the value
    // would be stored as `application/json` -- silently losing the declared
    // media type (which the encrypted path preserves). An explicit type must
    // serialize the value and carry the type.
    const prepared = prepareBody(
      { '@context': 'https://www.w3.org/ns/did/v1' },
      { contentType: 'application/ld+json' }
    )
    expect(prepared.contentType).toBe('application/ld+json')
    expect(prepared.json).toBeUndefined()
    expect(new TextDecoder().decode(prepared.body as Uint8Array)).toBe(
      '{"@context":"https://www.w3.org/ns/did/v1"}'
    )
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

  it('guesses the content-type from options.filename for a Uint8Array', () => {
    const bytes = new TextEncoder().encode('<!doctype html>')
    expect(prepareBody(bytes, { filename: 'index.html' }).contentType).toBe(
      'text/html'
    )
  })

  it('falls back to octet-stream when the filename has no known extension', () => {
    const bytes = new TextEncoder().encode('data')
    expect(prepareBody(bytes, { filename: 'resource' }).contentType).toBe(
      'application/octet-stream'
    )
  })

  it('guesses from options.filename for a typeless Blob', () => {
    const blob = new Blob(['body { color: red }'])
    expect(prepareBody(blob, { filename: 'styles.css' }).contentType).toBe(
      'text/css'
    )
  })

  it('prefers a non-empty Blob.type over the filename guess', () => {
    const blob = new Blob(['hi'], { type: 'text/plain' })
    expect(prepareBody(blob, { filename: 'note.html' }).contentType).toBe(
      'text/plain'
    )
  })

  it('lets options.contentType override the filename guess', () => {
    const bytes = new TextEncoder().encode('data')
    expect(
      prepareBody(bytes, { filename: 'index.html', contentType: 'text/plain' })
        .contentType
    ).toBe('text/plain')
  })

  it('throws a ValidationError for unsupported data (e.g. a primitive)', () => {
    expect(() => prepareBody('not allowed' as never)).toThrow(ValidationError)
    expect(() => prepareBody(null as never)).toThrow(ValidationError)
  })
})

describe('guessContentTypeFromId', () => {
  it('maps known static-web extensions, case-insensitively', () => {
    expect(guessContentTypeFromId('index.html')).toBe('text/html')
    expect(guessContentTypeFromId('app.MJS')).toBe('text/javascript')
    expect(guessContentTypeFromId('photo.JPEG')).toBe('image/jpeg')
  })

  it('uses the last extension of a multi-dot name', () => {
    expect(guessContentTypeFromId('logo.min.svg')).toBe('image/svg+xml')
  })

  it('returns undefined for an unknown extension', () => {
    expect(guessContentTypeFromId('archive.tar.gz')).toBeUndefined()
  })

  it('returns undefined for a name with no extension', () => {
    expect(guessContentTypeFromId('resource')).toBeUndefined()
  })

  it('returns undefined for a leading-dot dotfile', () => {
    expect(guessContentTypeFromId('.gitignore')).toBeUndefined()
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

  it('returns the parsed object for an application/*+json structured suffix', async () => {
    const response = responseStub({
      contentType: 'application/ld+json',
      data: { '@context': 'x' }
    })
    expect(await parseResource(response)).toEqual({ '@context': 'x' })
  })

  it('returns the parsed object for a JSON content-type with parameters', async () => {
    const response = responseStub({
      contentType: 'application/json; charset=utf-8',
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

  // Content-types that merely contain the substring "json" but are NOT JSON
  // (e.g. JSON Lines / NDJSON / JSON-seq) must read back as raw binary, not be
  // JSON-parsed -- a multi-line JSONL body is not a single JSON value.
  it.each(['application/jsonl', 'application/json-seq', 'application/json5'])(
    'returns a Blob for %s (json-substring but not JSON)',
    async contentType => {
      const blob = new Blob(['{"a":1}\n{"a":2}\n'], { type: contentType })
      const response = responseStub({ contentType, blob })
      const parsed = await parseResource(response)
      expect(parsed).toBeInstanceOf(Blob)
      expect(await (parsed as Blob).text()).toBe('{"a":1}\n{"a":2}\n')
    }
  )

  // `@interop/http-client` pre-consumes the JSON body into `.data`, so a stored
  // top-level `null` arrives as `.data === null` with the stream already used.
  // `readJsonData` must return that `null`, not fall through to `.json()`.
  it('returns a stored top-level null without re-reading the body', async () => {
    const response = {
      headers: new Headers({ 'content-type': 'application/json' }),
      data: null,
      async json() {
        throw new TypeError('Body has already been used')
      },
      async blob() {
        return new Blob([])
      }
    } as unknown as HttpResponse
    expect(await parseResource(response)).toBeNull()
  })
})

describe('createdId', () => {
  /**
   * Builds a minimal create-response stub.
   *
   * @param options {object}
   * @param [options.data] {unknown}      the pre-parsed JSON body, if any
   * @param [options.location] {string}   the `Location` header, if any
   * @returns {HttpResponse}
   */
  function createResponse({
    data,
    location
  }: {
    data?: unknown
    location?: string
  }): HttpResponse {
    return {
      headers: new Headers(location ? { location } : {}),
      data
    } as unknown as HttpResponse
  }

  it("prefers the body's id", () => {
    expect(createdId(createResponse({ data: { id: 'abc' } }))).toBe('abc')
  })

  it('falls back to the last (decoded) Location segment for a body-less 2xx', () => {
    expect(
      createdId(
        createResponse({ location: 'https://was.example/space/s/c/a%20b' })
      )
    ).toBe('a b')
  })

  it('ignores a trailing slash on the Location header', () => {
    expect(
      createdId(createResponse({ location: 'https://was.example/space/s/' }))
    ).toBe('s')
  })

  it('throws a WasServerError when neither body id nor Location is present', () => {
    expect(() => createdId(createResponse({}))).toThrow(WasServerError)
    expect(() => createdId(null)).toThrow(WasServerError)
  })
})

describe('dataOrNull', () => {
  it('maps a null (404) response to null', () => {
    expect(dataOrNull(null)).toBeNull()
  })

  it('unwraps pre-parsed JSON data', () => {
    const response = responseStub({
      contentType: 'application/json',
      data: { id: 'c1' }
    })
    expect(dataOrNull(response)).toEqual({ id: 'c1' })
  })

  it('maps an undefined data (non-JSON content-type or 204) to null', () => {
    // The http-client leaves `data` undefined when the response is not JSON
    // (e.g. a misconfigured proxy answering `200 text/html`) or has no body.
    // Casting that through as `T` would make callers dereference `undefined`.
    const response = responseStub({ contentType: 'text/html' })
    expect(dataOrNull(response)).toBeNull()
  })

  it('passes a stored top-level JSON null through as null', () => {
    const response = responseStub({
      contentType: 'application/json',
      data: null
    })
    expect(dataOrNull(response)).toBeNull()
  })
})
