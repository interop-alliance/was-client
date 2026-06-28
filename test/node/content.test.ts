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
import {
  prepareBody,
  parseResource,
  guessContentTypeFromId
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
})
