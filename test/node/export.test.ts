/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the three whole-space export shapes on `Space`:
 * `export()` (buffered bytes), `exportBlob()` (typed `application/x-tar`
 * container), and `exportStream()` (constant-memory byte stream). A stub
 * `ZcapClient` returns a canned tar `HttpResponse`, so no signer or server is
 * involved; the guards for a body-less response and a JSON-mislabeled archive
 * are exercised directly.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { WasClient, WasServerError } from '../../src/index.js'

const TAR_BYTES = new Uint8Array([0x74, 0x61, 0x72, 0x00, 0xff, 0x01])

/**
 * A canned export response: the fields `Space._exportResponse()` reads
 * (`bodyUsed`, `data`, `headers`) plus the body accessors the three methods
 * use (`arrayBuffer`, `blob`, `body`).
 */
interface ExportResponse {
  contentType?: string
  bodyUsed?: boolean
  data?: unknown
  body?: ReadableStream<Uint8Array> | null
  bytes?: Uint8Array
}

/**
 * Builds a `WasClient` whose signed `POST` returns the given canned export
 * response. Defaults model a conformant server: an unread `application/x-tar`
 * body carrying `TAR_BYTES`.
 *
 * @param response {ExportResponse}
 * @returns {WasClient}
 */
function clientWithExportResponse(response: ExportResponse = {}): WasClient {
  const bytes = response.bytes ?? TAR_BYTES
  const contentType =
    'contentType' in response ? response.contentType : 'application/x-tar'
  const headers = new Headers()
  if (contentType !== undefined) {
    headers.set('content-type', contentType)
  }
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async request() {
      return {
        status: 200,
        headers,
        bodyUsed: response.bodyUsed ?? false,
        data: response.data,
        body:
          'body' in response
            ? response.body
            : new ReadableStream<Uint8Array>({
                start(controller) {
                  controller.enqueue(bytes.slice(0, 3))
                  controller.enqueue(bytes.slice(3))
                  controller.close()
                }
              }),
        async arrayBuffer() {
          return bytes.buffer.slice(
            bytes.byteOffset,
            bytes.byteOffset + bytes.byteLength
          )
        },
        async blob() {
          const buffer = bytes.buffer.slice(
            bytes.byteOffset,
            bytes.byteOffset + bytes.byteLength
          ) as ArrayBuffer
          return new Blob([buffer], {
            type: contentType === 'application/x-tar' ? contentType : ''
          })
        }
      } as unknown as HttpResponse
    }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  return new WasClient({ serverUrl: 'https://was.example', zcapClient })
}

/**
 * Drains a `ReadableStream<Uint8Array>` into a single concatenated array.
 *
 * @param stream {ReadableStream<Uint8Array>}
 * @returns {Promise<Uint8Array>}
 */
async function drain(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  const reader = stream.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) {
      break
    }
    chunks.push(value)
  }
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

describe('space.export()', () => {
  it('returns the archive bytes as a Uint8Array', async () => {
    const client = clientWithExportResponse()
    const bytes = await client.space('s').export()
    expect(bytes).toEqual(TAR_BYTES)
  })
})

describe('space.exportStream()', () => {
  it('returns the response stream whose chunks concatenate to the archive', async () => {
    const client = clientWithExportResponse()
    const stream = await client.space('s').exportStream()
    expect(stream).toBeInstanceOf(ReadableStream)
    expect(await drain(stream)).toEqual(TAR_BYTES)
  })

  it('throws WasServerError when the response carries no body stream', async () => {
    const client = clientWithExportResponse({ body: null })
    await expect(client.space('s').exportStream()).rejects.toBeInstanceOf(
      WasServerError
    )
  })
})

describe('space.exportBlob()', () => {
  it('returns a Blob typed application/x-tar when the server sets the type', async () => {
    const client = clientWithExportResponse()
    const blob = await client.space('s').exportBlob()
    expect(blob.type).toBe('application/x-tar')
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(TAR_BYTES)
  })

  it('normalizes the type when the server omits the content-type', async () => {
    const client = clientWithExportResponse({ contentType: undefined })
    const blob = await client.space('s').exportBlob()
    expect(blob.type).toBe('application/x-tar')
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(TAR_BYTES)
  })
})

describe('export mislabeled-JSON guard', () => {
  it('throws WasServerError when the body was pre-consumed into .data', async () => {
    const client = clientWithExportResponse({
      contentType: 'application/json',
      bodyUsed: true,
      data: { not: 'a tar' }
    })
    await expect(client.space('s').export()).rejects.toBeInstanceOf(
      WasServerError
    )
    await expect(client.space('s').exportStream()).rejects.toBeInstanceOf(
      WasServerError
    )
    await expect(client.space('s').exportBlob()).rejects.toBeInstanceOf(
      WasServerError
    )
  })

  it('names the mislabeled content-type in the error message', async () => {
    const client = clientWithExportResponse({
      contentType: 'application/json',
      data: { not: 'a tar' }
    })
    await expect(client.space('s').export()).rejects.toThrow(
      /application\/json/
    )
  })
})
