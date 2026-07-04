/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the shared write orchestration (`upsertResource`): the
 * conditional-codec pre-read, codec-vs-caller precondition selection, and the
 * masked-404 policy -- a conditional write against a document that exists but is
 * unreadable with the bound capability must surface a clear error, not an
 * inexplicable failed create.
 */
import { describe, it, expect } from 'vitest'

import type { HttpResponse } from '@interop/http-client'
import { PreconditionFailedError } from '../../src/index.js'
import type { ResourceCodec } from '../../src/index.js'
import type { ClientContext, SendInput } from '../../src/internal/request.js'
import { upsertResource } from '../../src/internal/write.js'

/**
 * A minimal conditional codec: encodes the value as JSON and mirrors the EDV
 * codec's precondition behavior (fresh insert when `current` is null, pinned
 * update otherwise).
 */
const conditionalCodec: ResourceCodec = {
  metadataMode: 'plaintext',
  conditionalWrites: true,
  async encode({ id, data, current }) {
    return {
      id,
      json: data as object,
      contentType: 'application/json',
      ...(current
        ? { ifMatch: current.headers.get('etag') ?? undefined }
        : { ifNoneMatch: true })
    }
  },
  async decode() {
    throw new Error('not used')
  },
  async encodeMeta({ custom }) {
    return { custom }
  },
  async decodeMeta() {
    return {}
  }
}

/**
 * Builds a `ClientContext` over a stub `ZcapClient` whose `request` dispatches
 * on the HTTP method: GET throws `getStatus`, PUT throws `putStatus` (or
 * succeeds when undefined). Records every call.
 *
 * @param options {object}
 * @param [options.getStatus] {number}   status the pre-read GET fails with
 * @param [options.putStatus] {number}   status the PUT fails with
 * @returns {object} { context, calls }
 */
function contextWithStatuses({
  getStatus,
  putStatus
}: { getStatus?: number; putStatus?: number } = {}): {
  context: ClientContext
  calls: SendInput[]
} {
  const calls: SendInput[] = []
  const context = {
    serverUrl: 'https://was.example',
    controllerDid: 'did:example:alice',
    zcapClient: {
      async request(args: SendInput) {
        calls.push(args)
        const status = args.method === 'GET' ? getStatus : putStatus
        if (status !== undefined) {
          throw { status, response: { status } }
        }
        return {
          status: 200,
          headers: new Headers({ etag: '"v2"' })
        } as unknown as HttpResponse
      }
    }
  } as unknown as ClientContext
  return { context, calls }
}

describe('upsertResource: masked-404 conditional-write policy', () => {
  it('maps the 412 after an unreadable pre-read to a clear error', async () => {
    // A PUT-only capability on an existing document: the pre-read is masked as
    // 404 (null), so the codec encodes a fresh insert (`If-None-Match: *`) --
    // and a conditional-writes backend rejects it with 412. That 412 must name
    // the real cause: the document exists but is unreadable.
    const { context } = contextWithStatuses({ getStatus: 404, putStatus: 412 })
    await expect(
      upsertResource(context, {
        path: '/space/s/c/r',
        codec: conditionalCodec,
        id: 'r',
        data: { v: 1 }
      })
    ).rejects.toThrow(/not readable with this capability/)
  })

  it('keeps the 412 typed as PreconditionFailedError with its cause', async () => {
    const { context } = contextWithStatuses({ getStatus: 404, putStatus: 412 })
    const failure = await upsertResource(context, {
      path: '/space/s/c/r',
      codec: conditionalCodec,
      id: 'r',
      data: { v: 1 }
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(PreconditionFailedError)
    expect((failure as PreconditionFailedError).cause).toBeInstanceOf(
      PreconditionFailedError
    )
  })

  it('passes an ordinary 412 through unchanged (stale If-Match update)', async () => {
    // When the pre-read DID return the current document, a 412 is a genuine
    // lost-update conflict and must not be re-labeled.
    const { context } = contextWithStatuses({ putStatus: 412 })
    const failure = await upsertResource(context, {
      path: '/space/s/c/r',
      codec: conditionalCodec,
      id: 'r',
      data: { v: 2 }
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(PreconditionFailedError)
    expect((failure as Error).message).not.toMatch(
      /not readable with this capability/
    )
  })

  it('pre-reads only for a conditional codec and forwards its precondition', async () => {
    const { context, calls } = contextWithStatuses()
    await upsertResource(context, {
      path: '/space/s/c/r',
      codec: conditionalCodec,
      id: 'r',
      data: { v: 1 }
    })
    expect(calls.map(call => call.method)).toEqual(['GET', 'PUT'])
    // The pre-read succeeded, so the codec pinned the update to its ETag.
    expect(calls[1]?.headers?.['if-match']).toBe('"v2"')
  })

  it('uses the caller precondition for a non-conditional codec (no pre-read)', async () => {
    const plaintextCodec: ResourceCodec = {
      ...conditionalCodec,
      conditionalWrites: undefined
    } as unknown as ResourceCodec
    const { context, calls } = contextWithStatuses()
    await upsertResource(context, {
      path: '/space/s/c/r',
      codec: plaintextCodec,
      id: 'r',
      data: { v: 1 },
      precondition: { ifMatch: '"caller"' }
    })
    expect(calls.map(call => call.method)).toEqual(['PUT'])
    expect(calls[0]?.headers?.['if-match']).toBe('"caller"')
  })
})
