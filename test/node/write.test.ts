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
import {
  NotFoundError,
  PreconditionFailedError,
  ValidationError
} from '../../src/index.js'
import type { ResourceCodec } from '../../src/index.js'
import type { ClientContext, SendInput } from '../../src/internal/request.js'
import { featureProbeFrom } from '../../src/internal/features.js'
import { insertResource, upsertResource } from '../../src/internal/write.js'
import { stubFeatures } from '../helpers/codec.js'

/**
 * A features probe for a backend advertising `conditional-writes` -- the
 * capable-backend default for these tests.
 */
const conditionalFeatures = stubFeatures(['conditional-writes'])

/**
 * A minimal conditional codec: encodes the value as JSON and mirrors the EDV
 * codec's precondition behavior (fresh insert when `current` is null, pinned
 * update otherwise).
 */
const conditionalCodec: ResourceCodec = {
  conditionalWrites: true,
  async encode({ id, data, current, precondition }) {
    return {
      id,
      json: data as object,
      contentType: 'application/json',
      ...(precondition ??
        (current
          ? { ifMatch: current.headers.get('etag') ?? undefined }
          : { ifNoneMatch: true }))
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
        data: { v: 1 },
        features: conditionalFeatures
      })
    ).rejects.toThrow(/not readable with this capability/)
  })

  it('keeps the 412 typed as PreconditionFailedError with its cause', async () => {
    const { context } = contextWithStatuses({ getStatus: 404, putStatus: 412 })
    const failure = await upsertResource(context, {
      path: '/space/s/c/r',
      codec: conditionalCodec,
      id: 'r',
      data: { v: 1 },
      features: conditionalFeatures
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
      data: { v: 2 },
      features: conditionalFeatures
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
      data: { v: 1 },
      features: conditionalFeatures
    })
    expect(calls.map(call => call.method)).toEqual(['GET', 'PUT'])
    // The pre-read succeeded, so the codec pinned the update to its ETag.
    expect(calls[1]?.headers?.['if-match']).toBe('"v2"')
  })

  it("pins a conditional codec's write to the caller's own baseline", async () => {
    // The caller named the same revision the pre-read observed, so the write
    // goes out pinned to the caller's validator rather than being silently
    // repinned to whatever the codec just read.
    const { context, calls } = contextWithStatuses()
    await upsertResource(context, {
      path: '/space/s/c/r',
      codec: conditionalCodec,
      id: 'r',
      data: { v: 1 },
      features: conditionalFeatures,
      precondition: { ifMatch: '"v2"' }
    })
    expect(calls.map(call => call.method)).toEqual(['GET', 'PUT'])
    expect(calls[1]?.headers?.['if-match']).toBe('"v2"')
  })

  it('refuses a caller baseline the pre-read has already moved past', async () => {
    const { context, calls } = contextWithStatuses()
    const failure = await upsertResource(context, {
      path: '/space/s/c/r',
      codec: conditionalCodec,
      id: 'r',
      data: { v: 1 },
      features: conditionalFeatures,
      precondition: { ifMatch: '"v1"' }
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(PreconditionFailedError)
    expect((failure as PreconditionFailedError).status).toBe(412)
    expect((failure as Error).message).toMatch(/another writer changed it/)
    // The write never left the client.
    expect(calls.map(call => call.method)).toEqual(['GET'])
  })

  it('refuses a create-if-absent against a document that is already there', async () => {
    const { context, calls } = contextWithStatuses()
    const failure = await upsertResource(context, {
      path: '/space/s/c/r',
      codec: conditionalCodec,
      id: 'r',
      data: { v: 1 },
      features: conditionalFeatures,
      precondition: { ifNoneMatch: true }
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(PreconditionFailedError)
    expect((failure as Error).message).toMatch(/already stored there/)
    expect(calls.map(call => call.method)).toEqual(['GET'])
  })

  it('refuses a caller baseline when the pre-read finds nothing readable', async () => {
    const { context, calls } = contextWithStatuses({ getStatus: 404 })
    const failure = await upsertResource(context, {
      path: '/space/s/c/r',
      codec: conditionalCodec,
      id: 'r',
      data: { v: 1 },
      features: conditionalFeatures,
      precondition: { ifMatch: '"v1"' }
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(PreconditionFailedError)
    expect((failure as Error).message).toMatch(
      /no current document is readable/
    )
    expect(calls.map(call => call.method)).toEqual(['GET'])
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
      features: conditionalFeatures,
      precondition: { ifMatch: '"caller"' }
    })
    expect(calls.map(call => call.method)).toEqual(['PUT'])
    expect(calls[0]?.headers?.['if-match']).toBe('"caller"')
  })
})

describe('upsertResource: chunked plans are insert-only', () => {
  it('refuses a codec that answers a write by id with a chunked plan', async () => {
    // Auto-routing a large blob is an `add()` affordance: reconciling an
    // existing document's chunks with a fresh stream is not this path's job, so
    // the plan is refused before anything is written.
    const chunkedCodec: ResourceCodec = {
      ...conditionalCodec,
      async encode() {
        return {
          chunked: true,
          id: 'r',
          async execute() {
            throw new Error('the plan must never be executed here')
          }
        }
      }
    }
    const { context, calls } = contextWithStatuses()
    const failure = await upsertResource(context, {
      path: '/space/s/c/r',
      codec: chunkedCodec,
      id: 'r',
      data: { v: 1 },
      features: conditionalFeatures
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(ValidationError)
    expect((failure as Error).message).toMatch(/add\(\)/)
    // Only the conditional pre-read went out; no PUT was attempted.
    expect(calls.map(call => call.method)).toEqual(['GET'])
  })

  it("appends the codec's own guidance to the generic refusal", async () => {
    // This layer is scheme-agnostic, so the recovery advice (which low-level
    // API drives the write directly) comes from the plan, not from here.
    const guidedCodec: ResourceCodec = {
      ...conditionalCodec,
      async encode() {
        return {
          chunked: true,
          id: 'r',
          guidance: 'Drive it with the low-level API instead.',
          async execute() {
            throw new Error('the plan must never be executed here')
          }
        }
      }
    }
    const { context } = contextWithStatuses()
    const failure = await upsertResource(context, {
      path: '/space/s/c/r',
      codec: guidedCodec,
      id: 'r',
      data: { v: 1 },
      features: conditionalFeatures
    }).catch((err: unknown) => err)
    expect((failure as Error).message).toContain(
      'Drive it with the low-level API instead.'
    )
  })
})

describe('insertResource: a chunked plan runs on the mapped request path', () => {
  /**
   * A codec that answers every encode with a plan whose `execute` issues one
   * `PUT` through the request context it is handed.
   */
  const planCodec: ResourceCodec = {
    ...conditionalCodec,
    async encode() {
      return {
        chunked: true,
        id: 'r',
        async execute(codecContext) {
          await codecContext.request({
            path: '/space/s/c/r',
            method: 'PUT',
            body: new Uint8Array([1, 2, 3])
          })
          return { id: 'r' }
        }
      }
    }
  }

  it('surfaces a 404 from the plan as a typed NotFoundError', async () => {
    // The plan drives its own I/O, but it is still the caller's `add()`: its
    // failures must be the typed errors `add()` documents, not raw ky/ezcap
    // errors.
    const { context } = contextWithStatuses({ putStatus: 404 })
    const failure = await insertResource(context, {
      itemsPath: '/space/s/c/',
      pathForId: (id: string) => `/space/s/c/${id}`,
      codec: planCodec,
      data: { v: 1 },
      features: conditionalFeatures
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(NotFoundError)
  })

  it('carries the HTTP status through, so a status-dispatching driver still works', async () => {
    const { context } = contextWithStatuses({ putStatus: 412 })
    const failure = await insertResource(context, {
      itemsPath: '/space/s/c/',
      pathForId: (id: string) => `/space/s/c/${id}`,
      codec: planCodec,
      data: { v: 1 },
      features: conditionalFeatures
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(PreconditionFailedError)
    expect((failure as PreconditionFailedError).status).toBe(412)
  })
})

describe('upsertResource: insert gate on a non-conditional backend', () => {
  it('refuses an insert-after-null-pre-read when the backend lacks conditional-writes', async () => {
    // The pre-read is null (absent OR unreadable -- indistinguishable), and the
    // backend would ignore `If-None-Match: *`, so a masked-404 insert could
    // silently clobber an existing document. The write must fail closed before
    // any PUT is sent.
    const { context, calls } = contextWithStatuses({ getStatus: 404 })
    const failure = await upsertResource(context, {
      path: '/space/s/c/r',
      codec: conditionalCodec,
      id: 'r',
      data: { v: 1 },
      features: stubFeatures([])
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(ValidationError)
    expect((failure as Error).message).toMatch(/conditional-writes/)
    expect(calls.map(call => call.method)).toEqual(['GET'])
  })

  it('does not consult the features probe when the pre-read found the document', async () => {
    // An update (current document readable) degrades to advisory on a
    // non-conditional backend by design; the probe must not even be consulted.
    const { context, calls } = contextWithStatuses()
    await upsertResource(context, {
      path: '/space/s/c/r',
      codec: conditionalCodec,
      id: 'r',
      data: { v: 1 },
      features: featureProbeFrom(async () => {
        throw new Error('features must not be consulted for an update')
      })
    })
    expect(calls.map(call => call.method)).toEqual(['GET', 'PUT'])
  })
})
