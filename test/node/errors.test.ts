/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `mapError`, which translates a thrown ky/ezcap error into the
 * appropriate `WasError` subclass and carries through the server's
 * `application/problem+json` fields.
 */
import { describe, it, expect } from 'vitest'
import { ProblemTypes } from '@interop/storage-core'

import {
  WasError,
  NotFoundError,
  CapabilityRevokedError,
  CapabilityExpiredError,
  AlreadyRevokedError,
  ValidationError,
  AuthRequiredError,
  NotImplementedError,
  ConflictError,
  PreconditionFailedError,
  PayloadTooLargeError,
  QuotaExceededError,
  WasServerError,
  WasSyncAuthError,
  WasSyncCheckpointError,
  WasSyncConflictError,
  WasSyncNotFoundError,
  httpStatus
} from '../../src/index.js'
import { mapError, UnknownEpochError } from '../../src/errors.js'

describe('mapError', () => {
  it('maps 400 to ValidationError', () => {
    expect(mapError({ status: 400 })).toBeInstanceOf(ValidationError)
  })

  it('maps 401 to AuthRequiredError', () => {
    expect(mapError({ status: 401 })).toBeInstanceOf(AuthRequiredError)
  })

  it('maps 403 to AuthRequiredError (authenticated but forbidden)', () => {
    expect(mapError({ status: 403 })).toBeInstanceOf(AuthRequiredError)
  })

  it('maps 404 to NotFoundError', () => {
    expect(mapError({ status: 404 })).toBeInstanceOf(NotFoundError)
  })

  it('maps 415 to ValidationError', () => {
    expect(mapError({ status: 415 })).toBeInstanceOf(ValidationError)
  })

  it('maps 501 to NotImplementedError', () => {
    expect(mapError({ status: 501 })).toBeInstanceOf(NotImplementedError)
  })

  it('maps any other 5xx to WasServerError', () => {
    expect(mapError({ status: 500 })).toBeInstanceOf(WasServerError)
    expect(mapError({ status: 503 })).toBeInstanceOf(WasServerError)
  })

  it('maps 409 to ConflictError', () => {
    expect(mapError({ status: 409 })).toBeInstanceOf(ConflictError)
  })

  it('maps 412 to PreconditionFailedError (distinct from 409)', () => {
    const mapped = mapError({ status: 412 })
    expect(mapped).toBeInstanceOf(PreconditionFailedError)
    expect(mapped).not.toBeInstanceOf(ConflictError)
  })

  it('maps 413 to PayloadTooLargeError', () => {
    expect(mapError({ status: 413 })).toBeInstanceOf(PayloadTooLargeError)
  })

  it('maps 507 to QuotaExceededError', () => {
    expect(mapError({ status: 507 })).toBeInstanceOf(QuotaExceededError)
  })

  describe('problem-type (data.type) dispatch', () => {
    const typeUri = (kind: string): string => `https://w3id.org/pws#${kind}`

    it('dispatches quota-exceeded to QuotaExceededError', () => {
      expect(
        mapError({ status: 507, data: { type: typeUri('quota-exceeded') } })
      ).toBeInstanceOf(QuotaExceededError)
    })

    it('dispatches payload-too-large to PayloadTooLargeError', () => {
      expect(
        mapError({ status: 413, data: { type: typeUri('payload-too-large') } })
      ).toBeInstanceOf(PayloadTooLargeError)
    })

    it('dispatches the 409 conflict kinds to ConflictError', () => {
      for (const kind of [
        'id-conflict',
        'reserved-id',
        'unsupported-backend'
      ]) {
        expect(
          mapError({ status: 409, data: { type: typeUri(kind) } })
        ).toBeInstanceOf(ConflictError)
      }
    })

    it('distinguishes invalid-authorization-header (400) as a ValidationError', () => {
      const mapped = mapError({
        status: 400,
        data: { type: typeUri('invalid-authorization-header') }
      })
      expect(mapped).toBeInstanceOf(ValidationError)
    })

    it('dispatches missing-authorization to AuthRequiredError', () => {
      expect(
        mapError({
          status: 401,
          data: { type: typeUri('missing-authorization') }
        })
      ).toBeInstanceOf(AuthRequiredError)
    })

    it('dispatches unsupported-operation to NotImplementedError', () => {
      expect(
        mapError({ data: { type: typeUri('unsupported-operation') } })
      ).toBeInstanceOf(NotImplementedError)
    })

    it('dispatches precondition-failed to PreconditionFailedError', () => {
      expect(
        mapError({
          status: 412,
          data: { type: typeUri('precondition-failed') }
        })
      ).toBeInstanceOf(PreconditionFailedError)
    })

    it('exposes the raw type URI on the error', () => {
      const mapped = mapError({
        status: 507,
        data: { type: typeUri('quota-exceeded') }
      })
      expect(mapped.type).toBe(typeUri('quota-exceeded'))
    })

    it('dispatches capability-revoked to CapabilityRevokedError, a NotFoundError by name', () => {
      const mapped = mapError({
        status: 404,
        data: { type: typeUri('capability-revoked') }
      })
      expect(mapped).toBeInstanceOf(CapabilityRevokedError)
      expect(mapped).toBeInstanceOf(NotFoundError)
      expect(mapped.name).toBe('CapabilityRevokedError')
    })

    it('dispatches capability-expired to CapabilityExpiredError, a NotFoundError by name', () => {
      const mapped = mapError({
        status: 404,
        data: { type: typeUri('capability-expired') }
      })
      expect(mapped).toBeInstanceOf(CapabilityExpiredError)
      expect(mapped).toBeInstanceOf(NotFoundError)
      expect(mapped.name).toBe('CapabilityExpiredError')
    })

    it('dispatches capability-already-revoked to AlreadyRevokedError, a ValidationError by name', () => {
      const mapped = mapError({
        status: 400,
        data: { type: typeUri('capability-already-revoked') }
      })
      expect(mapped).toBeInstanceOf(AlreadyRevokedError)
      expect(mapped).toBeInstanceOf(ValidationError)
      expect(mapped.name).toBe('AlreadyRevokedError')
    })

    it('keeps an invalid-request-body 400 a ValidationError named ValidationError', () => {
      const mapped = mapError({
        status: 400,
        data: { type: typeUri('invalid-request-body') }
      })
      expect(mapped).toBeInstanceOf(ValidationError)
      expect(mapped.name).toBe('ValidationError')
    })

    it('keeps a plain not-found 404 a NotFoundError named NotFoundError', () => {
      const mapped = mapError({
        status: 404,
        data: { type: typeUri('not-found') }
      })
      expect(mapped.name).toBe('NotFoundError')
    })

    it('resolves every ProblemTypes URI through the type map alone', () => {
      for (const type of Object.values(ProblemTypes)) {
        const withoutStatus = mapError({ data: { type } })
        const unmappedStatus = mapError({ status: 418, data: { type } })
        expect(withoutStatus.constructor, type).not.toBe(WasError)
        expect(unmappedStatus.constructor, type).not.toBe(WasError)
      }
    })

    it('dispatches the immutable and replica 409 kinds to ConflictError', () => {
      for (const kind of [
        'replica-refused',
        'revisions-immutable',
        'resource-immutable'
      ]) {
        expect(
          mapError({ status: 409, data: { type: typeUri(kind) } })
        ).toBeInstanceOf(ConflictError)
      }
    })

    it('dispatches encryption-scheme-mismatch (422) to ValidationError', () => {
      expect(
        mapError({
          status: 422,
          data: { type: typeUri('encryption-scheme-mismatch') }
        })
      ).toBeInstanceOf(ValidationError)
    })

    it('does not resolve inherited object properties as problem kinds', () => {
      for (const kind of ['constructor', 'toString', '__proto__']) {
        const mapped = mapError({
          status: 412,
          data: { type: `https://example/x#${kind}` }
        })
        expect(mapped).toBeInstanceOf(PreconditionFailedError)
      }
    })

    it('ignores a known fragment under a foreign namespace', () => {
      const mapped = mapError({
        status: 400,
        data: { type: 'https://evil.example/pws#quota-exceeded' }
      })
      expect(mapped).toBeInstanceOf(ValidationError)
      expect(mapped).not.toBeInstanceOf(QuotaExceededError)
    })

    it('names the problem kind in the message when there is no title', () => {
      const mapped = mapError({
        status: 422,
        data: { type: typeUri('encryption-scheme-mismatch') }
      })
      expect(mapped.message).toBe(
        'WAS request failed (encryption-scheme-mismatch)'
      )
    })

    it('falls back to status when the type kind is unrecognized', () => {
      const mapped = mapError({
        status: 404,
        data: { type: typeUri('some-future-kind') }
      })
      expect(mapped).toBeInstanceOf(NotFoundError)
    })
  })

  it('reads the status from a nested response object', () => {
    expect(mapError({ response: { status: 404 } })).toBeInstanceOf(
      NotFoundError
    )
  })

  it('falls back to the base WasError for an unrecognized status', () => {
    const mapped = mapError({ status: 418 })
    expect(mapped).toBeInstanceOf(WasError)
    expect(mapped).not.toBeInstanceOf(NotFoundError)
  })

  it('returns a WasError unchanged (idempotent)', () => {
    const original = new NotFoundError('already typed')
    expect(mapError(original)).toBe(original)
  })

  it('carries through the problem+json fields', () => {
    const mapped = mapError({
      status: 400,
      requestUrl: 'https://was.example/spaces/',
      data: {
        title: 'Invalid space description',
        errors: [{ detail: 'name is required' }, { detail: 'bad controller' }]
      }
    })
    expect(mapped.message).toBe('Invalid space description')
    expect(mapped.title).toBe('Invalid space description')
    expect(mapped.status).toBe(400)
    expect(mapped.requestUrl).toBe('https://was.example/spaces/')
    expect(mapped.details).toEqual(['name is required', 'bad controller'])
    expect(mapped.problems).toEqual([
      { detail: 'name is required' },
      { detail: 'bad controller' }
    ])
  })

  it('carries each problem entry with its JSON pointer', () => {
    const mapped = mapError({
      status: 400,
      data: {
        type: 'https://w3id.org/pws#invalid-request-body',
        title: 'Invalid query body',
        errors: [
          {
            detail: 'The checkpoint was not issued here.',
            pointer: '#/checkpoint'
          },
          { detail: 'no pointer' },
          { detail: 'bad pointer', pointer: 42 }
        ]
      }
    })
    expect(mapped.problems).toEqual([
      {
        detail: 'The checkpoint was not issued here.',
        pointer: '#/checkpoint'
      },
      { detail: 'no pointer' },
      { detail: 'bad pointer' }
    ])
    expect(mapped.details).toEqual([
      'The checkpoint was not issued here.',
      'no pointer',
      'bad pointer'
    ])
  })

  it('tolerates a non-array `errors` field without masking the real error', () => {
    // A non-conformant body with `errors` as a string is truthy, so a bare
    // `?.map` would throw a `TypeError` and replace the intended subclass.
    const mapped = mapError({
      status: 400,
      data: { title: 'Bad request', errors: 'boom' }
    })
    expect(mapped).toBeInstanceOf(ValidationError)
    expect(mapped.message).toBe('Bad request')
    expect(mapped.details).toBeUndefined()
    expect(mapped.problems).toBeUndefined()
  })

  it('tolerates malformed `errors` entries without masking the real error', () => {
    // Each entry is unvalidated server JSON: a `null` or primitive entry must
    // not make `mapError` itself throw a `TypeError` on `.detail`.
    const mapped = mapError({
      status: 409,
      data: {
        title: 'Conflict',
        errors: [null, 'boom', 42, { detail: 'id already exists' }]
      }
    })
    expect(mapped).toBeInstanceOf(ConflictError)
    expect(mapped.details).toEqual(['id already exists'])
    expect(mapped.problems).toEqual([{ detail: 'id already exists' }])
  })

  it('maps 422 to ValidationError', () => {
    expect(mapError({ status: 422 })).toBeInstanceOf(ValidationError)
  })

  it('strips control characters from and caps the title', () => {
    const mapped = mapError({
      status: 400,
      data: { title: 'bad\u0007 req\u001b[31muest' }
    })
    expect(mapped.title).toBe('bad req[31muest')
    expect(mapped.message).toBe('bad req[31muest')

    const long = mapError({ status: 400, data: { title: 'x'.repeat(5000) } })
    expect(long.title).toHaveLength(1024)
    expect(long.message).toHaveLength(1024)
  })

  it('strips control characters from and caps each detail and pointer', () => {
    const mapped = mapError({
      status: 400,
      data: {
        errors: [
          { detail: 'a\u0007b\u009bc', pointer: '#/x\u001b' },
          { detail: 'y'.repeat(5000) }
        ]
      }
    })
    expect(mapped.problems?.[0]).toEqual({ detail: 'abc', pointer: '#/x' })
    expect(mapped.details?.[1]).toHaveLength(1024)
  })

  it('drops a non-string type or title', () => {
    const mapped = mapError({
      status: 400,
      data: { type: 12345, title: { nested: true } }
    })
    expect(mapped).toBeInstanceOf(ValidationError)
    expect(mapped.type).toBeUndefined()
    expect(mapped.title).toBeUndefined()
    expect(mapped.message).not.toContain('[object Object]')
    expect(mapped.message).not.toContain('12345')
  })

  it('preserves the original error as the cause', () => {
    const original = { status: 500, message: 'boom' }
    expect(mapError(original).cause).toBe(original)
  })
})

describe('httpStatus', () => {
  it('reads a flat `status`', () => {
    expect(httpStatus({ status: 404 })).toBe(404)
  })

  it('reads a nested `response.status`', () => {
    expect(httpStatus({ response: { status: 412 } })).toBe(412)
  })

  it('returns undefined for a value carrying no status', () => {
    expect(httpStatus(new Error('boom'))).toBeUndefined()
    expect(httpStatus(undefined)).toBeUndefined()
  })
})

describe('sync error constructors', () => {
  it('keep their default status when passed `status: undefined`', () => {
    expect(new WasSyncConflictError('m', { status: undefined }).status).toBe(
      412
    )
    expect(new WasSyncNotFoundError('m', { status: undefined }).status).toBe(
      404
    )
    expect(new WasSyncAuthError(403, { status: undefined }).status).toBe(403)
    expect(new WasSyncCheckpointError('m', { status: undefined }).status).toBe(
      400
    )
  })
})

describe('UnknownEpochError', () => {
  it('strips control characters from the key ids in its message', () => {
    const err = new UnknownEpochError({
      collectionId: 'notes',
      kids: ['did:key:z6Mk\u001b[2Jabc', 'did:key:z6Mk\u0007def']
    })
    expect(err.message).not.toContain('\u001b')
    expect(err.message).not.toContain('\u0007')
    expect(err.message).toContain('did:key:z6Mk[2Jabc, did:key:z6Mkdef')
  })

  it('caps the joined key ids in its message', () => {
    const err = new UnknownEpochError({
      collectionId: 'notes',
      kids: ['k'.repeat(5000)]
    })
    expect(err.message).toContain(`[${'k'.repeat(1024)}]`)
    expect(err.message).not.toContain('k'.repeat(1025))
  })
})
