/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for `mapError`, which translates a thrown ky/ezcap error into the
 * appropriate `WasError` subclass and carries through the server's
 * `application/problem+json` fields.
 */
import { describe, it, expect } from 'vitest'

import {
  WasError,
  NotFoundError,
  ValidationError,
  AuthRequiredError,
  NotImplementedError,
  ConflictError,
  PreconditionFailedError,
  PayloadTooLargeError,
  QuotaExceededError,
  WasServerError
} from '../../src/index.js'
import { mapError } from '../../src/errors.js'

describe('mapError', () => {
  it('maps 400 to ValidationError', () => {
    expect(mapError({ status: 400 })).toBeInstanceOf(ValidationError)
  })

  it('maps 401 to AuthRequiredError', () => {
    expect(mapError({ status: 401 })).toBeInstanceOf(AuthRequiredError)
  })

  it('maps 404 to NotFoundError', () => {
    expect(mapError({ status: 404 })).toBeInstanceOf(NotFoundError)
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
    const typeUri = (kind: string): string =>
      `https://wallet.storage/spec#${kind}`

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
  })

  it('preserves the original error as the cause', () => {
    const original = { status: 500, message: 'boom' }
    expect(mapError(original).cause).toBe(original)
  })
})
