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

  it('preserves the original error as the cause', () => {
    const original = { status: 500, message: 'boom' }
    expect(mapError(original).cause).toBe(original)
  })
})
