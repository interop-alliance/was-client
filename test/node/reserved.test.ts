/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the reserved-path-segment guard. The client rejects ids that
 * collide with the spec's Reserved Path Segment Registry up front, with a clear
 * `ValidationError`, rather than letting the server answer `409 Conflict`.
 */
import { describe, it, expect } from 'vitest'

import { ValidationError } from '../../src/index.js'
import {
  RESERVED_SEGMENTS,
  assertNotReserved
} from '../../src/internal/reserved.js'

describe('assertNotReserved', () => {
  it('throws a ValidationError for a reserved collection id', () => {
    expect(() => assertNotReserved('policy', 'collection')).toThrow(
      ValidationError
    )
    expect(() => assertNotReserved('policy', 'collection')).toThrow(
      /reserved path segment "policy" as a collection id/
    )
  })

  it('throws a ValidationError for a reserved resource id', () => {
    expect(() => assertNotReserved('meta', 'resource')).toThrow(ValidationError)
    expect(() => assertNotReserved('meta', 'resource')).toThrow(
      /reserved path segment "meta" as a resource id/
    )
  })

  it('rejects every segment in the registry', () => {
    for (const segment of RESERVED_SEGMENTS) {
      expect(() => assertNotReserved(segment, 'collection')).toThrow(
        ValidationError
      )
    }
  })

  it('accepts an ordinary id', () => {
    expect(() => assertNotReserved('credentials', 'collection')).not.toThrow()
    expect(() => assertNotReserved('greeting', 'resource')).not.toThrow()
  })
})
