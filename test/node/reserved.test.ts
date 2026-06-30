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
  RESERVED_COLLECTION_IDS,
  RESERVED_RESOURCE_IDS,
  assertNotReserved
} from '../../src/internal/reserved.js'

describe('assertNotReserved', () => {
  it('throws a ValidationError for a reserved collection id', () => {
    expect(() => assertNotReserved('export', 'collection')).toThrow(
      ValidationError
    )
    expect(() => assertNotReserved('export', 'collection')).toThrow(
      /reserved path segment "export" as a collection id/
    )
  })

  it('throws a ValidationError for a reserved resource id', () => {
    expect(() => assertNotReserved('backend', 'resource')).toThrow(
      ValidationError
    )
    expect(() => assertNotReserved('backend', 'resource')).toThrow(
      /reserved path segment "backend" as a resource id/
    )
  })

  it('rejects every segment in the collection registry', () => {
    for (const segment of RESERVED_COLLECTION_IDS) {
      expect(() => assertNotReserved(segment, 'collection')).toThrow(
        ValidationError
      )
    }
  })

  it('rejects every segment in the resource registry', () => {
    for (const segment of RESERVED_RESOURCE_IDS) {
      expect(() => assertNotReserved(segment, 'resource')).toThrow(
        ValidationError
      )
    }
  })

  it('splits reserved sets by kind to match the server', () => {
    // `export`/`collections` are reserved for collections but accepted for
    // resources; `backend` is reserved for resources but accepted for
    // collections; `import` is reserved for collections.
    expect(() => assertNotReserved('export', 'resource')).not.toThrow()
    expect(() => assertNotReserved('collections', 'resource')).not.toThrow()
    expect(() => assertNotReserved('backend', 'collection')).not.toThrow()
    expect(() => assertNotReserved('import', 'collection')).toThrow(
      ValidationError
    )
  })

  it('accepts an ordinary id', () => {
    expect(() => assertNotReserved('credentials', 'collection')).not.toThrow()
    expect(() => assertNotReserved('greeting', 'resource')).not.toThrow()
  })
})
