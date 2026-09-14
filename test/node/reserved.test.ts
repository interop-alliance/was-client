/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the reserved-path-segment guard. The client rejects ids that
 * collide with the spec's Reserved Path Segment Registry up front, with a clear
 * `ValidationError`, rather than letting the server answer `409 Conflict`.
 */
import { describe, it, expect } from 'vitest'

import {
  RESERVED_COLLECTION_IDS,
  RESERVED_RESOURCE_IDS
} from '@interop/storage-core'

import { ValidationError } from '../../src/index.js'
import { assertNotReserved } from '../../src/internal/reserved.js'
import {
  collectionPath,
  isReservedCollectionId,
  isReservedResourceId
} from '../../src/paths.js'

describe('assertNotReserved', () => {
  it('throws a ValidationError for a reserved collection id', () => {
    expect(() =>
      assertNotReserved({ id: 'export', kind: 'collection' })
    ).toThrow(ValidationError)
    expect(() =>
      assertNotReserved({ id: 'export', kind: 'collection' })
    ).toThrow(/reserved path segment "export" as a collection id/)
  })

  it('throws a ValidationError for a reserved resource id', () => {
    expect(() =>
      assertNotReserved({ id: 'backend', kind: 'resource' })
    ).toThrow(ValidationError)
    expect(() =>
      assertNotReserved({ id: 'backend', kind: 'resource' })
    ).toThrow(/reserved path segment "backend" as a resource id/)
  })

  it('rejects every segment in the collection registry', () => {
    for (const segment of RESERVED_COLLECTION_IDS) {
      expect(() =>
        assertNotReserved({ id: segment, kind: 'collection' })
      ).toThrow(ValidationError)
    }
  })

  it('rejects every segment in the resource registry', () => {
    for (const segment of RESERVED_RESOURCE_IDS) {
      expect(() =>
        assertNotReserved({ id: segment, kind: 'resource' })
      ).toThrow(ValidationError)
    }
  })

  it('splits reserved sets by kind to match the server', () => {
    // `export`/`collections` are reserved for collections but accepted for
    // resources; `backend` is reserved for resources but accepted for
    // collections; `import` is reserved for collections.
    expect(() =>
      assertNotReserved({ id: 'export', kind: 'resource' })
    ).not.toThrow()
    expect(() =>
      assertNotReserved({ id: 'collections', kind: 'resource' })
    ).not.toThrow()
    expect(() =>
      assertNotReserved({ id: 'backend', kind: 'collection' })
    ).not.toThrow()
    expect(() =>
      assertNotReserved({ id: 'import', kind: 'collection' })
    ).toThrow(ValidationError)
  })

  it('accepts an ordinary id', () => {
    expect(() =>
      assertNotReserved({ id: 'credentials', kind: 'collection' })
    ).not.toThrow()
    expect(() =>
      assertNotReserved({ id: 'greeting', kind: 'resource' })
    ).not.toThrow()
  })
})

describe('the ./paths subpath', () => {
  it('reports a reserved collection id through isReservedCollectionId', () => {
    expect(isReservedCollectionId('export')).toBe(true)
    expect(isReservedCollectionId('import')).toBe(true)
    expect(isReservedCollectionId('credentials')).toBe(false)
  })

  it('reports a reserved resource id through isReservedResourceId', () => {
    expect(isReservedResourceId('backend')).toBe(true)
    expect(isReservedResourceId('greeting')).toBe(false)
  })

  it('lets a caller refuse a segment the path builder would throw on', () => {
    // The predicate and the builder agree: what one reports reserved is what
    // the other refuses, so a caller can ask before forming a path out of a
    // value it did not choose.
    expect(isReservedCollectionId('export')).toBe(true)
    expect(() => collectionPath('space-1', 'export')).toThrow(ValidationError)
  })
})
