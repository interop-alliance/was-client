/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the `custom` normalization `asCollectionMetadata` applies on
 * read. An absent, `null`, or empty stored `custom` all mean "cleared" on the
 * wire, so a reader sees one answer -- no `custom` member -- instead of three.
 */
import { describe, it, expect } from 'vitest'

import { asCollectionMetadata } from '../../src/internal/describe.js'

describe('asCollectionMetadata', () => {
  it('drops a stored `custom` of null', () => {
    const read = asCollectionMetadata({
      id: 'credentials',
      type: ['Collection'],
      custom: null
    })
    expect('custom' in read).toBe(false)
    expect(read.id).toBe('credentials')
  })

  it('drops an empty stored `custom`', () => {
    const read = asCollectionMetadata({
      id: 'credentials',
      type: ['Collection'],
      custom: {}
    })
    expect('custom' in read).toBe(false)
  })

  it('leaves a `custom` carrying members as served', () => {
    const custom = { label: 'Credentials' }
    const read = asCollectionMetadata({ id: 'credentials', custom })
    expect(read.custom).toBe(custom)
  })

  it('leaves an opaque envelope as served', () => {
    const custom = { jwe: { ciphertext: 'abc' } }
    const read = asCollectionMetadata({ id: 'credentials', custom })
    expect(read.custom).toEqual(custom)
  })

  it('keeps every other member, `custom` absent already', () => {
    const stored = {
      id: 'credentials',
      type: ['Collection'],
      name: 'Credentials',
      encryption: { type: 'edv' },
      plaintext: true
    }
    expect(asCollectionMetadata(stored)).toEqual(stored)
  })

  it('does not modify the stored object a write composes from', () => {
    const stored = { id: 'credentials', custom: {} }
    asCollectionMetadata(stored)
    expect(stored.custom).toEqual({})
  })
})
