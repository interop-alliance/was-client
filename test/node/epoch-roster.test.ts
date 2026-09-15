/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the crypto-free descriptor predicates (`hasKeyEpochs`,
 * `epochRostersEqual`). They pin the two definitions consumers key their
 * open/refuse and cipher-rebuild decisions off: what counts as a usable epoch
 * roster, and what counts as the same epoch configuration -- in particular that
 * recipient churn inside an existing epoch and the `hmac` member are NOT part
 * of it.
 */
import { describe, it, expect } from 'vitest'

import {
  EDV_SCHEME_VERSION,
  hasKeyEpochs,
  epochRostersEqual
} from '../../src/edv/index.js'
import type {
  CollectionEncryption,
  CollectionEncryptionRecipient
} from '../../src/types.js'

function recipient(kid: string): CollectionEncryptionRecipient {
  return {
    header: { kid, alg: 'ECDH-ES+A256KW' },
    encrypted_key: 'ciphertext'
  }
}

function descriptor({
  currentEpoch,
  epochIds,
  recipientKids = ['did:key:zAlice#zAlice']
}: {
  currentEpoch?: unknown
  epochIds: string[]
  recipientKids?: string[]
}): CollectionEncryption {
  return {
    scheme: 'edv',
    version: 1,
    ...(currentEpoch !== undefined && {
      currentEpoch: currentEpoch as string
    }),
    epochs: epochIds.map(id => ({
      id,
      recipients: recipientKids.map(kid => recipient(kid))
    }))
  }
}

describe('hasKeyEpochs', () => {
  it('refuses an absent descriptor', () => {
    expect(hasKeyEpochs(undefined)).toBe(false)
  })

  it('refuses a descriptor with no currentEpoch', () => {
    expect(hasKeyEpochs(descriptor({ epochIds: ['epoch-1'] }))).toBe(false)
  })

  it('refuses a non-string currentEpoch', () => {
    expect(
      hasKeyEpochs(descriptor({ currentEpoch: 7, epochIds: ['epoch-1'] }))
    ).toBe(false)
  })

  it('refuses an empty or absent epochs list', () => {
    expect(
      hasKeyEpochs(descriptor({ currentEpoch: 'epoch-1', epochIds: [] }))
    ).toBe(false)
    expect(hasKeyEpochs({ scheme: 'edv', currentEpoch: 'epoch-1' })).toBe(false)
  })

  it('accepts a descriptor carrying both halves of a roster', () => {
    expect(
      hasKeyEpochs(
        descriptor({
          currentEpoch: 'epoch-2',
          epochIds: ['epoch-1', 'epoch-2']
        })
      )
    ).toBe(true)
  })
})

describe('epochRostersEqual', () => {
  it('reads two absent descriptors as equal', () => {
    expect(epochRostersEqual(undefined, undefined)).toBe(true)
  })

  it('reads an absent descriptor and a present one as different', () => {
    const present = descriptor({
      currentEpoch: 'epoch-1',
      epochIds: ['epoch-1']
    })
    expect(epochRostersEqual(undefined, present)).toBe(false)
    expect(epochRostersEqual(present, undefined)).toBe(false)
  })

  it('reads a differing currentEpoch as different', () => {
    expect(
      epochRostersEqual(
        descriptor({
          currentEpoch: 'epoch-1',
          epochIds: ['epoch-1', 'epoch-2']
        }),
        descriptor({
          currentEpoch: 'epoch-2',
          epochIds: ['epoch-1', 'epoch-2']
        })
      )
    ).toBe(false)
  })

  it('reads a differing epoch-id order as different', () => {
    expect(
      epochRostersEqual(
        descriptor({
          currentEpoch: 'epoch-1',
          epochIds: ['epoch-1', 'epoch-2']
        }),
        descriptor({
          currentEpoch: 'epoch-1',
          epochIds: ['epoch-2', 'epoch-1']
        })
      )
    ).toBe(false)
  })

  it('reads a differing epoch count as different', () => {
    expect(
      epochRostersEqual(
        descriptor({ currentEpoch: 'epoch-1', epochIds: ['epoch-1'] }),
        descriptor({
          currentEpoch: 'epoch-1',
          epochIds: ['epoch-1', 'epoch-2']
        })
      )
    ).toBe(false)
  })

  it('reads a differing version as different', () => {
    const currentEpoch = 'epoch-1'
    const epochIds = ['epoch-1']
    expect(
      epochRostersEqual(
        { ...descriptor({ currentEpoch, epochIds }), version: 2 },
        descriptor({ currentEpoch, epochIds })
      )
    ).toBe(false)
    expect(
      epochRostersEqual(
        { ...descriptor({ currentEpoch, epochIds }), version: 2 },
        { ...descriptor({ currentEpoch, epochIds }), version: undefined }
      )
    ).toBe(false)
  })

  it('reads an absent version as EDV_SCHEME_VERSION', () => {
    const currentEpoch = 'epoch-1'
    const epochIds = ['epoch-1']
    expect(
      epochRostersEqual(
        { ...descriptor({ currentEpoch, epochIds }), version: undefined },
        {
          ...descriptor({ currentEpoch, epochIds }),
          version: EDV_SCHEME_VERSION
        }
      )
    ).toBe(true)
  })

  it('reads a differing scheme as different', () => {
    const currentEpoch = 'epoch-1'
    const epochIds = ['epoch-1']
    const other = {
      ...descriptor({ currentEpoch, epochIds }),
      scheme: 'other'
    } as unknown as CollectionEncryption
    expect(
      epochRostersEqual(descriptor({ currentEpoch, epochIds }), other)
    ).toBe(false)
  })

  it('reads the same configuration with a different hmac member as equal', () => {
    const currentEpoch = 'epoch-1'
    const epochIds = ['epoch-1']
    const hmac = (kid: string) => ({
      id: 'urn:hmac',
      type: 'Sha256HmacKey2019',
      recipients: [recipient(kid)]
    })
    expect(
      epochRostersEqual(
        { ...descriptor({ currentEpoch, epochIds }), hmac: hmac('did:key:zA') },
        { ...descriptor({ currentEpoch, epochIds }), hmac: hmac('did:key:zB') }
      )
    ).toBe(true)
  })

  it('reads the same roster with different recipients as equal', () => {
    expect(
      epochRostersEqual(
        descriptor({
          currentEpoch: 'epoch-2',
          epochIds: ['epoch-1', 'epoch-2'],
          recipientKids: ['did:key:zAlice#zAlice']
        }),
        descriptor({
          currentEpoch: 'epoch-2',
          epochIds: ['epoch-1', 'epoch-2'],
          recipientKids: ['did:key:zAlice#zAlice', 'did:key:zBob#zBob']
        })
      )
    ).toBe(true)
  })

  it('reads an identical roster as equal', () => {
    const currentEpoch = 'epoch-2'
    const epochIds = ['epoch-1', 'epoch-2']
    expect(
      epochRostersEqual(
        descriptor({ currentEpoch, epochIds }),
        descriptor({ currentEpoch, epochIds })
      )
    ).toBe(true)
  })
})
