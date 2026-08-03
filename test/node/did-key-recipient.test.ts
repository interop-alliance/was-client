/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the recipient-derivation rule (`x25519RecipientFromDidKey`):
 * a grantee's decryption key is derived from the `did:key` its capability
 * request already names as `controller`, rather than accepted on the wire.
 * These pin the two properties that makes load-bearing: the derivation matches
 * what the grantee itself derives from the same key material (so the epoch
 * roster entry's `kid` matches), and anything that is not an Ed25519 did:key is
 * refused.
 */
import { describe, it, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'

import {
  isEd25519DidKey,
  x25519RecipientFromDidKey
} from '../../src/edv/index.js'
import { didKeyResolver } from '../../src/edv/epochCrypto.js'

describe('isEd25519DidKey', () => {
  it('accepts an Ed25519 did:key DID', async () => {
    const keyPair = await Ed25519VerificationKey.generate()
    const did = `did:key:${keyPair.publicKeyMultibase}`
    expect(isEd25519DidKey(did)).toBe(true)
  })

  it('refuses a non-did:key DID, a non-Ed25519 did:key, and a key id', () => {
    expect(isEd25519DidKey('did:web:app.example')).toBe(false)
    // z6LS... is an X25519 did:key -- no Ed25519 signing key behind it.
    expect(
      isEd25519DidKey(
        'did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
      )
    ).toBe(false)
    expect(isEd25519DidKey('did:key:z6MkAbc#z6LSdef')).toBe(false)
    expect(isEd25519DidKey(undefined)).toBe(false)
    expect(isEd25519DidKey('')).toBe(false)
  })
})

describe('x25519RecipientFromDidKey', () => {
  it('derives the same key-agreement key the DID holder derives', async () => {
    const keyPair = await Ed25519VerificationKey.generate()
    const did = `did:key:${keyPair.publicKeyMultibase}`
    keyPair.controller = did
    // What the grantee computes on its own side, holding the private key.
    const own = X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair
    })

    const recipient = x25519RecipientFromDidKey({ did })

    expect(recipient.id).toBe(own.id)
    expect(recipient.publicKeyMultibase).toBe(own.publicKeyMultibase)
    expect(recipient.type).toBe('X25519KeyAgreementKey2020')
    // The recipient id is a fragment on the controller DID itself, so it
    // resolves through the default did:key recipient resolver.
    expect(recipient.id).toBe(`${did}#${own.publicKeyMultibase}`)
  })

  it('derives an id the did:key recipient resolver resolves', async () => {
    const keyPair = await Ed25519VerificationKey.generate()
    const recipient = x25519RecipientFromDidKey({
      did: `did:key:${keyPair.publicKeyMultibase}`
    })
    const resolved = await didKeyResolver({ id: recipient.id })
    expect(resolved.publicKeyMultibase).toBe(recipient.publicKeyMultibase)
    expect(resolved.type).toBe('X25519KeyAgreementKey2020')
  })

  it('is deterministic: the same DID always derives the same recipient', () => {
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    expect(x25519RecipientFromDidKey({ did })).toEqual(
      x25519RecipientFromDidKey({ did })
    )
  })

  it('refuses a DID with no Ed25519 twin', () => {
    expect(() =>
      x25519RecipientFromDidKey({ did: 'did:web:app.example' })
    ).toThrow(/not an Ed25519 did:key/)
    expect(() =>
      x25519RecipientFromDidKey({
        did: 'did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
      })
    ).toThrow(/not an Ed25519 did:key/)
  })

  it('refuses a key id (a DID with a fragment)', () => {
    const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    expect(() =>
      x25519RecipientFromDidKey({
        did: `${did}#${did.slice('did:key:'.length)}`
      })
    ).toThrow(/not an Ed25519 did:key/)
  })
})
