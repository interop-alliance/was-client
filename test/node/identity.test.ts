/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The WAS identity derivation (`./identity`). The fixture values are
 * byte-critical: they were captured from the wallet apps' original derivation
 * (DCW `agentsFromSecret`, Freewallet `agentsFromSeed`) and carried through
 * `@interop/wallet-core/identity` to here, so these tests pin the exact keys
 * every existing account derives through. If any fixture here changes,
 * existing accounts are stranded -- that is a bug in the change, not in the
 * test. `@interop/wallet-core` runs the same fixture against this subpath.
 */
import { describe, it, expect, beforeAll } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'

import {
  BOOTSTRAP_HANDLE,
  BOOTSTRAP_KEY_NAME,
  agentsFromSecret,
  agentsFromSeed,
  singleKeyResolver
} from '../../src/identity/index.js'
import type { ProfileAgents } from '../../src/identity/index.js'
import { ValidationError } from '../../src/errors.js'

const SECRET = 'test-passphrase'
// The app-captured fixture for the string-secret path (DCW profiles).
const SECRET_DID = 'did:key:z6MkjpXcSL52t3j5hzooU2hKaXMCGbhnPBX9cZ1gM1wbiPNE'
const SECRET_KAK_PUB = 'z6LSipWZB2yondq7hes32riaFotVTxH4NiN7Joi7aBCSLmCf'

// seed = bytes 0..31; the app-captured fixture for the seed path (Freewallet
// keyring / guest sessions).
const SEED = new Uint8Array(32).map((_, i) => i)
const SEED_DID = 'did:key:z6Mkff8vLZrPzRgQmV5EQ1zaruuKy6funtwQumLUSrvQc7sp'
const SEED_KAK_PUB = 'z6LSfPNtHH7mnNdAPtVDdeUBp8m5VZT7ywgtdUaJGxtK725h'

describe('bootstrap constants', () => {
  it('pins the load-bearing handle and (typo included) key name', () => {
    expect(BOOTSTRAP_HANDLE).toBe('bootstrap')
    expect(BOOTSTRAP_KEY_NAME).toBe('boostrap-key')
  })
})

describe('agentsFromSecret', () => {
  let agents: ProfileAgents
  beforeAll(async () => {
    agents = await agentsFromSecret({ secret: SECRET })
  })

  it('derives the app-fixture identity from a string secret', () => {
    expect(agents.controllerDid).toBe(SECRET_DID)
    expect(agents.keyAgent.id).toBe(SECRET_DID)
    expect(agents.keyAgreementKey.id).toBe(`${SECRET_DID}#${SECRET_KAK_PUB}`)
  })

  it('is deterministic across calls', async () => {
    const again = await agentsFromSecret({ secret: SECRET })
    expect(again.controllerDid).toBe(agents.controllerDid)
    expect(again.keyAgreementKey.id).toBe(agents.keyAgreementKey.id)
  })

  it('matches seedFromSecret + agentsFromSeed (the stored-seed path)', async () => {
    const seed = await CapabilityAgent.seedFromSecret({
      secret: SECRET,
      handle: BOOTSTRAP_HANDLE
    })
    const fromSeed = await agentsFromSeed({ seed })
    expect(fromSeed.controllerDid).toBe(SECRET_DID)
    expect(fromSeed.keyAgreementKey.id).toBe(`${SECRET_DID}#${SECRET_KAK_PUB}`)
  })
})

describe('agentsFromSeed', () => {
  let agents: ProfileAgents
  beforeAll(async () => {
    agents = await agentsFromSeed({ seed: SEED })
  })

  it('derives the app-fixture identity from a 32-byte seed', () => {
    expect(agents.controllerDid).toBe(SEED_DID)
    expect(agents.keyAgreementKey.id).toBe(`${SEED_DID}#${SEED_KAK_PUB}`)
  })

  it('does NOT equal hashing the seed as a secret (fromSeed skips the salted hash)', async () => {
    const viaSecret = await agentsFromSecret({
      secret: new TextDecoder().decode(SEED)
    })
    expect(viaSecret.controllerDid).not.toBe(agents.controllerDid)
  })

  it('rejects a seed that is not 32 bytes', async () => {
    await expect(agentsFromSeed({ seed: SEED.slice(0, 16) })).rejects.toThrow(
      ValidationError
    )
    await expect(agentsFromSeed({ seed: new Uint8Array(64) })).rejects.toThrow(
      'Expected a 32-byte seed, got 64 bytes.'
    )
  })
})

describe('derived agents shape', () => {
  let agents: ProfileAgents
  beforeAll(async () => {
    agents = await agentsFromSecret({ secret: SECRET })
  })

  it('wires the ZcapClient with the bootstrap signer for invocation and delegation', () => {
    const signer = agents.keyAgent.getSigner()
    expect(signer.id.startsWith(`${SECRET_DID}#`)).toBe(true)
    const zcap = agents.zcapClient as unknown as {
      invocationSigner: { id: string }
      delegationSigner: { id: string }
    }
    expect(zcap.invocationSigner.id).toBe(signer.id)
    expect(zcap.delegationSigner.id).toBe(signer.id)
  })

  it('resolves its own KAK through the bundled keyResolver and rejects others', async () => {
    const resolved = await agents.keyResolver({
      id: agents.keyAgreementKey.id
    })
    expect(resolved).toEqual({
      id: agents.keyAgreementKey.id,
      type: 'X25519KeyAgreementKey2020',
      publicKeyMultibase: SECRET_KAK_PUB
    })
    await expect(
      agents.keyResolver({ id: 'did:key:other#key' })
    ).rejects.toThrow('Unknown key id')
  })
})

describe('singleKeyResolver', () => {
  const keyAgreementKey = {
    id: 'did:key:zTest#zKak',
    type: 'X25519KeyAgreementKey2020',
    publicKeyMultibase: 'zKak'
  }

  it('resolves exactly the supplied key', async () => {
    const resolve = singleKeyResolver({ keyAgreementKey })
    expect(await resolve({ id: keyAgreementKey.id })).toEqual(keyAgreementKey)
  })

  it('throws for any other id, including undefined', async () => {
    const resolve = singleKeyResolver({ keyAgreementKey })
    await expect(resolve({ id: 'did:key:zOther#zKey' })).rejects.toThrow(
      'Unknown key id "did:key:zOther#zKey".'
    )
    await expect(resolve({})).rejects.toThrow('Unknown key id')
  })

  it('does not match an undefined id against an id-less key', async () => {
    const resolve = singleKeyResolver({
      keyAgreementKey: { type: keyAgreementKey.type }
    })
    await expect(resolve({})).rejects.toThrow('Unknown key id')
  })
})
