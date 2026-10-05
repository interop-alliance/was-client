/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: `ensureSpace` and `ensureSpaceAndCollection` against a live
 * WAS server. The fakes tier covers the two halves separately, each against a
 * hand-written description. This suite pins what no fake can assert: a served
 * Space description carries `id`, so the description `ensureSpace` returns can
 * be handed straight to `ensureSpaceAndCollection`, on the first pass and on
 * the already-provisioned second pass alike.
 *
 * Requires a running server: `TEST_SERVER_URL`, which the global setup sets
 * when it boots one in-process.
 */
import { describe, it, beforeAll, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient } from '../../src/index.js'
import { ensureSpace, ensureSpaceAndCollection } from '../../src/sync/index.js'
import { EDV_SCHEME_VERSION } from '../../src/edv/constants.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

describeLive('sync provisioning (live server)', () => {
  let was: WasClient
  let spaceId: string

  beforeAll(async () => {
    const keyPair = await Ed25519VerificationKey.generate()
    was = WasClient.fromSigner({
      serverUrl: serverUrl!,
      signer: keyPair.didKeySigner()
    })
    spaceId = crypto.randomUUID()
  })

  it('ensureSpace creates the Space and returns the served description with its id', async () => {
    const description = await ensureSpace({
      was,
      spaceId,
      controllerDid: was.controllerDid,
      spaceName: 'Provisioning Integration'
    })
    expect(description.id).toBe(spaceId)
    expect(description.controller).toBe(was.controllerDid)
    expect(description.name).toBe('Provisioning Integration')

    const served = await was.space(spaceId).describe()
    expect(served).toEqual(description)
  })

  it('ensureSpace on the existing Space returns the same served description', async () => {
    const description = await ensureSpace({
      was,
      spaceId,
      controllerDid: was.controllerDid,
      spaceName: 'A name the existing Space keeps ignoring'
    })
    expect(description.id).toBe(spaceId)
    expect(description.name).toBe('Provisioning Integration')
  })

  it('ensureSpaceAndCollection accepts the description ensureSpace returned', async () => {
    const spaceDescription = await ensureSpace({
      was,
      spaceId,
      controllerDid: was.controllerDid
    })
    const first = await ensureSpaceAndCollection({
      was,
      spaceId,
      controllerDid: was.controllerDid,
      collectionId: 'vault',
      spaceDescription
    })
    expect(first).toEqual({ created: true })

    const vault = await was.space(spaceId).collection('vault').describe()
    expect(vault?.encryption).toMatchObject({ version: EDV_SCHEME_VERSION })

    // The already-provisioned pass: same served description, nothing created.
    const second = await ensureSpaceAndCollection({
      was,
      spaceId,
      controllerDid: was.controllerDid,
      collectionId: 'vault',
      spaceDescription: await ensureSpace({
        was,
        spaceId,
        controllerDid: was.controllerDid
      })
    })
    expect(second).toEqual({ created: false })
  })

  it('ensureSpaceAndCollection without a description provisions both halves itself', async () => {
    const otherSpaceId = crypto.randomUUID()
    const first = await ensureSpaceAndCollection({
      was,
      spaceId: otherSpaceId,
      controllerDid: was.controllerDid,
      collectionId: 'notes',
      encryption: 'plaintext'
    })
    expect(first).toEqual({ created: true })
    const served = await was.space(otherSpaceId).describe()
    expect(served?.id).toBe(otherSpaceId)

    const second = await ensureSpaceAndCollection({
      was,
      spaceId: otherSpaceId,
      controllerDid: was.controllerDid,
      collectionId: 'notes',
      encryption: 'plaintext'
    })
    expect(second).toEqual({ created: false })
  })
})
