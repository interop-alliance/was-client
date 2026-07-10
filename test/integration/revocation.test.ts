/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: `space.revoke()` / `was.revoke()` against a live WAS server.
 * The assertion that carries the feature is not the 204 -- it is a capability
 * that worked before the call and fails after it.
 *
 * Covers both callers the server's dual-root rule admits: the space controller
 * revoking a capability it delegated, and a delegee revoking the capability it
 * holds (with no separate grant). Also pins the surprising consequence of
 * permissive access-control policies: on a `PublicCanRead` target a revoked
 * capability's *read* still succeeds, via the policy, while its *write* fails.
 *
 * Requires a running server: set `TEST_SERVER_URL`. It must be byte-identical to
 * the server's own `SERVER_URL` -- zcap invocation targets embed host and port,
 * so `localhost` vs `127.0.0.1`, or a port mismatch, yields a bare 404 that looks
 * like a bug and is not. The suite skips when `TEST_SERVER_URL` is unset, so a
 * bare `pnpm test:integration` (no server) is not a failure.
 */
import { describe, it, beforeAll, afterAll, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient, NotFoundError, ValidationError } from '../../src/index.js'
import type { IDelegatedZcap, Space } from '../../src/index.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * Builds a fresh did:key Ed25519 signer, a WAS client over it, and its DID.
 *
 * @returns {Promise<{ was: WasClient, did: string }>}
 */
async function freshWasClient(): Promise<{ was: WasClient; did: string }> {
  const keyPair = await Ed25519VerificationKey.generate()
  const did = `did:key:${keyPair.fingerprint()}`
  keyPair.id = `${did}#${keyPair.fingerprint()}`
  keyPair.controller = did
  const was = WasClient.fromSigner({
    serverUrl: serverUrl!,
    signer: keyPair.signer()
  })
  return { was, did }
}

describeLive('space.revoke() (live server)', () => {
  let alice: WasClient
  let app: WasClient
  let appDid: string
  let stranger: WasClient
  let space: Space
  let spaceId: string

  beforeAll(async () => {
    ;({ was: alice } = await freshWasClient())
    ;({ was: app, did: appDid } = await freshWasClient())
    ;({ was: stranger } = await freshWasClient())

    space = await alice.createSpace({ name: 'Revocation Integration' })
    spaceId = space.id
    const notes = await space.createCollection({ id: 'notes', name: 'Notes' })
    await notes.put('doc-1', { hello: 'world' })
  })

  afterAll(async () => {
    try {
      await space.delete()
    } catch {
      /* best-effort cleanup */
    }
  })

  /**
   * Delegates read/write on the `notes` collection to the app -- the "session
   * key" shape a controller hands an application.
   *
   * @returns {Promise<IDelegatedZcap>}
   */
  async function grantToApp(): Promise<IDelegatedZcap> {
    return alice
      .space(spaceId)
      .collection('notes')
      .grant({
        to: appDid,
        actions: ['GET', 'PUT', 'POST', 'DELETE'],
        expires: new Date(Date.now() + 60 * 60 * 1000)
      })
  }

  it('the controller revokes; the delegee loses read and write', async () => {
    const zcap = await grantToApp()
    const granted = app.space(spaceId).collection('notes', { capability: zcap })

    // The capability works before the revocation.
    expect(await granted.get('doc-1')).toEqual({ hello: 'world' })

    await alice.space(spaceId).revoke(zcap)

    // ...and is dead after it. WAS masks unauthorized as 404.
    expect(await granted.get('doc-1')).toBeNull()
    await expect(granted.put('doc-2', { escape: true })).rejects.toThrow(
      NotFoundError
    )
    // The write did not land.
    expect(
      await alice.space(spaceId).collection('notes').get('doc-2')
    ).toBeNull()

    // The controller's own (root) access is untouched: root zcaps are never
    // revocable, and no revocation applies to a chain of just the root.
    expect(await alice.space(spaceId).collection('notes').get('doc-1')).toEqual(
      {
        hello: 'world'
      }
    )
  })

  it('a delegee revokes its own capability, holding no separate grant', async () => {
    const zcap = await grantToApp()
    const granted = app.space(spaceId).collection('notes', { capability: zcap })
    expect(await granted.get('doc-1')).toEqual({ hello: 'world' })

    // The app is not the space controller. It qualifies purely as a controller
    // in the to-be-revoked capability's chain -- the dual-root rule -- and the
    // client invokes the revocation URL's own root capability, which is what
    // makes one code path serve both callers.
    await app.space(spaceId).revoke(zcap)

    expect(await granted.get('doc-1')).toBeNull()
  })

  it('was.revoke() derives the space from the capability', async () => {
    const zcap = await grantToApp()
    const granted = app.space(spaceId).collection('notes', { capability: zcap })
    expect(await granted.get('doc-1')).toEqual({ hello: 'world' })

    // No space id supplied: it comes from the capability's invocationTarget,
    // which here is the collection URL beneath the space.
    await alice.revoke(zcap)

    expect(await granted.get('doc-1')).toBeNull()
  })

  it('revocation withdraws the capability, not a policy grant', async () => {
    const notices = await alice
      .space(spaceId)
      .createCollection({ id: 'public-notices', name: 'Notices' })
    await notices.put('notice-1', { open: true })
    await notices.setPublic()

    const zcap = await alice
      .space(spaceId)
      .collection('public-notices')
      .grant({
        to: appDid,
        actions: ['GET', 'PUT'],
        expires: new Date(Date.now() + 60 * 60 * 1000)
      })
    await alice.space(spaceId).revoke(zcap)

    const granted = app
      .space(spaceId)
      .collection('public-notices', { capability: zcap })

    // Access-control policies are permissive: revoking withdraws only what the
    // capability granted. The read survives -- via the PublicCanRead policy, not
    // via the capability. The write, which no policy grants, does not. These two
    // assertions together are what distinguish "the capability is dead" from
    // "the request happened to succeed".
    expect(await granted.get('notice-1')).toEqual({ open: true })
    await expect(granted.put('notice-2', { sneaky: true })).rejects.toThrow(
      NotFoundError
    )
  })

  it('a non-participant cannot revoke, and the capability survives', async () => {
    const zcap = await grantToApp()

    // The stranger is neither the space controller nor in the capability's
    // chain, so the server masks the refusal as a 404.
    await expect(stranger.space(spaceId).revoke(zcap)).rejects.toThrow(
      NotFoundError
    )

    // Nothing was stored: the capability still works.
    const granted = app.space(spaceId).collection('notes', { capability: zcap })
    expect(await granted.get('doc-1')).toEqual({ hello: 'world' })
  })

  it('resubmitting a stored revocation is a ValidationError, not a no-op', async () => {
    const zcap = await grantToApp()
    await alice.space(spaceId).revoke(zcap)

    // `revoke()` is deliberately not idempotent: the chain now contains a
    // revoked link, which the server reports with the same 400 it uses for a
    // tampered or foreign-rooted capability, so the client cannot tell them
    // apart and does not swallow any of them.
    await expect(alice.space(spaceId).revoke(zcap)).rejects.toThrow(
      ValidationError
    )
  })

  it('a capability rooted in another space cannot be revoked here', async () => {
    const otherSpace = await alice.createSpace({ name: 'Other Space' })
    await otherSpace.createCollection({ id: 'notes', name: 'Notes' })
    const foreign = await alice
      .space(otherSpace.id)
      .collection('notes')
      .grant({
        to: appDid,
        actions: ['GET'],
        expires: new Date(Date.now() + 60 * 60 * 1000)
      })

    try {
      // Revocation is scoped to one space; there is no global revocation.
      await expect(alice.space(spaceId).revoke(foreign)).rejects.toThrow(
        ValidationError
      )

      // Submitted to its own space, it revokes -- scoping cuts both ways.
      await expect(alice.revoke(foreign)).resolves.toBeUndefined()
    } finally {
      await otherSpace.delete().catch(() => {})
    }
  })
})
