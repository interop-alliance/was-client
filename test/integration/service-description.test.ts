/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration test: service discovery against a live WAS server. The client
 * follows the `rel="service"` link from the server's responses, selects the
 * v0.5 entry, and creates and lists a Space at the Spaces Repository URL the
 * document names.
 *
 * Requires a running server: set `TEST_SERVER_URL`, byte-identical to the
 * server's own `SERVER_URL` (zcap invocation targets embed host and port). The
 * suite skips when `TEST_SERVER_URL` is unset.
 */
import { describe, it, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

import { WasClient } from '../../src/index.js'

const serverUrl = process.env.TEST_SERVER_URL
const describeLive = serverUrl ? describe : describe.skip

/**
 * Builds a WAS client over a fresh did:key Ed25519 signer.
 *
 * @returns {Promise<WasClient>}
 */
async function freshWasClient(): Promise<WasClient> {
  const keyPair = await Ed25519VerificationKey.generate()
  return WasClient.fromSigner({
    serverUrl: serverUrl!,
    signer: keyPair.didKeySigner()
  })
}

describeLive('service discovery (live server)', () => {
  it('discovers the service description and selects v0.5', async () => {
    const was = await freshWasClient()
    const info = await was.service()
    expect(info.version).toBe('0.5')
    expect(new URL(info.description.url).origin).toBe(
      new URL(serverUrl!).origin
    )
    expect(info.spacesUrl).toEqual(expect.any(String))
    expect(info.hasFeature('listing')).toBe(true)
  })

  it('finds the link on a 404 for a URL the client holds', async () => {
    const response = await fetch(
      new URL('space/no-such-space/c/r', `${serverUrl!.replace(/\/?$/, '/')}`),
      { method: 'HEAD' }
    )
    expect(response.status).toBe(404)
    expect(response.headers.get('link')).toMatch(/rel="?service"?/)
  })

  it('creates and lists a Space at the advertised Spaces Repository URL', async () => {
    const was = await freshWasClient()
    const space = await was.createSpace({ name: 'Service Discovery' })
    const listing = await was.listSpaces()
    expect(listing.items.map(item => item.id)).toContain(space.id)
    await space.delete()
    // Space creation, listing, and deletion run past the 5s default when the
    // rest of the integration tier loads the same server in parallel.
  }, 30_000)
})
