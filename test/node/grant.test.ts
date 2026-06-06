/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the delegation primitive. `delegateGrant` maps `GrantOptions`
 * onto `zcapClient.delegate(...)`, normalizing action verbs to uppercase so a
 * lowercase grant (`'get'`) still validates on the server (which matches
 * actions case-sensitively against `'GET'`). A stub `ZcapClient` captures the
 * delegate args, so no signer or server is involved.
 */
import { describe, it, expect } from 'vitest'

import { WasClient } from '../../src/index.js'

interface DelegateArgs {
  controller?: string
  invocationTarget?: string
  allowedActions?: string[]
  expires?: string | Date
  capability?: unknown
}

/**
 * Builds a `WasClient` over a stub `ZcapClient` that records the most recent
 * `delegate(...)` call and echoes its args back as the delegated zcap.
 *
 * @returns {object}
 * @returns return.client {WasClient}
 * @returns return.lastDelegate {function} returns the captured delegate args
 */
function clientWithDelegateSpy(): {
  client: WasClient
  lastDelegate: () => DelegateArgs | undefined
} {
  let captured: DelegateArgs | undefined
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async delegate(args: DelegateArgs) {
      captured = args
      return { ...args, allowedAction: args.allowedActions }
    }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  const client = new WasClient({ serverUrl: 'https://was.example', zcapClient })
  return { client, lastDelegate: () => captured }
}

describe('was.grant (delegation)', () => {
  it('normalizes lowercase actions to uppercase before signing', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.grant({
      to: 'did:example:bob',
      actions: ['get'],
      target: 'https://was.example/space/s/c/r'
    })
    expect(lastDelegate()?.allowedActions).toEqual(['GET'])
  })

  it('passes through controller, invocationTarget, expires and capability', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    const expires = '2026-01-01T00:00:00Z'
    const parent = { id: 'urn:zcap:parent' }
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET', 'put'],
      target: 'https://was.example/space/s',
      expires,
      capability: parent as never
    })
    const args = lastDelegate()
    expect(args?.controller).toBe('did:example:bob')
    expect(args?.invocationTarget).toBe('https://was.example/space/s')
    expect(args?.allowedActions).toEqual(['GET', 'PUT'])
    expect(args?.expires).toBe(expires)
    expect(args?.capability).toBe(parent)
  })
})
