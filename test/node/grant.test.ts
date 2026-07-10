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

/**
 * An unparented grant into the Space tree roots at the *Space's* root
 * capability, carrying the narrower target as an attenuated `invocationTarget`.
 * Both forms grant the same access, but only a Space-rooted chain can be revoked
 * (revocation is Space-scoped and the endpoint requires the chain to root
 * exactly in the Space), so a collection-rooted grant would be un-revocable.
 */
describe('grant rooting (revocability)', () => {
  const spaceRoot = `urn:zcap:root:${encodeURIComponent('https://was.example/space/s')}`

  it('roots a collection grant at its space, attenuating the target', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client
      .space('s')
      .collection('c')
      .grant({
        to: 'did:example:bob',
        actions: ['GET']
      })

    const args = lastDelegate()
    expect(args?.capability).toBe(spaceRoot)
    expect(args?.invocationTarget).toBe('https://was.example/space/s/c')
  })

  it('roots a resource-targeted was.grant at its space', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://was.example/space/s/c/r'
    })

    expect(lastDelegate()?.capability).toBe(spaceRoot)
  })

  it('roots a space grant at itself', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.space('s').grant({ to: 'did:example:bob', actions: ['GET'] })

    const args = lastDelegate()
    expect(args?.capability).toBe(spaceRoot)
    expect(args?.invocationTarget).toBe('https://was.example/space/s')
  })

  it('re-delegation keeps the bound capability as the parent', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    const held = { id: 'urn:uuid:held' }
    await client
      .space('s', { capability: held as never })
      .collection('c')
      .grant({ to: 'did:example:bob', actions: ['GET'] })

    expect(lastDelegate()?.capability).toBe(held)
  })

  it('leaves a target outside the space tree to the ezcap default root', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://was.example/kms/keystores/k1'
    })

    expect(lastDelegate()?.capability).toBeUndefined()
  })

  it('leaves a target on another origin to the ezcap default root', async () => {
    const { client, lastDelegate } = clientWithDelegateSpy()
    await client.grant({
      to: 'did:example:bob',
      actions: ['GET'],
      target: 'https://elsewhere.example/space/s/c'
    })

    expect(lastDelegate()?.capability).toBeUndefined()
  })

  it('roots at the space under a server mounted on a base path', async () => {
    let captured: DelegateArgs | undefined
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      async delegate(args: DelegateArgs) {
        captured = args
        return { ...args, allowedAction: args.allowedActions }
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serverUrl: 'https://host.example/was/',
      zcapClient
    })

    await client
      .space('s')
      .collection('c')
      .grant({
        to: 'did:example:bob',
        actions: ['GET']
      })

    // The base path is preserved in the Space URL the chain roots at.
    expect(captured?.capability).toBe(
      `urn:zcap:root:${encodeURIComponent('https://host.example/was/space/s')}`
    )
    expect(captured?.invocationTarget).toBe(
      'https://host.example/was/space/s/c'
    )
  })
})
