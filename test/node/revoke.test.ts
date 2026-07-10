/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the revocation primitive. `submitRevocation` POSTs a delegated
 * capability to `/space/:spaceId/zcaps/revocations/:capabilityId`, invoking that
 * URL's own root capability. A stub `ZcapClient` captures the request args, so
 * no signer or server is involved; the live behavior is covered by
 * `test/integration/revocation.test.ts`.
 */
import { describe, it, expect } from 'vitest'

import { WasClient, ValidationError, NotFoundError } from '../../src/index.js'
import type { IDelegatedZcap } from '../../src/index.js'

const SERVER_URL = 'https://was.example'
const CAPABILITY_ID = 'urn:uuid:6f1c1b0e-1f3a-4a5e-9a1e-3b2c4d5e6f70'

interface RequestArgs {
  url?: string
  method?: string
  action?: string
  capability?: {
    '@context'?: string
    id?: string
    invocationTarget?: string
    controller?: string
  }
  json?: unknown
}

/**
 * A delegated capability granting read/write on a collection under `spaceId`,
 * shaped like the output of `space.grant()` (proof and chain elided to what the
 * client actually reads).
 *
 * @param [options] {object}
 * @param [options.invocationTarget] {string}   the capability's target URL
 * @returns {IDelegatedZcap}
 */
function delegatedZcap({
  invocationTarget = `${SERVER_URL}/space/space-1/notes`
}: { invocationTarget?: string } = {}): IDelegatedZcap {
  return {
    '@context': ['https://w3id.org/zcap/v1'],
    id: CAPABILITY_ID,
    parentCapability: `urn:zcap:root:${encodeURIComponent(`${SERVER_URL}/space/space-1`)}`,
    controller: 'did:example:bob',
    invocationTarget,
    allowedAction: ['GET', 'PUT'],
    expires: '2030-01-01T00:00:00Z',
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-01-01T00:00:00Z',
      verificationMethod: 'did:example:alice#key-1',
      proofPurpose: 'capabilityDelegation',
      capabilityChain: [
        `urn:zcap:root:${encodeURIComponent(`${SERVER_URL}/space/space-1`)}`
      ],
      proofValue: 'zStubProofValue'
    }
  }
}

/**
 * Builds a `WasClient` over a stub `ZcapClient` that records the most recent
 * `request(...)` call and answers with `response` (a 204 by default), or throws
 * `rejectWith` when given.
 *
 * @param [options] {object}
 * @param [options.rejectWith] {unknown}   an error the stub request throws
 * @returns {object}
 * @returns return.client {WasClient}
 * @returns return.lastRequest {function} returns the captured request args
 */
function clientWithRequestSpy({ rejectWith }: { rejectWith?: unknown } = {}): {
  client: WasClient
  lastRequest: () => RequestArgs | undefined
} {
  let captured: RequestArgs | undefined
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async request(args: RequestArgs) {
      captured = args
      if (rejectWith !== undefined) {
        throw rejectWith
      }
      return { status: 204, headers: new Headers() }
    }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  const client = new WasClient({ serverUrl: SERVER_URL, zcapClient })
  return { client, lastRequest: () => captured }
}

describe('space.revoke (revocation)', () => {
  it('POSTs to the space revocation endpoint, framing the capability id', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.space('space-1').revoke(delegatedZcap())

    const args = lastRequest()
    expect(args?.method).toBe('POST')
    expect(args?.url).toBe(
      `${SERVER_URL}/space/space-1/zcaps/revocations/` +
        encodeURIComponent(CAPABILITY_ID)
    )
    // The `urn:uuid:` colons must be percent-encoded into the single final
    // segment, not left to split it.
    expect(args?.url).toContain('urn%3Auuid%3A')
  })

  it('sends the capability verbatim as the body', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const zcap = delegatedZcap()
    await client.space('space-1').revoke(zcap)

    expect(lastRequest()?.json).toBe(zcap)
  })

  it('leaves `action` unset so it defaults to the POST method', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.space('space-1').revoke(delegatedZcap())

    // The WAS route expects the HTTP verb, never ezcap's `read`/`write`.
    expect(lastRequest()?.action).toBe('POST')
  })

  it('invokes the revocation URL root capability, in object form', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.space('space-1').revoke(delegatedZcap())

    const { capability, url } = lastRequest() ?? {}
    // Object form, not a `urn:zcap:root:` string: ezcap rejects string root ids
    // whose target is not `https:`.
    expect(typeof capability).toBe('object')
    expect(capability?.['@context']).toBe('https://w3id.org/zcap/v1')
    expect(capability?.invocationTarget).toBe(url)
    expect(capability?.id).toBe(`urn:zcap:root:${encodeURIComponent(url!)}`)
    // Client-side only -- the server re-derives the real controller.
    expect(capability?.controller).toBe('did:example:alice')
  })

  it('refuses to revoke a root capability, before any request', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    const root = {
      '@context': 'https://w3id.org/zcap/v1',
      id: `urn:zcap:root:${encodeURIComponent(`${SERVER_URL}/space/space-1`)}`,
      invocationTarget: `${SERVER_URL}/space/space-1`,
      controller: 'did:example:alice'
    } as unknown as IDelegatedZcap

    await expect(client.space('space-1').revoke(root)).rejects.toThrow(
      ValidationError
    )
    expect(lastRequest()).toBeUndefined()
  })

  describe('error mapping', () => {
    it('maps the resubmission 400 to ValidationError (not idempotent)', async () => {
      const { client } = clientWithRequestSpy({
        rejectWith: {
          status: 400,
          data: {
            type: 'https://wallet.storage/spec#invalid-request-body',
            title: 'Invalid Revoke Capability request',
            errors: [
              { detail: 'The provided capability delegation is invalid.' }
            ]
          }
        }
      })
      const error = await client
        .space('space-1')
        .revoke(delegatedZcap())
        .catch((err: unknown) => err)

      expect(error).toBeInstanceOf(ValidationError)
      expect((error as ValidationError).status).toBe(400)
    })

    it('maps the non-participant 404 to NotFoundError', async () => {
      const { client } = clientWithRequestSpy({ rejectWith: { status: 404 } })

      await expect(
        client.space('space-1').revoke(delegatedZcap())
      ).rejects.toThrow(NotFoundError)
    })
  })
})

describe('was.revoke (space derived from the capability)', () => {
  it('derives the space from a collection-scoped invocationTarget', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.revoke(delegatedZcap())

    expect(lastRequest()?.url).toBe(
      `${SERVER_URL}/space/space-1/zcaps/revocations/` +
        encodeURIComponent(CAPABILITY_ID)
    )
  })

  it('derives the space from a resource-scoped invocationTarget', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.revoke(
      delegatedZcap({
        invocationTarget: `${SERVER_URL}/space/space-1/notes/doc-1`
      })
    )

    expect(lastRequest()?.url).toBe(
      `${SERVER_URL}/space/space-1/zcaps/revocations/` +
        encodeURIComponent(CAPABILITY_ID)
    )
  })

  it('derives the space from a space-scoped invocationTarget', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.revoke(
      delegatedZcap({ invocationTarget: `${SERVER_URL}/space/space-1` })
    )

    expect(lastRequest()?.url).toBe(
      `${SERVER_URL}/space/space-1/zcaps/revocations/` +
        encodeURIComponent(CAPABILITY_ID)
    )
  })

  it('derives the space from a sub-resource invocationTarget', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.revoke(
      delegatedZcap({
        invocationTarget: `${SERVER_URL}/space/space-1/notes/doc-1/meta`
      })
    )

    expect(lastRequest()?.url).toBe(
      `${SERVER_URL}/space/space-1/zcaps/revocations/` +
        encodeURIComponent(CAPABILITY_ID)
    )
  })

  it('percent-decodes an encoded space id segment', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await client.revoke(
      delegatedZcap({ invocationTarget: `${SERVER_URL}/space/a%2Fb/notes` })
    )

    expect(lastRequest()?.url).toBe(
      `${SERVER_URL}/space/a%2Fb/zcaps/revocations/` +
        encodeURIComponent(CAPABILITY_ID)
    )
  })

  it('rejects a capability whose target is outside the /space tree', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    await expect(
      client.revoke(
        delegatedZcap({ invocationTarget: `${SERVER_URL}/kms/keystores/k1` })
      )
    ).rejects.toThrow(ValidationError)
    expect(lastRequest()).toBeUndefined()
  })

  it('rejects a capability whose invocationTarget is not an absolute URL', async () => {
    const { client } = clientWithRequestSpy()
    await expect(
      client.revoke(delegatedZcap({ invocationTarget: '/space/space-1/notes' }))
    ).rejects.toThrow(ValidationError)
  })

  it('rejects a capability targeting a space on another origin', async () => {
    const { client, lastRequest } = clientWithRequestSpy()
    // The path grammar alone would match; only the base check catches this, and
    // without it the revocation would be aimed at *our* server's same-named
    // space.
    await expect(
      client.revoke(
        delegatedZcap({
          invocationTarget: 'https://elsewhere.example/space/space-1/notes'
        })
      )
    ).rejects.toThrow(ValidationError)
    expect(lastRequest()).toBeUndefined()
  })

  it('resolves the space under a server mounted on a base path', async () => {
    let captured: RequestArgs | undefined
    const zcapClient = {
      invocationSigner: { id: 'did:example:alice#key-1' },
      async request(args: RequestArgs) {
        captured = args
        return { status: 204, headers: new Headers() }
      }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const client = new WasClient({
      serverUrl: 'https://host.example/was/',
      zcapClient
    })

    await client.revoke(
      delegatedZcap({
        invocationTarget: 'https://host.example/was/space/space-1/notes'
      })
    )

    expect(captured?.url).toBe(
      'https://host.example/was/space/space-1/zcaps/revocations/' +
        encodeURIComponent(CAPABILITY_ID)
    )
  })
})
