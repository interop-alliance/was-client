/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for service discovery: the `rel="service"` Link header parser,
 * version selection against fixture service descriptions, and
 * `WasClient.service()` with the gate every signed request passes through. A
 * stubbed global `fetch` serves the discovery requests and a stub `ZcapClient`
 * records signed ones, so no server is involved.
 */
import { describe, it, expect, vi, afterEach } from 'vitest'

import type { HttpResponse } from '@interop/http-client'

import {
  IncompatibleServerError,
  NotSupportedError,
  WasClient,
  WasServerError
} from '../../src/index.js'
import type { ServiceDescription } from '../../src/index.js'
import {
  PWS_SPEC_ID,
  selectServiceVersion,
  serviceLinkTarget
} from '../../src/internal/service.js'
import type { RequestArgs } from '../helpers/stubClient.js'
import { jsonResponse } from '../helpers/stubClient.js'

const SERVER_URL = 'https://host.example/was/'
const SERVICE_URL = 'https://host.example/was/service'

/**
 * A service description in the shape of the spec's example: a v0.5 and a v0.4
 * entry for WAS, another specification, and an `instance` disclosure.
 *
 * @returns {ServiceDescription}
 */
function exampleDescription(): ServiceDescription {
  return {
    url: SERVICE_URL,
    specs: {
      [PWS_SPEC_ID]: [
        {
          version: '0.5',
          url: 'https://w3c-ccg.github.io/wallet-attached-storage-spec/v0.5/',
          spaces: 'https://host.example/was/spaces/',
          features: ['listing', 'collection-management', 'future-token'],
          signatureAlgorithms: ['EdDSA'],
          zcapCryptosuites: ['eddsa-jcs-2022']
        },
        {
          version: '0.4',
          spaces: 'https://host.example/was/spaces/',
          features: ['listing']
        }
      ],
      'https://w3id.org/encrypted-collections': [{ version: '0.2' }]
    },
    instance: { name: 'was-teaching-server' }
  }
}

describe('serviceLinkTarget', () => {
  it('reads the service target from a single link', () => {
    expect(
      serviceLinkTarget({
        header: `<${SERVICE_URL}>; rel="service"`,
        baseUrl: SERVER_URL
      })
    ).toBe(SERVICE_URL)
  })

  it('finds the service link among others, with commas in quoted params', () => {
    const header =
      '<https://host.example/a>; rel="next"; title="a, b", ' +
      `<${SERVICE_URL}>; rel=service`
    expect(serviceLinkTarget({ header, baseUrl: SERVER_URL })).toBe(SERVICE_URL)
  })

  it('matches one of several relation types, case-insensitively', () => {
    expect(
      serviceLinkTarget({
        header: `<${SERVICE_URL}>; rel="describedby SERVICE"`,
        baseUrl: SERVER_URL
      })
    ).toBe(SERVICE_URL)
  })

  it('resolves a relative target against the response URL', () => {
    expect(
      serviceLinkTarget({
        header: '<service>; rel="service"',
        baseUrl: 'https://host.example/was/space/s/c/r'
      })
    ).toBe('https://host.example/was/space/s/c/service')
  })

  it('answers undefined with no header or no service link', () => {
    expect(serviceLinkTarget({ header: null, baseUrl: SERVER_URL })).toBe(
      undefined
    )
    expect(
      serviceLinkTarget({
        header: '<https://host.example/a>; rel="service-desc"',
        baseUrl: SERVER_URL
      })
    ).toBe(undefined)
  })
})

describe('selectServiceVersion', () => {
  it('chooses the v0.5 entry and exposes its spaces URL and features', () => {
    const info = selectServiceVersion(exampleDescription())
    expect(info.version).toBe('0.5')
    expect(info.entry.version).toBe('0.5')
    expect(info.spacesUrl).toBe('https://host.example/was/spaces/')
    expect(info.features).toEqual([
      'listing',
      'collection-management',
      'future-token'
    ])
    expect(info.description.url).toBe(SERVICE_URL)
  })

  it('carries unknown feature tokens and reads an absent token as unsupported', () => {
    const info = selectServiceVersion(exampleDescription())
    expect(info.hasFeature('future-token')).toBe(true)
    expect(info.hasFeature('collection-management')).toBe(true)
    expect(info.hasFeature('quotas')).toBe(false)
  })

  it('reads an absent features array as no features', () => {
    const info = selectServiceVersion({
      url: SERVICE_URL,
      specs: { [PWS_SPEC_ID]: [{ version: '0.5' }] }
    })
    expect(info.features).toEqual([])
    expect(info.hasFeature('listing')).toBe(false)
  })

  it('leaves spacesUrl absent when the entry has no spaces member', () => {
    const info = selectServiceVersion({
      url: SERVICE_URL,
      specs: { [PWS_SPEC_ID]: [{ version: '0.5', features: ['listing'] }] }
    })
    expect(info.spacesUrl).toBe(undefined)
    expect('spacesUrl' in info).toBe(false)
  })

  it('ignores an entry without a version', () => {
    const info = selectServiceVersion({
      url: SERVICE_URL,
      specs: {
        [PWS_SPEC_ID]: [
          { spaces: 'https://evil.example/spaces/' },
          { version: '0.5', spaces: 'https://host.example/was/spaces/' }
        ]
      }
    })
    expect(info.spacesUrl).toBe('https://host.example/was/spaces/')
  })

  it('ignores unknown specs keys, including near-miss identifiers', () => {
    const attempt = (): unknown =>
      selectServiceVersion({
        url: SERVICE_URL,
        specs: {
          'https://w3id.org/pws/': [{ version: '0.5' }],
          'http://w3id.org/pws': [{ version: '0.5' }],
          'https://example.com/other-spec': [{ version: '0.5' }]
        }
      })
    expect(attempt).toThrow(IncompatibleServerError)
  })

  it('refuses a server that lists only versions this client does not speak', () => {
    const attempt = (): unknown =>
      selectServiceVersion({
        url: SERVICE_URL,
        specs: { [PWS_SPEC_ID]: [{ version: '0.4' }, { version: '1.0' }] }
      })
    expect(attempt).toThrow(IncompatibleServerError)
    expect(attempt).toThrow(/offered: 0\.4, 1\.0/)
  })

  it.each([
    ['a non-object', 'nope'],
    ['null', null],
    ['a document without url', { specs: { [PWS_SPEC_ID]: [] } }],
    ['a document without specs', { url: SERVICE_URL }],
    ['an array specs', { url: SERVICE_URL, specs: [] }],
    [
      'a non-array version list',
      { url: SERVICE_URL, specs: { [PWS_SPEC_ID]: { version: '0.5' } } }
    ],
    [
      'a relative spaces URL',
      {
        url: SERVICE_URL,
        specs: { [PWS_SPEC_ID]: [{ version: '0.5', spaces: '/spaces/' }] }
      }
    ],
    [
      'a non-array features member',
      {
        url: SERVICE_URL,
        specs: { [PWS_SPEC_ID]: [{ version: '0.5', features: 'listing' }] }
      }
    ]
  ])('refuses %s with IncompatibleServerError', (_label, description) => {
    expect(() => selectServiceVersion(description)).toThrow(
      IncompatibleServerError
    )
  })

  it('does not look at instance', () => {
    const description = exampleDescription()
    const withOddInstance = {
      ...description,
      instance: { name: 42, version: ['x'] }
    }
    expect(selectServiceVersion(withOddInstance).version).toBe('0.5')
    const withoutInstance = { url: description.url, specs: description.specs }
    expect(selectServiceVersion(withoutInstance).version).toBe('0.5')
  })
})

/**
 * One request the stubbed global `fetch` saw.
 */
interface FetchCall {
  url: string
  method: string
  headers: Record<string, string>
}

/**
 * Stubs the global `fetch`: a `HEAD` of any URL answers `probe` (a status and
 * an optional `Link` header), and a `GET` of the service URL answers the
 * service description `body`.
 *
 * @param options {object}
 * @param [options.probeStatus] {number}   the `HEAD` status, default 404
 * @param [options.link] {string | null}   the `Link` header, `null` for none
 * @param [options.body] {string}   the service description response body
 * @param [options.serviceStatus] {number}   the service `GET` status
 * @returns {FetchCall[]}   the recorded calls
 */
function stubDiscovery({
  probeStatus = 404,
  link = `<${SERVICE_URL}>; rel="service"`,
  body = JSON.stringify(exampleDescription()),
  serviceStatus = 200
}: {
  probeStatus?: number
  link?: string | null
  body?: string
  serviceStatus?: number
} = {}): FetchCall[] {
  const calls: FetchCall[] = []
  vi.stubGlobal('fetch', async (url: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET'
    calls.push({
      url,
      method,
      headers: (init.headers ?? {}) as Record<string, string>
    })
    if (method === 'HEAD') {
      return new Response(null, {
        status: probeStatus,
        headers: link === null ? {} : { link }
      })
    }
    if (url === SERVICE_URL) {
      return new Response(body, {
        status: serviceStatus,
        headers: { 'content-type': 'application/json' }
      })
    }
    throw new Error(`unexpected fetch ${method} ${url}`)
  })
  return calls
}

/**
 * Builds a `WasClient` at {@link SERVER_URL} over a stub `ZcapClient` that
 * records signed requests and answers each with `data`.
 *
 * @param [options] {object}
 * @param [options.data] {unknown}   the signed response body
 * @param [options.serviceDescription] {ServiceDescription}
 * @returns {{ was: WasClient, signed: RequestArgs[] }}
 */
function client({
  data = { id: 'new-space' },
  serviceDescription
}: { data?: unknown; serviceDescription?: ServiceDescription } = {}): {
  was: WasClient
  signed: RequestArgs[]
} {
  const signed: RequestArgs[] = []
  const zcapClient = {
    invocationSigner: { id: 'did:example:alice#key-1' },
    async request(args: RequestArgs): Promise<HttpResponse> {
      signed.push(args)
      return jsonResponse({
        data,
        status: 201,
        headers: { location: 'https://host.example/was/space/new-space/' }
      })
    }
  } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
  const was = new WasClient({
    serverUrl: SERVER_URL,
    zcapClient,
    serviceDescription
  })
  return { was, signed }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('WasClient.service()', () => {
  it('HEADs serverUrl, follows the service link, and reads it unsigned', async () => {
    const calls = stubDiscovery()
    const { was, signed } = client()
    const info = await was.service()
    expect(info.version).toBe('0.5')
    expect(info.spacesUrl).toBe('https://host.example/was/spaces/')
    expect(calls.map(call => `${call.method} ${call.url}`)).toEqual([
      `HEAD ${SERVER_URL}`,
      `GET ${SERVICE_URL}`
    ])
    const headerNames = calls.flatMap(call =>
      Object.keys(call.headers).map(name => name.toLowerCase())
    )
    expect(headerNames).not.toContain('authorization')
    expect(headerNames).not.toContain('capability-invocation')
    expect(signed).toEqual([])
  })

  it('reads the link from a 308 or any other probe status', async () => {
    stubDiscovery({ probeStatus: 308 })
    expect((await client().was.service()).version).toBe('0.5')
  })

  it('memoizes discovery across calls and signed requests', async () => {
    const calls = stubDiscovery()
    const { was } = client()
    await Promise.all([was.service(), was.service()])
    await was.space('s').describe()
    expect(calls).toHaveLength(2)
  })

  it('discovers again on refresh', async () => {
    const calls = stubDiscovery()
    const { was } = client()
    await was.service()
    await was.service({ refresh: true })
    expect(calls).toHaveLength(4)
  })

  it('refuses a server whose response has no service link (pre-0.5)', async () => {
    stubDiscovery({ link: null })
    const { was } = client()
    await expect(was.service()).rejects.toThrow(IncompatibleServerError)
  })

  it('refuses a service description that is not JSON', async () => {
    stubDiscovery({ body: '<html>' })
    await expect(client().was.service()).rejects.toThrow(
      IncompatibleServerError
    )
  })

  it('refuses a service link whose target answers 404', async () => {
    stubDiscovery({ serviceStatus: 404, body: '' })
    await expect(client().was.service()).rejects.toThrow(
      IncompatibleServerError
    )
  })

  it('reports a server fault without the link as transient, and retries', async () => {
    stubDiscovery({ probeStatus: 503, link: null })
    const { was } = client()
    const failure = was.service()
    await expect(failure).rejects.toThrow(WasServerError)
    await expect(failure).rejects.not.toThrow(IncompatibleServerError)
    stubDiscovery()
    expect((await was.service()).version).toBe('0.5')
  })

  it.each([501, 505, 507])(
    'refuses a %i probe without the link as incompatible, with no status',
    async probeStatus => {
      stubDiscovery({ probeStatus, link: null })
      const failure = client().was.service()
      await expect(failure).rejects.toThrow(IncompatibleServerError)
      await expect(failure).rejects.toMatchObject({ status: undefined })
    }
  )

  it('refuses a service link whose target answers 501', async () => {
    stubDiscovery({ serviceStatus: 501, body: '' })
    await expect(client().was.service()).rejects.toThrow(
      IncompatibleServerError
    )
  })

  it('selects from a constructor-supplied description without fetching', async () => {
    const calls = stubDiscovery()
    const { was } = client({ serviceDescription: exampleDescription() })
    expect((await was.service()).version).toBe('0.5')
    expect(calls).toEqual([])
    await was.service({ refresh: true })
    expect(calls).toHaveLength(2)
  })

  it('refuses a constructor-supplied description with no understood version', async () => {
    const calls = stubDiscovery()
    const { was } = client({
      serviceDescription: {
        url: SERVICE_URL,
        specs: { [PWS_SPEC_ID]: [{ version: '0.4' }] }
      }
    })
    await expect(was.service()).rejects.toThrow(IncompatibleServerError)
    expect(calls).toEqual([])
  })
})

describe('the discovery gate on signed requests', () => {
  it('stops a signed read before signing, instead of resolving to null', async () => {
    stubDiscovery({ link: null })
    const { was, signed } = client()
    await expect(was.space('s').describe()).rejects.toThrow(
      IncompatibleServerError
    )
    await expect(was.request({ path: '/space/s/' })).rejects.toThrow(
      IncompatibleServerError
    )
    expect(signed).toEqual([])
  })

  it('does not gate unsigned public reads', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', async (url: string) => {
      calls.push(url)
      return new Response(JSON.stringify({ hello: 'world' }), {
        headers: { 'content-type': 'application/json' }
      })
    })
    const { was } = client()
    await was.publicRead({ resourceUrl: 'https://other.example/space/s/c/r' })
    expect(calls).toEqual(['https://other.example/space/s/c/r'])
  })
})

describe('the Spaces Repository URL', () => {
  it('createSpace and listSpaces use the advertised spaces URL', async () => {
    const description: ServiceDescription = {
      url: SERVICE_URL,
      specs: {
        [PWS_SPEC_ID]: [
          { version: '0.5', spaces: 'https://repo.example/tenants/' }
        ]
      }
    }
    const { was, signed } = client({ serviceDescription: description })
    await was.createSpace({ name: 'Home' })
    expect(signed[0]?.url).toBe('https://repo.example/tenants/')
    expect(signed[0]?.method).toBe('POST')

    const listing = client({
      data: { url: 'https://repo.example/tenants/', totalItems: 0, items: [] },
      serviceDescription: description
    })
    await listing.was.listSpaces()
    expect(listing.signed[0]?.url).toBe('https://repo.example/tenants/')
    expect(listing.signed[0]?.method).toBe('GET')
  })

  it('refuses createSpace and listSpaces when the server has no Spaces Repository', async () => {
    const { was, signed } = client({
      serviceDescription: {
        url: SERVICE_URL,
        specs: { [PWS_SPEC_ID]: [{ version: '0.5' }] }
      }
    })
    await expect(was.createSpace()).rejects.toThrow(NotSupportedError)
    await expect(was.listSpaces()).rejects.toThrow(NotSupportedError)
    expect(signed).toEqual([])
  })
})
