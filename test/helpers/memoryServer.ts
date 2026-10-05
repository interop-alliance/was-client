/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * An in-memory WAS server behind a stub `ZcapClient`, plus a reader's keys
 * and the single-epoch descriptor it is recipient zero of -- for unit tests
 * that drive the encrypted chunked-stream paths end to end through the
 * handle API without a live server.
 */
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { HttpResponse } from '@interop/http-client'

import { WasClient } from '../../src/index.js'
import type { CollectionEncryption } from '../../src/index.js'
import { createEdvEncryption, ownerRecipient } from '../../src/edv/index.js'
import { mintEpoch, wrapEpochSecret } from '../../src/edv/epochCrypto.js'
import { serviceDescriptionFor } from './stubClient.js'
import type { RequestArgs } from './stubClient.js'

/**
 * A reader's keys and the single-epoch descriptor it is recipient zero of.
 *
 * @returns {Promise<object>}
 */
export async function readerWithDescriptor(): Promise<{
  keys: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  encryption: CollectionEncryption
}> {
  const kak = await X25519KeyAgreementKey2020.generate({
    controller: 'did:example:alice'
  })
  const keyAgreementKey = kak as unknown as IKeyAgreementKey
  const keyResolver = (async () => ({
    id: kak.id,
    type: kak.type,
    publicKeyMultibase: kak.publicKeyMultibase
  })) as unknown as IKeyResolver
  const { epochId, secret } = await mintEpoch()
  const recipient = await wrapEpochSecret({
    epochSecret: secret,
    recipient: ownerRecipient({ keyAgreementKey })
  })
  return {
    keys: { keyAgreementKey, keyResolver },
    encryption: {
      scheme: 'edv',
      epochs: [{ id: epochId, recipients: [recipient] }],
      currentEpoch: epochId
    }
  }
}

/**
 * An in-memory WAS server behind a stub `ZcapClient`: `PUT` stores the body
 * under a fresh `ETag` (refusing an `If-None-Match: *` create over a stored
 * path, or an `If-Match` on a stale `ETag`, with 412), `GET` serves it back
 * (404 when absent), and `DELETE` removes a resource together with every
 * chunk stored under it (honoring `If-Match` too). `failWhen` makes a chosen
 * request fail with its `status` (default 503), to tear a write, and
 * `beforeRequest` lets a test act as a concurrent writer.
 *
 * @returns {object}   the client, the stored bodies by path, and the hooks
 */
export function memoryServer(): {
  store: Map<string, Uint8Array>
  write: (path: string, body: Uint8Array) => string
  client: (options: {
    maxBlobBytes: number
    chunkSize: number
    idDerivation?: 'random' | 'content'
  }) => WasClient
  failWhen: {
    test?: (args: RequestArgs, path: string) => boolean
    status?: number
  }
  beforeRequest: { run?: (args: RequestArgs, path: string) => void }
} {
  const store = new Map<string, Uint8Array>()
  const etags = new Map<string, string>()
  let version = 0
  const write = (path: string, body: Uint8Array): string => {
    const etag = `"${++version}"`
    store.set(path, body)
    etags.set(path, etag)
    return etag
  }
  const failWhen: {
    test?: (args: RequestArgs, path: string) => boolean
    status?: number
  } = {}
  const beforeRequest: { run?: (args: RequestArgs, path: string) => void } = {}
  const fail = (status: number): never => {
    throw { status, response: { status } }
  }
  const request = async (args: RequestArgs): Promise<HttpResponse> => {
    const path = new URL(args.url!).pathname
    const method = args.method ?? 'GET'
    beforeRequest.run?.(args, path)
    if (failWhen.test?.(args, path)) {
      fail(failWhen.status ?? 503)
    }
    const ifMatch = args.headers?.['if-match']
    if (ifMatch !== undefined && etags.get(path) !== ifMatch) {
      fail(412)
    }
    if (method === 'PUT') {
      if (args.headers?.['if-none-match'] === '*' && store.has(path)) {
        fail(412)
      }
      const body =
        args.body instanceof Uint8Array
          ? args.body
          : new TextEncoder().encode(JSON.stringify(args.json))
      const etag = write(path, body)
      return {
        status: 204,
        headers: new Headers({ etag })
      } as unknown as HttpResponse
    }
    if (method === 'DELETE') {
      for (const stored of [...store.keys()]) {
        if (stored === path || stored.startsWith(`${path}/chunks/`)) {
          store.delete(stored)
          etags.delete(stored)
        }
      }
      return { status: 204, headers: new Headers() } as unknown as HttpResponse
    }
    const bytes = store.get(path)
    if (bytes === undefined) {
      fail(404)
    }
    const text = new TextDecoder().decode(bytes)
    const isChunk = path.includes('/chunks/')
    return {
      status: 200,
      headers: new Headers({
        'content-type': isChunk
          ? 'application/octet-stream'
          : 'application/jose+json',
        etag: etags.get(path)!
      }),
      ...(!isChunk && { data: JSON.parse(text) }),
      async json() {
        return JSON.parse(text)
      },
      async text() {
        return text
      },
      async arrayBuffer() {
        return bytes!.slice().buffer
      }
    } as unknown as HttpResponse
  }
  const client = ({
    maxBlobBytes,
    chunkSize,
    idDerivation
  }: {
    maxBlobBytes: number
    chunkSize: number
    idDerivation?: 'random' | 'content'
  }): WasClient =>
    new WasClient({
      serverUrl: 'https://was.example',
      serviceDescription: serviceDescriptionFor(),
      zcapClient: {
        invocationSigner: { id: 'did:example:alice#key-1' },
        request
      } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient'],
      encryption: createEdvEncryption({
        resolveKeys: async () => null,
        maxBlobBytes,
        chunkSize,
        ...(idDerivation !== undefined && { idDerivation })
      })
    })
  return { store, write, client, failWhen, beforeRequest }
}
