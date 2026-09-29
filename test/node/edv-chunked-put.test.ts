/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A large encrypted binary written by id through the handle API, end to end
 * over an in-memory WAS server: `resource.put()` on a random-id encrypted
 * handle routes an over-threshold payload to the chunked write at the
 * caller's id, a second create-if-absent `put()` at that id fails with a 412
 * so the caller can read the held copy, and a pending stub left by a torn
 * write is recognized with the doc cipher's `isPendingStub` and removed with
 * `resource.delete()`, which takes its chunks with it.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { EdvClientCore } from '@interop/edv-client'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { HttpResponse } from '@interop/http-client'

import {
  ConflictError,
  EncryptionError,
  PreconditionFailedError,
  WasClient
} from '../../src/index.js'
import type { CollectionEncryption, Json } from '../../src/index.js'
import {
  createEdvDocCipher,
  createEdvEncryption,
  createRefreshingEdvDocCipher,
  ownerRecipient
} from '../../src/edv/index.js'
import { blobBytes } from '../../src/edv/core.js'
import { mintEpoch, wrapEpochSecret } from '../../src/edv/epochCrypto.js'
import { serviceDescriptionFor } from '../helpers/stubClient.js'
import type { RequestArgs } from '../helpers/stubClient.js'

/**
 * A reader's keys and the single-epoch descriptor it is recipient zero of.
 *
 * @returns {Promise<object>}
 */
async function readerWithDescriptor(): Promise<{
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
function memoryServer(): {
  store: Map<string, Uint8Array>
  write: (path: string, body: Uint8Array) => string
  client: (options: { maxBlobBytes: number; chunkSize: number }) => WasClient
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
    chunkSize
  }: {
    maxBlobBytes: number
    chunkSize: number
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
        chunkSize
      })
    })
  return { store, write, client, failWhen, beforeRequest }
}

describe('Resource.put: a chunked encrypted write by id', () => {
  const blob = new Uint8Array(64).map((_value, index) => (index * 3) % 251)

  it('round-trips at the caller id, and a second create-if-absent put gets a 412', async () => {
    const { keys, encryption } = await readerWithDescriptor()
    const server = memoryServer()
    const collection = server
      .client({ maxBlobBytes: 16, chunkSize: 24 })
      .space('s')
      .collection('c', { encryption: { ...encryption, keys } })
    const id = (await EdvClientCore.generateId()) as string
    const resource = collection.resource(id)

    await resource.put(blob, { contentType: 'image/png', ifNoneMatch: true })
    const chunkPaths = [...server.store.keys()].filter(path =>
      path.startsWith(`/space/s/c/${id}/chunks/`)
    )
    expect(chunkPaths.length).toBe(3)

    const held = await resource.get()
    expect(held).toBeInstanceOf(Blob)
    expect((held as Blob).type).toBe('image/png')
    expect(await blobBytes(held as Blob)).toEqual(blob)

    await expect(
      resource.put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
  })

  it('leaves a pending stub the caller can recognize and delete, then rewrite', async () => {
    const { keys, encryption } = await readerWithDescriptor()
    const server = memoryServer()
    const collection = server
      .client({ maxBlobBytes: 16, chunkSize: 24 })
      .space('s')
      .collection('c', { encryption: { ...encryption, keys } })
    const id = (await EdvClientCore.generateId()) as string
    const resource = collection.resource(id)
    const documentPath = `/space/s/c/${id}`

    // Tear the write after the first document write: the second chunk and
    // the cleanup delete both fail, so the stub stays with one chunk.
    server.failWhen.test = (args, path) =>
      (args.method === 'PUT' && path.endsWith('/chunks/1')) ||
      args.method === 'DELETE'
    await expect(
      resource.put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(EncryptionError)
    server.failWhen.test = undefined
    expect(server.store.has(documentPath)).toBe(true)

    // The next run: the id is taken, and the held copy cannot be read.
    await expect(
      resource.put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    await expect(resource.get()).rejects.toBeInstanceOf(EncryptionError)

    // The caller recognizes the stub from its raw envelope...
    const cipher = await createEdvDocCipher({
      ...keys,
      collectionId: 'c',
      encryption
    })
    const envelope = (await collection
      .resource(id, { encryption: 'plaintext' })
      .get()) as Json
    await expect(cipher.isPendingStub({ id, envelope })).resolves.toBe(true)
    // ...through the self-refreshing cipher a sync engine holds, too.
    const refreshing = await createRefreshingEdvDocCipher({
      ...keys,
      collectionId: 'c',
      cache: {
        readDescriptor: async () => encryption,
        writeDescriptor: async () => {}
      }
    })
    await expect(refreshing.isPendingStub({ id, envelope })).resolves.toBe(true)

    // ...deletes it, chunks included, and writes the Resource again.
    await resource.delete()
    expect(
      [...server.store.keys()].some(path => path.startsWith(documentPath))
    ).toBe(false)
    await resource.put(blob, { contentType: 'image/png', ifNoneMatch: true })
    expect(await blobBytes((await resource.get()) as Blob)).toEqual(blob)
  })

  it('fails with a 412 and keeps the document another writer stored mid-write', async () => {
    const { keys, encryption } = await readerWithDescriptor()
    const server = memoryServer()
    const collection = server
      .client({ maxBlobBytes: 16, chunkSize: 24 })
      .space('s')
      .collection('c', { encryption: { ...encryption, keys } })
    const id = (await EdvClientCore.generateId()) as string
    const documentPath = `/space/s/c/${id}`
    const theirs = new TextEncoder().encode('{"theirs":true}')

    // Another writer replaces the pending stub just before the final update.
    let documentPuts = 0
    server.beforeRequest.run = (args, path) => {
      if (args.method === 'PUT' && path === documentPath) {
        documentPuts++
        if (documentPuts === 2) {
          server.write(documentPath, theirs)
        }
      }
    }
    await expect(
      collection
        .resource(id)
        .put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect(server.store.get(documentPath)).toEqual(theirs)
  })

  it('surfaces a 409 on the first document write as a ConflictError', async () => {
    const { keys, encryption } = await readerWithDescriptor()
    const server = memoryServer()
    const collection = server
      .client({ maxBlobBytes: 16, chunkSize: 24 })
      .space('s')
      .collection('c', { encryption: { ...encryption, keys } })
    const id = (await EdvClientCore.generateId()) as string

    server.failWhen.status = 409
    server.failWhen.test = (args, path) =>
      args.method === 'PUT' && path === `/space/s/c/${id}`
    await expect(
      collection
        .resource(id)
        .put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(ConflictError)
  })

  it('surfaces a 409 on the final update as a ConflictError and deletes the stub', async () => {
    const { keys, encryption } = await readerWithDescriptor()
    const server = memoryServer()
    const collection = server
      .client({ maxBlobBytes: 16, chunkSize: 24 })
      .space('s')
      .collection('c', { encryption: { ...encryption, keys } })
    const id = (await EdvClientCore.generateId()) as string
    const documentPath = `/space/s/c/${id}`

    let documentPuts = 0
    server.failWhen.status = 409
    server.failWhen.test = (args, path) =>
      args.method === 'PUT' && path === documentPath && ++documentPuts === 2
    await expect(
      collection
        .resource(id)
        .put(blob, { contentType: 'image/png', ifNoneMatch: true })
    ).rejects.toBeInstanceOf(ConflictError)
    expect(
      [...server.store.keys()].some(path => path.startsWith(documentPath))
    ).toBe(false)
  })
})
