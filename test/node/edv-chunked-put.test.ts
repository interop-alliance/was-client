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
import { EdvClientCore } from '@interop/edv-client'

import {
  ConflictError,
  EncryptionError,
  PreconditionFailedError
} from '../../src/index.js'
import type { Json } from '../../src/index.js'
import {
  createEdvDocCipher,
  createRefreshingEdvDocCipher
} from '../../src/edv/index.js'
import { blobBytes } from '../../src/edv/core.js'
import { bytesOf } from '../helpers/bytes.js'
import { memoryServer, readerWithDescriptor } from '../helpers/memoryServer.js'

describe('Resource.put: a chunked encrypted write by id', () => {
  const blob = bytesOf(64)

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
