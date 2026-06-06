/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Integration tests for the WAS client against an in-process reference server.
 * Covers core CRUD (spaces, collections, JSON + binary resources), listings,
 * the 404-returns-null read semantics, delegation round-trips, and
 * export/import.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest'

import {
  WasClient,
  Space,
  Collection,
  Resource,
  NotFoundError,
  NotImplementedError
} from '../../src/index.js'
import { startServer, buildClient } from './helpers.js'
import type { TestServer } from './helpers.js'

const PORT = 9787

describe('WasClient (integration)', () => {
  let server: TestServer
  let alice: WasClient

  beforeAll(async () => {
    server = await startServer({ port: PORT })
    ;({ client: alice } = await buildClient({ serverUrl: server.serverUrl }))
  })

  afterAll(async () => {
    await server.close()
  })

  describe('lazy handles', () => {
    it('builds handles synchronously without I/O', () => {
      const space = alice.space('does-not-exist')
      expect(space).toBeInstanceOf(Space)
      const collection = space.collection('nope')
      expect(collection).toBeInstanceOf(Collection)
      expect(collection.resource('whatever')).toBeInstanceOf(Resource)
      expect(collection.spaceId).toBe('does-not-exist')
    })
  })

  describe('spaces', () => {
    it('creates a space and reads it back', async () => {
      const space = await alice.createSpace({ name: 'Home' })
      expect(space).toBeInstanceOf(Space)

      const description = await space.describe()
      expect(description).toMatchObject({
        id: space.id,
        type: ['Space'],
        name: 'Home',
        controller: alice.controllerDid
      })
    })

    it('returns null when describing a missing space (404 conflation)', async () => {
      const missing = await alice.space('no-such-space').describe()
      expect(missing).toBeNull()
    })

    it('deletes a space and is idempotent', async () => {
      const space = await alice.createSpace({ name: 'Disposable' })
      await space.delete()
      expect(await space.describe()).toBeNull()
      // Idempotent: deleting again does not throw.
      await space.delete()
    })

    it('configures (updates) an existing space', async () => {
      const space = await alice.createSpace({ name: 'Original' })
      const updated = await space.configure({ name: 'Renamed' })
      expect(updated.name).toBe('Renamed')
      const reread = await space.describe()
      expect(reread?.name).toBe('Renamed')
    })

    it('listSpaces surfaces NotImplementedError (server 501)', async () => {
      await expect(alice.listSpaces()).rejects.toBeInstanceOf(
        NotImplementedError
      )
    })
  })

  describe('collections', () => {
    let space: Space

    beforeAll(async () => {
      space = await alice.createSpace({ name: 'Collections Space' })
    })

    it('creates a collection by id and reads its description', async () => {
      const collection = await space.createCollection({
        id: 'credentials',
        name: 'Verifiable Credentials'
      })
      expect(collection.id).toBe('credentials')
      const description = await collection.describe()
      expect(description).toEqual({
        id: 'credentials',
        type: ['Collection'],
        name: 'Verifiable Credentials'
      })
    })

    it('lists collections in a space', async () => {
      const listing = await space.collections()
      expect(listing).not.toBeNull()
      expect(listing!.totalItems).toBeGreaterThanOrEqual(1)
      expect(listing!.items.some(item => item.id === 'credentials')).toBe(true)
    })

    it('rejects a reserved collection id up front', async () => {
      await expect(space.createCollection({ id: 'policy' })).rejects.toThrow(
        /reserved path segment/
      )
    })

    it('throws NotFoundError adding to a collection in a missing space', async () => {
      const orphan = alice.space('missing-space').collection('c')
      await expect(orphan.add({ hello: 'world' })).rejects.toBeInstanceOf(
        NotFoundError
      )
    })
  })

  describe('resources (JSON)', () => {
    let collection: Collection

    beforeAll(async () => {
      const space = await alice.createSpace({ name: 'Resources Space' })
      collection = await space.createCollection({ id: 'docs', name: 'Docs' })
    })

    it('adds a JSON resource (server-generated id) and gets it back', async () => {
      const result = await collection.add({ name: 'Sample', value: 42 })
      expect(result.id).toBeTruthy()
      expect(result.url).toContain(`/${result.id}`)
      expect(result.contentType).toMatch(/json/)

      const fetched = await collection.get(result.id)
      expect(fetched).toMatchObject({ name: 'Sample', value: 42 })
    })

    it('puts a JSON resource by id (upsert) and lists items', async () => {
      await collection.put('greeting', { message: 'hello' })
      const got = await collection.get('greeting')
      expect(got).toMatchObject({ message: 'hello' })

      await collection.put('greeting', { message: 'updated' })
      const updated = await collection.get('greeting')
      expect(updated).toMatchObject({ message: 'updated' })

      const listing = await collection.list()
      expect(listing).not.toBeNull()
      expect(listing!.items.some(item => item.id === 'greeting')).toBe(true)
    })

    it('returns null getting a missing resource (404 conflation)', async () => {
      expect(await collection.get('no-such-resource')).toBeNull()
    })

    it('deletes a resource via its handle', async () => {
      await collection.put('temp', { tmp: true })
      expect(await collection.get('temp')).not.toBeNull()
      await collection.resource('temp').delete()
      expect(await collection.get('temp')).toBeNull()
    })

    it('rejects a reserved resource id on put', async () => {
      await expect(collection.put('meta', { x: 1 })).rejects.toThrow(
        /reserved path segment/
      )
    })
  })

  describe('resources (binary)', () => {
    let collection: Collection

    beforeAll(async () => {
      const space = await alice.createSpace({ name: 'Binary Space' })
      collection = await space.createCollection({ id: 'files', name: 'Files' })
    })

    it('puts and reads Uint8Array bytes via getBytes/getText', async () => {
      const bytes = new TextEncoder().encode('line 1\nline 2\n')
      await collection.put('note.txt', bytes, { contentType: 'text/plain' })

      const handle = collection.resource('note.txt')
      expect(await handle.getText()).toBe('line 1\nline 2\n')
      expect(await handle.getBytes()).toEqual(bytes)
    })

    it('add() returns a Blob from get() for non-JSON content', async () => {
      const blob = new Blob(['hello blob'], { type: 'text/plain' })
      const result = await collection.add(blob)
      const fetched = await collection.get(result.id)
      expect(fetched).toBeInstanceOf(Blob)
      expect(await (fetched as Blob).text()).toBe('hello blob')
    })

    it('getText/getBytes return null for a missing resource', async () => {
      const handle = collection.resource('absent')
      expect(await handle.getText()).toBeNull()
      expect(await handle.getBytes()).toBeNull()
    })
  })

  describe('delegation', () => {
    let bob: WasClient
    let bobDid: string

    beforeAll(async () => {
      ;({ client: bob, did: bobDid } = await buildClient({
        serverUrl: server.serverUrl
      }))
    })

    it('bob cannot see alice space without a grant', async () => {
      const space = await alice.createSpace({ name: 'Private' })
      const seenByBob = await bob.space(space.id).describe()
      expect(seenByBob).toBeNull()
    })

    it('grants read on a space; recipient reads via fromCapability', async () => {
      const space = await alice.createSpace({ name: 'Shared Space' })
      const zcap = await space.grant({ to: bobDid, actions: ['GET'] })

      const handle = bob.fromCapability(zcap)
      expect(handle).toBeInstanceOf(Space)
      const description = await (handle as Space).describe()
      expect(description?.name).toBe('Shared Space')
    })

    it('grants read on a resource; recipient reads but cannot write', async () => {
      const space = await alice.createSpace({ name: 'Doc Space' })
      const collection = await space.createCollection({ id: 'docs' })
      const added = await collection.add({ secret: 'value' })

      // Lowercase action input is normalized to uppercase in the signed zcap,
      // so it still validates against the server (which expects 'GET').
      const zcap = await alice.grant({
        to: bobDid,
        actions: ['get'],
        target: added.url
      })
      expect(zcap.allowedAction).toEqual(['GET'])

      const handle = bob.fromCapability(zcap)
      expect(handle).toBeInstanceOf(Resource)
      const resource = handle as Resource

      expect(await resource.get()).toMatchObject({ secret: 'value' })
      // The grant is read-only; a write must be denied.
      await expect(resource.put({ secret: 'tampered' })).rejects.toThrow()
    })
  })

  describe('export / import', () => {
    it('exports a space to a tar archive and imports it into another', async () => {
      const source = await alice.createSpace({ name: 'Export Source' })
      const collection = await source.createCollection({
        id: 'notes',
        name: 'Notes'
      })
      await collection.put('first', { body: 'one' })
      await collection.put('second', { body: 'two' })

      const archive = await source.export()
      expect(archive).toBeInstanceOf(Uint8Array)
      expect(archive.byteLength).toBeGreaterThan(0)

      const target = await alice.createSpace({ name: 'Import Target' })
      const stats = await target.import(archive)
      expect(stats.collectionsCreated).toBeGreaterThanOrEqual(1)
      expect(stats.resourcesCreated).toBeGreaterThanOrEqual(2)

      const imported = await target.collection('notes').get('first')
      expect(imported).toMatchObject({ body: 'one' })
    })
  })

  describe('manual request escape hatch', () => {
    it('signs a raw request and returns the raw HttpResponse', async () => {
      const space = await alice.createSpace({ name: 'Raw Space' })
      const response = await alice.request({
        path: `/space/${space.id}`,
        method: 'GET'
      })
      expect(response.status).toBe(200)
      expect((response.data as { name: string }).name).toBe('Raw Space')
    })
  })
})
