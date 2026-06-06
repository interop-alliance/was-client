/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Test harness: spins up the WAS reference server in-process over a temp-dir
 * filesystem backend (mirroring the server's own per-suite pattern), and builds
 * Ed25519 signers / `WasClient`s whose controller DIDs the server can resolve.
 */
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { createApp } from 'was-teaching-server/dist/server.js'
import { FileSystemBackend } from 'was-teaching-server/dist/backends/filesystem.js'

import { WasClient } from '../../src/index.js'
import type { ISigner } from '../../src/index.js'

/**
 * A running in-process server and the means to tear it down.
 */
export interface TestServer {
  serverUrl: string
  close(): Promise<void>
}

/**
 * Starts a WAS server on the given port, backed by a fresh temp directory.
 *
 * @param options {object}
 * @param options.port {number}
 * @returns {Promise<TestServer>}
 */
export async function startServer({
  port
}: {
  port: number
}): Promise<TestServer> {
  const serverUrl = `http://localhost:${port}`
  const dataDir = await mkdtemp(path.join(tmpdir(), 'was-client-test-'))
  const app = createApp({
    serverUrl,
    backend: new FileSystemBackend({ dataDir })
  })
  await app.listen({ port })
  return {
    serverUrl,
    close: async () => {
      await app.close()
      await rm(dataDir, { recursive: true, force: true })
    }
  }
}

/**
 * A freshly generated identity: its `did:key` controller and a signer.
 */
export interface Identity {
  did: string
  signer: ISigner
}

/**
 * Generates a random Ed25519 identity whose `did:key` the server can resolve.
 *
 * @returns {Promise<Identity>}
 */
export async function generateIdentity(): Promise<Identity> {
  const keyPair = await Ed25519VerificationKey.generate()
  const did = `did:key:${keyPair.fingerprint()}`
  keyPair.id = `${did}#${keyPair.fingerprint()}`
  keyPair.controller = did
  return { did, signer: keyPair.signer() }
}

/**
 * Builds a `WasClient` for a fresh identity against the given server.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @returns {Promise<{ client: WasClient; did: string }>}
 */
export async function buildClient({
  serverUrl
}: {
  serverUrl: string
}): Promise<{ client: WasClient; did: string }> {
  const { did, signer } = await generateIdentity()
  const client = WasClient.fromSigner({ serverUrl, signer })
  return { client, did }
}
