/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Tests for the cryptosuite `WasClient.fromSigner` signs delegation proofs
 * with. The client signs with `eddsa-jcs-2022`, which canonicalizes with JCS
 * rather than URDNA2015, so delegating never runs a JSON-LD canonicalization
 * and never needs a document loader to serve the suite's context.
 *
 * These sign for real (no stub `ZcapClient`) and verify the result, because the
 * question the swap raises is whether signing survives the document loader the
 * client actually gets: `fromSigner` passes none, so ezcap falls through to
 * `@interop/zcap`'s default loader, which serves the zcap context and jsigs'
 * strict loader and nothing else. `EddsaJcs2022` exposes no static
 * `CONTEXT`/`CONTEXT_URL`, so ezcap's auto-loader branch never fires either.
 *
 * The mixed-chain cases cover the transition, during which a chain can carry
 * both suites across its links.
 */
import { describe, it, expect } from 'vitest'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  Ed25519Signature2020,
  createVerifyCryptosuite
} from '@interop/ed25519-signature'
import { DataIntegrityProof } from '@interop/data-integrity-proof'
import { ZcapClient } from '@interop/ezcap'
import jsigs from '@interop/jsonld-signatures'
import {
  CapabilityDelegation,
  createRootCapability,
  documentLoader as zcapDocumentLoader
} from '@interop/zcap'
import type {
  ICapabilityDelegationProof,
  IDocumentLoader,
  IRemoteDocument
} from '@interop/data-integrity-core'

import { WasClient } from '../../src/index.js'
import type { IDelegatedZcap, ISigner } from '../../src/index.js'

const SERVER_URL = 'https://was.example'
const SPACE_URL = `${SERVER_URL}/space/space-1`
const TARGET_URL = `${SPACE_URL}/notes/`

/**
 * The verification-method and DID documents the verifying loader serves,
 * keyed by URL. Each `signingKey()` call registers both for the key it mints.
 */
const servedDocuments = new Map<string, unknown>()

/**
 * Mints an Ed25519 key as a `did:key` controller, registering its Multikey
 * verification method and DID document with the test loader. The method is
 * served with the type the key's own export publishes (`Multikey`); both
 * suites resolve it through `Ed25519VerificationKey.from`, which accepts
 * Multikey and the `Ed25519VerificationKey2020` restatement alike.
 *
 * @returns {Promise<object>}
 * @returns return.did {string}       the key's `did:key` controller
 * @returns return.signer {ISigner}   a signer over that key
 */
async function signingKey(): Promise<{
  did: string
  signer: ISigner
}> {
  const keyPair = await Ed25519VerificationKey.generate()
  const did = `did:key:${keyPair.publicKeyMultibase}`
  const methodId = `${did}#${keyPair.publicKeyMultibase}`
  keyPair.controller = did
  keyPair.id = methodId
  const method = await keyPair.export({ publicKey: true, includeContext: true })
  servedDocuments.set(methodId, method)
  servedDocuments.set(did, {
    '@context': ['https://www.w3.org/ns/did/v1', method['@context']],
    id: did,
    verificationMethod: [method],
    capabilityDelegation: [methodId],
    capabilityInvocation: [methodId]
  })
  return { did, signer: keyPair.signer() as ISigner }
}

/**
 * The loader used on the *verify* side only: serves the DIDs and verification
 * methods minted above, and defers everything else (the zcap context) to
 * `@interop/zcap`'s default loader. The signing side deliberately gets no
 * loader at all -- that is what these tests are checking.
 *
 * @param url {string}
 * @returns {Promise<IRemoteDocument>}
 */
const verifyingLoader: IDocumentLoader = async function verifyingLoader(
  url: string
): Promise<IRemoteDocument> {
  const document = servedDocuments.get(url)
  if (document !== undefined) {
    return { contextUrl: null, documentUrl: url, document }
  }
  return zcapDocumentLoader(url)
}

/**
 * Both delegation-proof suites as a verifier array, the shape the verify side
 * takes for the transition. `DataIntegrityProof.matchProof` keys on
 * `proof.type` and `proof.cryptosuite`, so neither suite ever sees the other's
 * proof.
 *
 * @returns {Array<object>}   the two verifier suites
 */
function bothSuites() {
  return [
    new Ed25519Signature2020(),
    new DataIntegrityProof({ cryptosuite: createVerifyCryptosuite() })
  ]
}

/**
 * The single delegation proof on a signed zcap. `IDelegatedZcap.proof` allows a
 * proof set; ezcap signs exactly one.
 *
 * @param zcap {IDelegatedZcap}
 * @returns {ICapabilityDelegationProof}
 */
function delegationProof(zcap: IDelegatedZcap): ICapabilityDelegationProof {
  const { proof } = zcap
  return Array.isArray(proof) ? (proof[0] as ICapabilityDelegationProof) : proof
}

/**
 * Registers the Space's root capability with the test loader, controlled by
 * `controller`, and returns its id. This stands in for what the server serves
 * at `urn:zcap:root:<encoded Space URL>`: every chain minted by `grant()` on a
 * Space-tree target roots here.
 *
 * @param controller {string}   the DID the Space's root capability names
 * @returns {string}
 */
function serveSpaceRoot(controller: string): string {
  const root = createRootCapability({ controller, invocationTarget: SPACE_URL })
  servedDocuments.set(root.id, root)
  return root.id
}

/**
 * Verifies a delegated zcap against a chain rooted at the Space, with both
 * suites offered. `allowTargetAttenuation` matches how the WAS server verifies:
 * grants into the Space tree root at the Space and carry the narrower target as
 * an attenuated `invocationTarget` (see `internal/grant.ts`).
 *
 * @param zcap {IDelegatedZcap}
 * @param expectedRootCapability {string}
 * @returns {Promise<{verified: boolean, error?: unknown}>}
 */
async function verifyDelegation(
  zcap: IDelegatedZcap,
  expectedRootCapability: string
): Promise<{ verified: boolean; error?: unknown }> {
  const suite = bothSuites()
  return jsigs.verify(zcap, {
    suite,
    purpose: new CapabilityDelegation({
      expectedRootCapability,
      allowTargetAttenuation: true,
      suite
    }),
    documentLoader: verifyingLoader
  })
}

/**
 * A `ZcapClient` on the pre-transition suite, used to build the parent and
 * child links a mixed chain needs. `fromSigner` no longer produces one of
 * these; the transition still does, from clients that have not bumped yet.
 *
 * @param signer {ISigner}
 * @returns {ZcapClient}
 */
function legacySuiteClient(signer: ISigner): ZcapClient {
  return new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: signer,
    delegationSigner: signer
  } as ConstructorParameters<typeof ZcapClient>[0])
}

describe('fromSigner delegation proofs', () => {
  it('signs with eddsa-jcs-2022 under the loader the client actually gets', async () => {
    const alice = await signingKey()
    const rootId = serveSpaceRoot(alice.did)
    const was = WasClient.fromSigner({
      serverUrl: SERVER_URL,
      signer: alice.signer
    })

    const zcap = await was.grant({
      to: 'did:example:bob',
      actions: ['get'],
      target: TARGET_URL
    })

    expect(delegationProof(zcap).type).toBe('DataIntegrityProof')
    expect(delegationProof(zcap).cryptosuite).toBe('eddsa-jcs-2022')
    // The suite appends its context to the signed zcap even though JCS
    // canonicalization never asks for it.
    expect(zcap['@context']).toContain(
      'https://w3id.org/security/data-integrity/v2'
    )
    expect((await verifyDelegation(zcap, rootId)).verified).toBe(true)
  })

  it('re-delegates its own grant, chain dereferencing included', async () => {
    const alice = await signingKey()
    const bob = await signingKey()
    const rootId = serveSpaceRoot(alice.did)
    const parent = await WasClient.fromSigner({
      serverUrl: SERVER_URL,
      signer: alice.signer
    }).grant({ to: bob.did, actions: ['get'], target: TARGET_URL })

    const child = await WasClient.fromSigner({
      serverUrl: SERVER_URL,
      signer: bob.signer
    }).grant({
      to: 'did:example:carol',
      actions: ['get'],
      capability: parent,
      target: TARGET_URL
    })

    expect(delegationProof(child).cryptosuite).toBe('eddsa-jcs-2022')
    expect((await verifyDelegation(child, rootId)).verified).toBe(true)
  })

  it('signs a new-suite child under an Ed25519Signature2020 parent', async () => {
    const alice = await signingKey()
    const bob = await signingKey()
    const rootId = serveSpaceRoot(alice.did)
    const legacyParent = (await legacySuiteClient(alice.signer).delegate({
      controller: bob.did,
      invocationTarget: TARGET_URL,
      capability: rootId,
      allowedActions: ['GET']
    })) as IDelegatedZcap

    const child = await WasClient.fromSigner({
      serverUrl: SERVER_URL,
      signer: bob.signer
    }).grant({
      to: 'did:example:carol',
      actions: ['get'],
      capability: legacyParent,
      target: TARGET_URL
    })

    expect(delegationProof(legacyParent).type).toBe('Ed25519Signature2020')
    expect(delegationProof(child).cryptosuite).toBe('eddsa-jcs-2022')
    expect((await verifyDelegation(child, rootId)).verified).toBe(true)
  })

  it('pins the reverse mixed link: an old-suite client cannot re-delegate a JCS-signed parent on its default loader', async () => {
    const alice = await signingKey()
    const bob = await signingKey()
    const parent = await WasClient.fromSigner({
      serverUrl: SERVER_URL,
      signer: alice.signer
    }).grant({ to: bob.did, actions: ['get'], target: TARGET_URL })

    // URDNA2015 expands the parent embedded in `proof.capabilityChain`, which
    // now carries the data-integrity context. Neither ezcap's auto-loader
    // branch nor jsigs' strict loader serves it, so the failure is at signing
    // time on the old client, before any server sees the chain. The fix is on
    // that client -- a loader that serves the data-integrity context, or the
    // suite bump -- so this asserts the hazard rather than a WAS client
    // behavior. It flipping to a pass means the hazard is gone.
    await expect(
      legacySuiteClient(bob.signer).delegate({
        controller: 'did:example:carol',
        invocationTarget: TARGET_URL,
        capability: parent,
        allowedActions: ['GET']
      })
    ).rejects.toThrow('https://w3id.org/security/data-integrity/v2')
  })
})
