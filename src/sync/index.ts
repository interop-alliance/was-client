/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/sync` subpath entry: cross-replica synchronization
 * support over WAS. Kept off the core entry so a consumer opts in.
 *
 * - `createWasSyncPort` -- the `WasSyncPort` over `was.request()` + the
 *   `changes` feed, moving stored bodies verbatim (no codec) for one Space +
 *   Collection.
 * - `contentCid` / `cidFrom` / `deriveSpaceId` -- content-addressed ids and
 *   Space-id derivation, byte-identical across replicas.
 * - `createPlaintextDocCipher` / `isEncryptedEnvelope` -- the identity cipher
 *   for a plaintext content-addressed collection, and the envelope predicate,
 *   both free of the `@interop/was-client/edv` crypto graph.
 * - `ensureSpaceAndCollection` -- idempotent Space + Collection provisioning.
 *
 * The 412 conflict / 404 not-found port signals (`WasSyncConflictError` /
 * `WasSyncNotFoundError`) live in the client's typed error hierarchy and are
 * re-exported here for convenience.
 */
export {
  createWasSyncPort,
  WAS_KEY_EPOCH_HEADER,
  formatEtag,
  parseEtag,
  errorStatus
} from './port.js'
export { contentCid, cidFrom, deriveSpaceId } from './cid.js'
export { isEncryptedEnvelope } from './envelope.js'
export { createPlaintextDocCipher } from './plaintextCipher.js'
export { ensureSpaceAndCollection } from './provisioning.js'
export { WasSyncConflictError, WasSyncNotFoundError } from '../errors.js'

export type {
  Json,
  SyncCheckpoint,
  WireDoc,
  SyncPage,
  MasterState,
  WasSyncPort,
  DocCipher
} from './types.js'
