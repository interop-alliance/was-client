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
 * - `ensureSpaceAndCollection` / `ensureSpace` -- idempotent Space +
 *   Collection provisioning, and its Space half alone (ensure the Space once,
 *   then thread the returned description through every collection).
 * - `isSyncConflictError` / `isSyncNotFoundError` / `isSyncAuthError` /
 *   `isUnknownEpochError` -- the classification contract for the signals
 *   below. A consumer matches by `err.name` and never with `instanceof`,
 *   because every one of these errors is raised inside a seam the app injects
 *   (the port, the caller's `DocCipher`) and that seam can resolve to a second
 *   copy of this package. Reading a property off the matched value, such as
 *   `status` on an auth error, is the intended shape.
 *
 * The 412 conflict / 404 not-found port signals (`WasSyncConflictError` /
 * `WasSyncNotFoundError`), and the opt-in revoked-access signal
 * (`WasSyncAuthError`, raised only under `mapAuthErrors`), live in the client's
 * typed error hierarchy and are re-exported here for convenience -- as are the
 * two decrypt-routing signals, so a crypto-free sync consumer can classify them
 * without importing the `/edv` entry that throws them: the stale-descriptor
 * signal (`UnknownEpochError`: the envelope's epoch is not on the descriptor at
 * all, so re-read it and rebuild the cipher) and the membership signal
 * (`KeyUnwrapError`: the epoch is on the descriptor but this reader holds no
 * key for it, so a refresh cannot help). `EncryptionError`, the fail-closed
 * umbrella `KeyUnwrapError` falls under, rides along. The classes are exported
 * for construction and for a caller inside one resolved copy; across a package
 * boundary the predicates are the contract
 * (`decisions/0001-cross-package-errors-match-by-name.md`).
 */
export { createWasSyncPort, KEY_EPOCH_HEADER, parseEtag } from './port.js'
// The sync subpath's names for the client's own error accessors, so a
// sync-only consumer reads a raw ky/ezcap failure without importing the core
// entry.
export { httpStatus as errorStatus, errorMessage } from '../errors.js'
export { contentCid, cidFrom, deriveSpaceId } from './cid.js'
export { isEncryptedEnvelope } from './envelope.js'
export { createPlaintextDocCipher } from './plaintextCipher.js'
export { ensureSpace, ensureSpaceAndCollection } from './provisioning.js'
export {
  isSyncAuthError,
  isSyncConflictError,
  isSyncNotFoundError,
  isUnknownEpochError
} from './predicates.js'
export {
  EncryptionError,
  KeyUnwrapError,
  UnknownEpochError,
  WasSyncAuthError,
  WasSyncConflictError,
  WasSyncNotFoundError
} from '../errors.js'

export type {
  Json,
  SyncCheckpoint,
  WireDoc,
  SyncPage,
  MasterState,
  WriteAck,
  SyncStatus,
  WasSyncPort,
  DocCipher
} from './types.js'
