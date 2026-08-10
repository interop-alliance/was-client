/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/log` subpath entry: transport for resource logs
 * (the Resource Log Profile, App Connect spec `#resource-log-profile`) -- the
 * hash-linked log format governing key resources co-managed between a
 * wallet's clients and the storage server. Deliberately crypto-free and kept
 * off the `/edv` graph: what lives here is the wire level (strict JSON Lines
 * parse/serialize) and the log-store seam (read-with-etag, compare-and-swap
 * append, guarded genesis create, the read-back `confirmAppend`). Chain
 * verification -- SCID and entry-hash
 * recomputation, proofs, the external-authorization rule, the chain-head pin
 * -- lives in the consuming verifier, which reads and appends through the
 * seam. The wire types themselves come from `@interop/storage-core` and are
 * re-exported here so a consumer imports one package.
 */
export {
  parseResourceLog,
  serializeResourceLog,
  serializeResourceLogEntry
} from './jsonl.js'
export {
  LOG_CONTENT_TYPE,
  resourceLogStore,
  confirmAppend
} from './logStore.js'
export type { ResourceLogStore } from './logStore.js'
export { LogNotConfirmedError } from '../errors.js'
export { WAS_RESOURCE_LOG_METHOD } from '@interop/storage-core'
export type {
  ResourceLogEntry,
  ResourceLogEntryProof,
  ResourceLogGenesisParameters,
  ResourceLogTerminalParameters,
  ResourceLogParameters
} from '@interop/storage-core'
