/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Wire and port types for cross-replica WAS synchronization.
 *
 * The change-feed wire model (`SyncCheckpoint`, `WireDoc`, and one page of the
 * feed) is the shared WAS data model from `@interop/storage-core`, re-exported
 * here under replication-facing names so a sync consumer imports one module.
 * `WasSyncPort` and `MasterState` are the injectable access seam the change
 * engine depends on, and `DocCipher` is the encrypt/decrypt seam a per-
 * collection cipher implements.
 */
import type {
  ChangeDocument,
  ChangesCheckpoint,
  ChangesPage
} from '@interop/storage-core'
import type { Json } from '../types.js'

export type { Json }

/**
 * The keyset position in the change feed: the `{ id, updatedAt }` of the last
 * document a pull returned, passed back verbatim to resume strictly after it.
 * `id` is the total-order tiebreaker within a single `updatedAt`. This is the
 * shared `ChangesCheckpoint` from `@interop/storage-core` -- server time only,
 * an opaque position token, never compared against a device clock.
 */
export type SyncCheckpoint = ChangesCheckpoint

/**
 * One document as it travels on the `changes` feed wire: `id` is the WAS
 * resource id, `version` the content revision (the push `If-Match` ETag), and
 * the stored body is under `data`. A tombstone carries `_deleted: true` with no
 * `data`. This is the shared `ChangeDocument` from `@interop/storage-core`; on
 * an encrypted collection `data`/`custom` are the opaque stored envelope, moved
 * verbatim (decrypt is a projection-time concern the engine's `DocCipher`
 * handles, never the port).
 */
export type WireDoc = ChangeDocument

/**
 * One page of the `changes` feed -- the return shape of {@link WasSyncPort.query}
 * (the shared `ChangesPage`): the page's `documents` and its resume
 * `checkpoint`, or `checkpoint: null` for an empty (no-change) page.
 */
export type SyncPage = ChangesPage

/**
 * The current master state of a single resource, read back for the 412-conflict
 * path ({@link WasSyncPort.get}). `deleted` distinguishes a tombstone from a
 * live resource. `updatedAt`, `metaVersion`, `custom`, `createdBy`, and `epoch`
 * are populated from the resource's `/meta` document when it exists; a resource
 * with no metadata yet reports an epoch-zero `updatedAt` placeholder (a valid,
 * sortable timestamp -- the change feed remains the authority on ordering).
 */
export interface MasterState {
  version: number
  updatedAt: string
  deleted: boolean
  metaVersion?: number
  data?: Json
  custom?: Json
  createdBy?: string
  epoch?: string
}

/**
 * The injected WAS-access seam. `createWasSyncPort` implements this over
 * `@interop/was-client`'s `was.request()` and the `Collection.changes()` feed;
 * a change engine depends only on this interface. Every method moves the stored
 * body verbatim -- no codec, no key handling.
 *
 * `putMeta` is optional: a replica that syncs only content (never the user-
 * writable `/meta` `custom`) may omit it. All other methods are required.
 */
export interface WasSyncPort {
  /**
   * Pulls one page of the `changes` feed. Omit `checkpoint` for the first page.
   * Returns the page's `documents` and its resume `checkpoint`, or
   * `checkpoint: null` for an empty (no-change) page.
   */
  query(options: { checkpoint?: SyncCheckpoint; limit: number }): Promise<{
    documents: WireDoc[]
    checkpoint: SyncCheckpoint | null
  }>

  /**
   * Conditionally writes the content body verbatim (`PUT /:id`). Pass
   * `ifNoneMatch: true` for create-if-absent, or `ifMatch` (a quoted ETag over
   * the content `version`) for update-if-unchanged. `epoch` stamps the opaque
   * key-epoch id the body was encrypted under (absent clears any prior stamp).
   * Returns the new server `version` (parsed from the write's `ETag`). Throws
   * {@link WasSyncConflictError} on `412`.
   */
  putContent(options: {
    id: string
    data: Json
    ifMatch?: string
    ifNoneMatch?: boolean
    epoch?: string
  }): Promise<number>

  /**
   * Conditionally deletes a resource (writes a tombstone; `DELETE /:id`). Pass
   * `ifMatch` (a quoted ETag over the content `version`) to delete only if
   * unchanged. Returns the tombstone's new server `version`. Throws
   * {@link WasSyncConflictError} on `412`, {@link WasSyncNotFoundError} on `404`
   * (already gone -- a settled outcome for a delete).
   */
  deleteContent(options: { id: string; ifMatch?: string }): Promise<number>

  /**
   * Conditionally writes the user-writable metadata `custom` (`PUT /:id/meta`).
   * Optional -- present only on a port that syncs metadata. Throws
   * {@link WasSyncConflictError} on `412`.
   */
  putMeta?(options: {
    id: string
    custom: Json
    ifMatch?: string
    ifNoneMatch?: boolean
  }): Promise<void>

  /**
   * Re-reads a single resource's current master state for the 412-conflict
   * assembler. Returns `null` when the resource is genuinely absent OR a
   * tombstone (the server's `GET` returns `404` for both -- indistinguishable,
   * mapped to deletion-wins by the callers).
   */
  get(options: { id: string }): Promise<MasterState | null>
}

/**
 * A per-collection document cipher: encrypts a JSON document into its stored
 * body (minting the resource id) and decrypts a stored body back. Minting the
 * id once, at write time, is what makes the same document converge on the same
 * bytes -- and the same content-derived id -- on every replica.
 *
 * The members reconcile a plaintext (identity) cipher, a single-recipient EDV
 * cipher, and a multi-recipient (key-epoch) EDV cipher:
 *
 * - `encrypt` may surface the `epoch` id a multi-recipient write encrypted
 *   under (the marker's `currentEpoch`); absent on a single-key or plaintext
 *   cipher.
 * - `encryptUpdate` is optional -- present only for a mutable, random-id
 *   collection that re-encrypts a head document in place under its existing id
 *   (advancing the envelope `sequence`). A content-addressed cipher (plaintext
 *   or `idDerivation: 'content'`) either omits it or throws: a changed document
 *   is a different id, never an in-place update.
 */
export interface DocCipher {
  encrypt(options: {
    data: Json
  }): Promise<{ id: string; envelope: Json; epoch?: string }>
  encryptUpdate?(options: {
    id: string
    data: Json
    current: Json
  }): Promise<{ id: string; envelope: Json }>
  decrypt(options: { envelope: Json }): Promise<Json>
}
