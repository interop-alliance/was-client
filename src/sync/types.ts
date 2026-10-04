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
 * collection cipher implements. `SyncStatus` is the closed status vocabulary
 * every replication driver reports one feed's state through.
 */
import type {
  ChangesCheckpoint,
  ChangesPage,
  ResourceChangeDocument,
  ResourceMetaStamp
} from '@interop/storage-core'
import type { CodecRequestContext } from '../codec.js'
import type { Json } from '../types.js'

export type { Json }

/**
 * The resume position in the change feed: the opaque checkpoint string of the
 * last document a pull returned, passed back verbatim to resume strictly after
 * it. It is scoped to the server and collection that issued it and compared by
 * equality only. This is the shared `ChangesCheckpoint` from
 * `@interop/storage-core`.
 */
export type SyncCheckpoint = ChangesCheckpoint

/**
 * One JSON document of the `changes` feed, as the port hands it on: `id` is
 * the WAS resource id and the stored body is under `data`. The port keeps
 * only the feed's `kind: 'resource'` entries with a JSON `contentType`, so
 * `kind` is always `'resource'` here. `updatedAt`,
 * `updatedAtCounter` and `originId` are the content record's write stamp, and
 * the optional nested `meta` is the `/meta` record's. Two revisions of one
 * resource are ordered by `(ms, updatedAtCounter, originId)`, with `ms` the
 * epoch millisecond value of `updatedAt`. The stamp is for comparison and is
 * not an `ifMatch` value. The feed carries the validators themselves: `etag`
 * (content) and `metaEtag` (the `/meta` object), opaque strings quoted
 * exactly as the server emits them, so a puller passes one back verbatim as a
 * conditional write's `ifMatch` without a {@link WasSyncPort.get} first. A
 * tombstone carries `_deleted: true` with no `data`. This is the shared
 * `ResourceChangeDocument` from `@interop/storage-core` with the feed's
 * `deleted` renamed `_deleted`, the member a replication consumer reads, and
 * its two bodies typed as `Json`, the parsed JSON they always are on the wire
 * (the shared type leaves them `unknown`); on an encrypted collection `data`/`custom` are the opaque
 * stored envelope, moved verbatim (decrypt is a projection-time concern the
 * engine's `DocCipher` handles, never the port). `writerId` (optional) rides
 * along on `ChangeDocument` unchanged: the writing agent's attribution label,
 * present when the writer declared one, and carried on a tombstone too as the
 * deleting request's own label, if any. Advisory and never server-verified; a
 * puller uses it to recognize its own writes echoed back. It is not part of
 * the stamp order.
 */
export interface WireDoc extends Omit<
  ResourceChangeDocument,
  'deleted' | 'data' | 'custom'
> {
  _deleted: boolean
  data?: Json
  custom?: Json
}

/**
 * One page of the `changes` feed -- the return shape of {@link
 * WasSyncPort.query} (the shared `ChangesPage`, its documents typed as
 * {@link WireDoc}): the page's `documents` and its resume `checkpoint`, or
 * `checkpoint: null` for an empty (no-change) page.
 */
export interface SyncPage extends Omit<ChangesPage, 'documents'> {
  documents: WireDoc[]
}

/**
 * The current master state of a single resource, read back for the 412-conflict
 * path ({@link WasSyncPort.get}). An absent or tombstoned resource surfaces as
 * `get` resolving `null`, never as a `MasterState`. `updatedAt`,
 * `updatedAtCounter`, `originId`, `meta`, `metaEtag`, `custom`, `createdBy`,
 * `epoch`, and `writerId` are populated from the resource's `/meta` document
 * when it exists.
 *
 * `updatedAt`, `updatedAtCounter` and `originId` are the content record's
 * write stamp, and `meta` is the `/meta` record's own stamp with its
 * generation. Each stamp is copied whole or not at all (`isWriteStamp` /
 * `isMetaStamp` from `@interop/storage-core`). A resource with no metadata
 * yet, or a `/meta` object without a whole stamp, reports an epoch-zero
 * `updatedAt` placeholder with no `updatedAtCounter` or `originId`: a valid,
 * sortable timestamp that sorts before every real one. The change feed
 * remains the authority on ordering; two revisions are compared by their
 * stamps.
 *
 * `etag` and `metaEtag` are the raw, opaque `ETag` validators the content and
 * `/meta` reads returned (absent only where the header did not reach the
 * client) -- pass one back verbatim as a later write's `ifMatch`. No revision
 * number is read out of a validator.
 */
export interface MasterState {
  etag?: string
  updatedAt: string
  updatedAtCounter?: number
  originId?: string
  meta?: ResourceMetaStamp
  metaEtag?: string
  data?: Json
  custom?: Json
  createdBy?: string
  epoch?: string
  writerId?: string
}

/**
 * The acknowledgment a conditional write returns. `etag` is the opaque
 * validator to echo, exactly as the server sent it: pass it back verbatim as
 * a later write's `ifMatch`. It is absent only where the header did not reach
 * the client (for example a cross-origin response without
 * `Access-Control-Expose-Headers: ETag`). The validator is opaque, so the ack
 * carries no revision number. A caller that needs the write's stamp reads it
 * from the change feed or from {@link WasSyncPort.get}.
 */
export interface WriteAck {
  etag?: string
}

/**
 * The injected WAS-access seam. `createWasSyncPort` implements this over
 * `@interop/was-client`'s `was.request()` and the `Collection.changes()` feed;
 * a change engine depends only on this interface. Every method moves the stored
 * body verbatim -- no codec, no key handling. Every method is required,
 * `putMeta` included: a replica that syncs content only simply never calls it.
 */
export interface WasSyncPort {
  /**
   * Pulls one page of the `changes` feed. Omit `checkpoint` for the first page.
   * Returns the page's `documents` and its resume `checkpoint`, or
   * `checkpoint: null` for an empty (no-change) page. The documents are the
   * feed's JSON Resources and their tombstones only. The `checkpoint` resumes
   * past every entry the pull skipped, so a page is empty only at the end of
   * the feed.
   */
  query(options: {
    checkpoint?: SyncCheckpoint
    limit: number
  }): Promise<SyncPage>

  /**
   * Conditionally writes the content body verbatim (`PUT /:id`). Pass
   * `ifNoneMatch: true` for create-if-absent, or `ifMatch` (the opaque `ETag`
   * from a prior read/write, echoed back verbatim) for update-if-unchanged.
   * `epoch` stamps the opaque key-epoch id the body was encrypted under
   * (absent clears any prior stamp). `writerId` declares the writing agent's
   * attribution label (sent as the `Writer-Id` header); per the spec's
   * declare-or-clear rule, omitting it clears any label already stored for
   * this resource, so a caller that wants to keep a prior label must resend
   * it. Returns the new {@link WriteAck}. Throws {@link WasSyncConflictError}
   * on `412`.
   */
  putContent(options: {
    id: string
    data: Json
    ifMatch?: string
    ifNoneMatch?: boolean
    epoch?: string
    writerId?: string
  }): Promise<WriteAck>

  /**
   * Conditionally deletes a resource (writes a tombstone; `DELETE /:id`). Pass
   * `ifMatch` (the opaque `ETag` from a prior read/write, echoed back
   * verbatim) to delete only if unchanged. `writerId` declares the deleting
   * agent's attribution label (sent as the `Writer-Id` header), attributing
   * the tombstone; per the spec's declare-or-clear rule, omitting it clears
   * any label already stored for this resource. Returns the tombstone's new
   * {@link WriteAck}. Throws {@link WasSyncConflictError} on `412`,
   * {@link WasSyncNotFoundError} on `404` (already gone -- a settled outcome
   * for a delete).
   *
   * Resolves `undefined` instead when the port was built with
   * `mapAuthErrors: true` and the target was already absent: there the delete
   * is idempotent, so there is no acked revision to report.
   */
  deleteContent(options: {
    id: string
    ifMatch?: string
    writerId?: string
  }): Promise<WriteAck | undefined>

  /**
   * Conditionally writes the user-writable metadata `custom` (`PUT /:id/meta`).
   * The write fully
   * replaces `custom`, so omitting it writes the CLEARED state (the server
   * clears every property the body leaves out) -- that is how a metadata clear
   * replicates. `writerId` declares the writing agent's attribution label as
   * the request body's top-level `writerId` member; per the spec's
   * declare-or-clear rule for a metadata write, omitting it clears any label
   * already stored for this resource -- a metadata write is itself a
   * revision, and on an encrypted collection it replaces the `custom`
   * envelope wholesale, so keeping a previous writer's label would
   * misattribute it. Returns the new metadata {@link WriteAck}, or `undefined`
   * when the response carried no `ETag`. Throws {@link WasSyncConflictError}
   * on `412`, and {@link WasSyncNotFoundError} on `404` (the resource is gone:
   * a delete race the caller corroborates). A port built with
   * `mapAuthErrors: true` raises {@link WasSyncAuthError} with `status: 404`
   * there instead, since the masked `404` is ambiguous.
   */
  putMeta(options: {
    id: string
    custom?: Json
    ifMatch?: string
    ifNoneMatch?: boolean
    writerId?: string
  }): Promise<WriteAck | undefined>

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
 * - `encrypt` and `encryptUpdate` may surface the `epoch` id a multi-recipient
 *   write encrypted under (the descriptor's `currentEpoch`); absent on a
 *   single-key or plaintext cipher.
 * - `encryptUpdate` is optional -- present only for a mutable, random-id
 *   collection that re-encrypts a head document in place under its existing id
 *   (advancing the envelope `sequence`). A content-addressed cipher (plaintext
 *   or `idDerivation: 'content'`) either omits it or throws: a changed document
 *   is a different id, never an in-place update.
 * - `decrypt` takes the resource id the envelope was stored under (the feed
 *   row's `id`, or the id a {@link WasSyncPort.get} addressed) and verifies the
 *   envelope against it, throwing `IntegrityError` when the envelope was
 *   written for a different id. A missing id throws `ValidationError` rather
 *   than skipping the check. An EDV cipher checks the AEAD-bound
 *   `was.resource` binding, or re-derives a content-derived id from the
 *   ciphertext. The plaintext cipher recomputes the content id. Pass the id
 *   the replica addressed, never the envelope's own cleartext `id`, which the
 *   server controls.
 * - `decrypt` also takes an optional `context`, the signed-request surface a
 *   codec reads a multi-resource document through. With it, an EDV cipher
 *   built with a `spaceId` reassembles a chunked envelope from its chunk
 *   resources (one built without a `spaceId` throws `NotSupportedError`). A
 *   replica gets one from its Collection handle (`collection.codecContext()`).
 *   A context is not the only way to read a chunked envelope: the EDV cipher
 *   (`EdvDocCipher`) also takes a `chunkSource` in its place, which serves the
 *   chunks from bytes the caller holds. With neither, a chunked envelope
 *   throws `EncryptionError`. A binary document decrypts to a `Blob`, and
 *   everything else to `Json`.
 */
export interface DocCipher {
  encrypt(options: {
    data: Json
  }): Promise<{ id: string; envelope: Json; epoch?: string }>
  encryptUpdate?(options: {
    id: string
    data: Json
    current: Json
  }): Promise<{ id: string; envelope: Json; epoch?: string }>
  decrypt(options: {
    id: string
    envelope: Json
    context?: CodecRequestContext
  }): Promise<Json | Blob>
}

/**
 * Per-feed replication status, surfaced to the app's state layer. The
 * vocabulary is closed: a consumer may render a status through a lookup keyed
 * on the string, so a widened value would fail at runtime rather than at
 * compile time.
 */
export type SyncStatus = 'idle' | 'syncing' | 'synced' | 'error'
