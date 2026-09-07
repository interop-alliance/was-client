/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The log-governed case of the descriptor-store seam. Two stores:
 *
 * - `logGovernedDescriptorStore` is the generic one, over any
 *   `ResourceLogStore` (a Resource-hosted key roster, a Collection's history
 *   log): reads resolve to the log's VERIFIED head state -- chain, proofs,
 *   external authorization against a caller-supplied controller view, and the
 *   chain-head pin all checked by `@interop/vh-resource-log` before any
 *   descriptor is handed out -- and writes become signed appends (verified-head
 *   build, the library's pre-write pass, compare-and-swap, read-back and pin).
 *   It also carries the sealing sweep, the idempotent backstop append that
 *   advances a log's head past the controller's latest membership change.
 * - `logGovernedCollectionDescriptorStore` is the pointer-following one, over a
 *   Collection whose served `encryption` member is a point-state projection of
 *   its governing history log, named by the projection's `history` member. It
 *   dispatches on that member, and for a governed Collection reads through the
 *   generic store and then holds the served projection to the verified head:
 *   a projection that does not JCS-equal the head's state after stripping
 *   `history` is refused.
 *
 * The generic read boundary (`readGovernedEpochConfiguration`) and the
 * `WasEpochConfiguration` state shape are shared with the wallet's user key
 * roster, which wraps the generic store. What stays outside this module is
 * DID-method resolution: the controller port and the pin store are injected by
 * the caller.
 */
import { canonicalize } from 'json-canonicalize'
import { RESOURCE_LOG_METHOD } from '@interop/storage-core'
import {
  buildResourceLogEntry,
  buildResourceLogGenesis,
  confirmAppend,
  isResourceLogConflictError,
  readResourceLog,
  ResourceLogClosedError,
  ResourceLogIntegrityError,
  sealResourceLog,
  verifyResourceLog,
  verifyResourceLogAppend,
  type ResourceLogController,
  type ResourceLogPinStore,
  type ResourceLogSigner,
  type ResourceLogStore,
  type VerifiedResourceLog
} from '@interop/vh-resource-log'
import type { Collection } from '../Collection.js'
import { PreconditionFailedError, ValidationError } from '../errors.js'
import { unreadableDescriptionError } from '../internal/describe.js'
import { resourceLogStore } from '../log/logStore.js'
import type { CollectionDescription, CollectionEncryption } from '../types.js'
import type { EncryptionDescriptorStore } from './descriptorStore.js'

/**
 * The state-document schema identifier an encryption descriptor carries in a
 * governed log entry, per the Encrypted Collections profile.
 */
export const EPOCH_CONFIGURATION_STATE_TYPE = 'WasEpochConfiguration'

/**
 * The log-entry `state` for a descriptor: the point-state projection's
 * `history` member stripped (it belongs to the projection only; the verifier
 * refuses an entry whose state carries it) and the schema identifier stamped.
 *
 * @param descriptor {CollectionEncryption}
 * @returns {CollectionEncryption & { type: string }}
 */
export function toEpochConfigurationState(
  descriptor: CollectionEncryption
): CollectionEncryption & { type: string } {
  const { history: _history, ...rest } = descriptor
  return { ...rest, type: EPOCH_CONFIGURATION_STATE_TYPE }
}

/**
 * The one governed epoch-configuration read: the fail-closed boundary that
 * decides whether a served log state may be treated as an encryption
 * descriptor. Resolves the controller view, reads and fully verifies the log
 * (chain, proofs, external authorization, and the chain-head pin, via
 * `readResourceLog`), and refuses a verified head whose state is not a
 * `WasEpochConfiguration` rather than handing it out as a descriptor.
 * Resolves `null` for an absent log (the pre-genesis state) only while no pin
 * is held for it; under a held pin an absent log is refused as a `rollback`,
 * the library's rule. Every trusted descriptor read goes through this helper,
 * so a hardening applied here reaches all of them.
 *
 * @param options {object}
 * @param options.store {ResourceLogStore}   the log's transport seam
 * @param options.resolveController {function}
 *   `() => Promise<ResourceLogController>` -- the caller's currently verified
 *   controller view, resolved per operation
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head
 *   pin for this log
 * @param options.logId {string}   the pin-slot key for this log, from
 *   `resourceLogPinId`
 * @returns {Promise<{ verified: VerifiedResourceLog; descriptor: CollectionEncryption; etag?: string } | null>}
 */
export async function readGovernedEpochConfiguration({
  store,
  resolveController,
  pinStore,
  logId
}: {
  store: ResourceLogStore
  resolveController: () => Promise<ResourceLogController>
  pinStore: ResourceLogPinStore
  logId: string
}): Promise<{
  verified: VerifiedResourceLog
  descriptor: CollectionEncryption
  etag?: string
} | null> {
  const controller = await resolveController()
  const current = await readResourceLog({
    store,
    controller,
    expectedMethod: RESOURCE_LOG_METHOD,
    pinStore,
    logId
  })
  if (current === null) {
    return null
  }
  const state = current.verified.state
  if (state.type !== EPOCH_CONFIGURATION_STATE_TYPE) {
    throw new ResourceLogIntegrityError(
      `The governed descriptor log carries state of type ` +
        `"${state.type}", not "${EPOCH_CONFIGURATION_STATE_TYPE}".`
    )
  }
  return {
    verified: current.verified,
    descriptor: state as CollectionEncryption,
    etag: current.etag
  }
}

/**
 * An `EncryptionDescriptorStore` over a resource log, which can therefore be
 * SEALED: `seal()` runs the sealing sweep (`sealResourceLog`) against the
 * caller's currently verified controller view, appending the idempotent no-op
 * backstop entry when the log's head still carries a controller version
 * before the controller's latest membership change -- `'sealed'` -- and
 * writing nothing when the log is already sealed, absent, or has no
 * membership change to seal against -- `'noop'`. A store built without a
 * signer has no `create` and refuses `replace` and `seal`.
 */
export interface LogGovernedDescriptorStore extends EncryptionDescriptorStore {
  seal(): Promise<'sealed' | 'noop'>
}

/**
 * Translates the log-store port's CAS conflict (the library's
 * `ResourceLogConflictError`, matched by `name` -- it is minted in the store
 * adapter's package, which may resolve its own library copy) into the
 * `PreconditionFailedError` the `EncryptionDescriptorStore` port documents
 * and the edv recipient loops rebase on. Any other error -- an untranslated
 * `PreconditionFailedError` included -- returns unchanged.
 *
 * @param err {unknown}
 * @returns {unknown}   the error to rethrow
 */
function asDescriptorStoreConflict(err: unknown): unknown {
  if (isResourceLogConflictError(err)) {
    return new PreconditionFailedError((err as Error).message, {
      status: 412,
      cause: err
    })
  }
  return err
}

/**
 * Builds the generic log-governed `EncryptionDescriptorStore` over a resource
 * log's transport seam. Because the seam is the same one the edv recipient
 * primitives (`initRecipients` / `addRecipient` / `removeRecipient`, with
 * their compare-and-swap retry loops) already drive, they run over a log
 * without knowing it: a lost race on the log is translated back to the
 * `PreconditionFailedError` those loops rebase on.
 *
 * The controller view is resolved per operation, never held, so a caller
 * that just edited its controller document hands every subsequent write the
 * view it now verifies. A replace builds its entry on the head the most
 * recent read on this instance verified, pinned to that read's `etag`, so a
 * stale head loses the compare-and-swap instead of forking; the library's
 * pre-write pass verifies the candidate as a reader would before it lands,
 * so a refused entry never poisons the served log for other readers.
 *
 * @param options {object}
 * @param options.log {ResourceLogStore}   the log's transport seam
 * @param options.resolveController {function}
 *   `() => Promise<ResourceLogController>` -- the caller's currently verified
 *   controller view, resolved per operation
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head pin
 *   for this log
 * @param options.logId {string}   the pin-slot key for this log, from
 *   `resourceLogPinId`
 * @param [options.signer] {ResourceLogSigner}   this client's enrolled
 *   signing key, for the appends this store writes; absent, the store is
 *   read-only
 * @returns {LogGovernedDescriptorStore}
 */
export function logGovernedDescriptorStore({
  log,
  resolveController,
  pinStore,
  logId,
  signer
}: {
  log: ResourceLogStore
  resolveController: () => Promise<ResourceLogController>
  pinStore: ResourceLogPinStore
  logId: string
  signer?: ResourceLogSigner
}): LogGovernedDescriptorStore {
  // The verified log observed by the most recent read or confirmed append on
  // this store instance, and the controller view it was verified under: the
  // library's pre-write pass reads the head's controller version as an index
  // into THAT view's version list, so a replace may only run it against a
  // view this one is a prefix of.
  let lastVerified: VerifiedResourceLog | null = null
  let lastVerifiedView: ResourceLogController | null = null

  function requireSigner(operation: string): ResourceLogSigner {
    if (signer === undefined) {
      throw new ValidationError(
        `Cannot ${operation} the governed descriptor: this store was built ` +
          'without a signer, so it is read-only.'
      )
    }
    return signer
  }

  async function settle({
    entry,
    controller
  }: {
    entry: Parameters<typeof confirmAppend>[0]['entry']
    controller: ResourceLogController
  }): Promise<void> {
    const readBack = await confirmAppend({ store: log, entry })
    const confirmed = await verifyResourceLog({
      entries: readBack.entries,
      controller,
      expectedMethod: RESOURCE_LOG_METHOD,
      pin: await pinStore.read({ logId })
    })
    await pinStore.write({ logId, pin: confirmed.pin })
    lastVerified = confirmed
    lastVerifiedView = controller
  }

  const store: LogGovernedDescriptorStore = {
    async read() {
      let view: ResourceLogController | null = null
      const current = await readGovernedEpochConfiguration({
        store: log,
        resolveController: async () => {
          view = await resolveController()
          return view
        },
        pinStore,
        logId
      })
      if (current === null) {
        lastVerified = null
        lastVerifiedView = null
        return null
      }
      lastVerified = current.verified
      lastVerifiedView = view
      return { descriptor: current.descriptor, etag: current.etag }
    },

    async replace(descriptor, { ifMatch }) {
      const logSigner = requireSigner('replace')
      if (ifMatch === undefined) {
        throw new ValidationError(
          'Cannot replace the governed descriptor: the backend returned no ' +
            'validator, and the profile forbids an unconditional write.'
        )
      }
      // An append builds on the head this instance last verified. A replace
      // that no read on this instance precedes -- a caller seeding the
      // compare-and-swap from a read another instance made -- acquires that
      // head now; the caller's validator still guards the append, so a seed
      // behind the served log loses the compare-and-swap as it would anywhere.
      if (lastVerified === null) {
        await store.read()
      }
      if (lastVerified === null) {
        throw new ValidationError(
          'Cannot replace the governed descriptor: the log is absent.'
        )
      }
      if (lastVerified.terminal) {
        throw new ResourceLogClosedError({ nextLog: lastVerified.terminal })
      }
      const controller = await resolveController()
      // The pre-write pass's precondition, enforced rather than assumed: the
      // view that verified `lastVerified` must be a prefix of this one (the
      // controller log is append-only, so carrying its head version is
      // enough). A resolver that regressed is reported as the port's conflict
      // class, so the edv machinery re-reads under the current view and
      // rebases instead of the pass refusing on a bound that indexes another
      // list.
      const verifiedHead =
        lastVerifiedView?.versionIds[lastVerifiedView.versionIds.length - 1]
      if (
        verifiedHead !== undefined &&
        !controller.versionIds.includes(verifiedHead)
      ) {
        throw new PreconditionFailedError(
          'Cannot replace the governed descriptor: the controller view ' +
            `resolved for this write does not carry version "${verifiedHead}", ` +
            'which the preceding read verified against; re-read and retry.',
          { status: 412 }
        )
      }
      const entry = await buildResourceLogEntry({
        head: lastVerified.head,
        state: toEpochConfigurationState(descriptor),
        controller,
        signer: logSigner
      })
      await verifyResourceLogAppend({ entry, controller, head: lastVerified })
      try {
        await log.append(entry, { ifMatch })
      } catch (err) {
        throw asDescriptorStoreConflict(err)
      }
      await settle({ entry, controller })
    },

    async seal() {
      const logSigner = requireSigner('seal')
      const controller = await resolveController()
      // Reuse the log view the most recent read or confirmed append on this
      // store instance verified: a rotation that just appended carries a
      // version past the removal, so the sweep resolves noop with no
      // re-fetch, and a stale view is safe (sealResourceLog's append path
      // re-reads before writing).
      const { sealed, verified } = await sealResourceLog({
        store: log,
        controller,
        expectedMethod: RESOURCE_LOG_METHOD,
        pinStore,
        logId,
        signer: logSigner,
        ...(lastVerified === null ? {} : { verified: lastVerified })
      })
      if (verified !== null) {
        lastVerified = verified
        lastVerifiedView = controller
      }
      return sealed ? 'sealed' : 'noop'
    }
  }

  if (signer !== undefined) {
    const logSigner = signer
    store.create = async descriptor => {
      // A held pin means this client has already verified a log in this slot,
      // so there is nothing to create. The pinned read refuses an absent log
      // as a rollback (a host hiding the pinned log must not be answered with
      // a fresh genesis over it); a served one is the lost create race,
      // translated so the edv machinery re-reads and adopts it.
      if ((await pinStore.read({ logId })) !== null) {
        await readGovernedEpochConfiguration({
          store: log,
          resolveController,
          pinStore,
          logId
        })
        throw new PreconditionFailedError(
          'The resource log create lost its guarded-create race: a log is ' +
            'already pinned and served; re-read and adopt it.',
          { status: 412 }
        )
      }
      const controller = await resolveController()
      const genesis = await buildResourceLogGenesis({
        state: toEpochConfigurationState(descriptor),
        method: RESOURCE_LOG_METHOD,
        controller,
        signer: logSigner
      })
      // The pre-write pass for a genesis: verified as a one-entry log before
      // anything is created, so a non-member signer never leaves behind a
      // log no reader accepts. `pin: null` is deliberate: the candidate is
      // not served history, and continuity belongs to the read-back.
      try {
        await verifyResourceLog({
          entries: [genesis],
          controller,
          expectedMethod: RESOURCE_LOG_METHOD,
          pin: null
        })
      } catch (err) {
        // A refused genesis against a log that already exists is a lost
        // create race (matched by name: the class may come from another
        // library copy), translated to the port's conflict class so the edv
        // machinery re-reads and adopts the winner's descriptor. With no log
        // served, or on any other class (a port bug), the error propagates
        // with nothing adopted.
        if (!(
          err instanceof Error && err.name === 'ResourceLogIntegrityError'
        )) {
          throw err
        }
        if ((await log.read()) === null) {
          throw err
        }
        throw new PreconditionFailedError(
          'The resource log create lost its guarded-create race: the genesis ' +
            `was refused pre-write (${err.message}) and a log is already ` +
            'served; re-read and adopt it.',
          { status: 412, cause: err }
        )
      }
      try {
        await log.create(genesis)
      } catch (err) {
        throw asDescriptorStoreConflict(err)
      }
      await settle({ entry: genesis, controller })
    }
  }

  return store
}

/**
 * Builds the `EncryptionDescriptorStore` over a Collection that may be
 * log-governed. `read()` fetches the Collection Description and dispatches on
 * its `encryption` member: absent, the store resolves `null` (a fresh
 * Collection that `create` makes log-governed with a genesis entry); present
 * without `history`, it is the plain point-state descriptor and the store
 * behaves exactly like `collectionDescriptorStore`; present with `history`,
 * the store refuses a `history.method` other than the profile's format
 * identifier before any fetch, refuses a `history.resource` that is not this
 * Collection's own log URL, opens the log through `resourceLogStore`, reads
 * it through the generic {@link logGovernedDescriptorStore}, and refuses a
 * projection that does not JCS-equal the verified head's state after
 * stripping `history`. The descriptor handed out is that verified state with
 * the served `history` pointer kept on it.
 *
 * Writes on a governed Collection are the generic store's signed appends and
 * need `signer`; without one the store is read-only for governed collections
 * (`replace` refuses, `create` is absent). A lost race surfaces as
 * `PreconditionFailedError` (412), the port's documented class.
 *
 * @param options {object}
 * @param options.collection {Collection}
 * @param options.resolveController {function}
 *   `() => Promise<ResourceLogController>` -- the caller's currently verified
 *   controller view, resolved per operation
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head pin
 *   for this log
 * @param options.logId {string}   the pin-slot key for this log, from
 *   `resourceLogPinId`
 * @param [options.signer] {ResourceLogSigner}   this client's enrolled
 *   signing key, for the appends this store writes
 * @returns {EncryptionDescriptorStore}
 */
export function logGovernedCollectionDescriptorStore({
  collection,
  resolveController,
  pinStore,
  logId,
  signer
}: {
  collection: Collection
  resolveController: () => Promise<ResourceLogController>
  pinStore: ResourceLogPinStore
  logId: string
  signer?: ResourceLogSigner
}): EncryptionDescriptorStore {
  const governed = logGovernedDescriptorStore({
    log: resourceLogStore({ collection }),
    resolveController,
    pinStore,
    logId,
    signer
  })
  // The description observed by the most recent read: its sibling fields are
  // forwarded by a point-state replace (the server's replace semantics would
  // otherwise drop them), and its `encryption` member decides which write path
  // a replace takes. Safe to carry even if stale: every write is pinned to the
  // same read's validator, so a concurrent change fails the CAS instead.
  let described: CollectionDescription | undefined

  async function readGoverned(
    projection: CollectionEncryption & {
      history: { method: string; resource: string }
    }
  ): Promise<{ descriptor: CollectionEncryption; etag?: string }> {
    const { history, ...pointState } = projection
    if (history.method !== RESOURCE_LOG_METHOD) {
      throw new ResourceLogIntegrityError(
        `The descriptor's history names the format "${history.method}", ` +
          `not "${RESOURCE_LOG_METHOD}".`
      )
    }
    if (!sameUrl(history.resource, collection.historyLogUrl)) {
      throw new ResourceLogIntegrityError(
        `The descriptor's history names the log "${history.resource}", ` +
          `not this Collection's own log "${collection.historyLogUrl}".`
      )
    }
    const current = await governed.read()
    if (current === null) {
      throw new ResourceLogIntegrityError(
        'The descriptor names a governing log, but the Collection serves none.'
      )
    }
    // The generic store's descriptor IS the verified head's state.
    if (canonicalize(pointState) !== canonicalize(current.descriptor)) {
      throw new ResourceLogIntegrityError(
        'The served descriptor does not match the verified head of its ' +
          'governing log.'
      )
    }
    return {
      descriptor: { ...current.descriptor, history },
      etag: current.etag
    }
  }

  const store: EncryptionDescriptorStore = {
    async read() {
      const current = await collection.describeWithEtag()
      if (current === null) {
        throw unreadableDescriptionError({
          operation: 'manage recipients',
          advice: 'Use a capability that can read the Collection Description.'
        })
      }
      described = current.description
      const descriptor = current.description.encryption
      if (descriptor === undefined) {
        return null
      }
      if (descriptor.scheme !== 'edv') {
        throw new ValidationError(
          'Cannot manage recipients: this collection is not declared ' +
            "encrypted with the 'edv' scheme."
        )
      }
      if (descriptor.history === undefined) {
        return { descriptor, etag: current.etag }
      }
      return readGoverned(
        descriptor as CollectionEncryption & {
          history: { method: string; resource: string }
        }
      )
    },

    async replace(descriptor, { ifMatch }) {
      if (described === undefined) {
        await store.read()
      }
      if (described?.encryption?.history !== undefined) {
        await governed.replace(descriptor, { ifMatch })
        return
      }
      await collection.replaceDescription(
        {
          name: described?.name,
          backend: described?.backend,
          encryption: descriptor
        },
        { ifMatch }
      )
    }
  }

  if (governed.create !== undefined) {
    const create = governed.create
    store.create = descriptor => create(descriptor)
  }

  return store
}

/**
 * Whether two absolute URLs name the same resource, compared normalized (so
 * a differently cased host or a default port does not read as a mismatch).
 *
 * @param left {string}
 * @param right {string}
 * @returns {boolean}
 */
function sameUrl(left: string, right: string): boolean {
  try {
    return new URL(left).href === new URL(right).href
  } catch {
    return false
  }
}
