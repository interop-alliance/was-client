/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Idempotent, non-clobbering Space + Collection provisioning for a synced
 * collection. Everything is create-if-absent: an existing Space description,
 * an existing encryption descriptor (which may carry a key-epoch roster other
 * clients encrypt under), and an existing access policy are never overwritten,
 * so ANY controller-tier client -- including one that joined a Space some
 * other wallet provisioned -- can re-run it to heal a torn provisioning run.
 * On a fully settled Space it issues only reads.
 *
 * This module ensures the CONTAINER only and stays crypto-free: an `'edv'`
 * collection is declared encrypted here, but its key-epoch roster -- which
 * every encrypted collection must carry before any read or write routes
 * (epoch-from-birth) -- is installed by the EDV-bearing second step,
 * `ensureFirstEpoch` in `@interop/was-client/edv`.
 *
 * Three collection modes: `'edv'` (the client-written encryption descriptor),
 * `'plaintext'` (no descriptor), and `'governed'` (a Collection whose
 * `encryption` member the server derives from its history log). A `'governed'`
 * collection is created descriptor-less here and declared governed afterwards,
 * by the caller's guarded create of the log.
 */
import type {
  CollectionDescription,
  IZcap,
  SpaceDescription
} from '../types.js'
import type { WasClient } from '../WasClient.js'
// A direct module import (not the `./edv` subpath entry), so the crypto-free
// sync module does not pull the EDV crypto graph for one number.
import { EDV_SCHEME_VERSION } from '../edv/constants.js'
import { ValidationError, WasError } from '../errors.js'
import { compareAndSwap } from '../internal/cas.js'
import { isGovernedDescriptor } from '../internal/describe.js'

/**
 * The Space display name applied at creation when the caller names none.
 */
const DEFAULT_SPACE_NAME = 'WAS Space'

/**
 * The encryption descriptor declared on a fresh (or not yet encrypted)
 * collection when the caller asks for `encryption: 'edv'`.
 */
const EDV_DESCRIPTOR = { scheme: 'edv', version: EDV_SCHEME_VERSION } as const

/**
 * Rethrows a failed provisioning step. A typed client error propagates
 * UNCHANGED, because what a caller does next depends on which one it is: an
 * `AuthRequiredError` (a revoked or expired grant) means stop retrying and
 * prompt for a reconnect, a `ConflictError` (`encryption-immutable`) means the
 * descriptor is already settled by another client, and a `WasServerError` is
 * worth a retry. Wrapping every failure in a bare `Error` made all of them
 * indistinguishable at the caller. Anything untyped -- which carries no such
 * signal to preserve -- is wrapped with the step's context instead.
 *
 * @param err {unknown}   the caught failure
 * @param context {string}   what the step was trying to do
 * @returns {never}   always throws
 */
function rethrowProvisioningFailure(err: unknown, context: string): never {
  if (err instanceof WasError) {
    throw err
  }
  throw new Error(context, { cause: err })
}

/**
 * The read-then-guarded-create both ensures share: the value is read and, when
 * present, kept as-is; when absent, `create` runs the `If-None-Match: *` write,
 * and when that fails for ANY reason the value is re-read, and a value now
 * present is adopted as the winner of a create race instead of failing. The race is detected by the re-read rather than by the
 * failure's status because the server answers a lost race with whatever check
 * the rival's description trips first: a 412 from the precondition, but also
 * a 400 or 409 from the encryption-descriptor transition rules when the rival
 * already installed key epochs. When nothing can be read back, the create's
 * own failure is rethrown, so a genuine failure keeps its type.
 *
 * A `create` that resolves `undefined` (a server that answered the create with
 * no body) also falls through to the re-read; that value being unreadable is
 * the one case reported as its own error.
 *
 * @param options {object}
 * @param options.read {function}   reads the value; `null` when absent
 * @param options.create {function}   the guarded write; resolves the created
 *   value, or `undefined` when the server echoed none
 * @param options.unreadable {string}   the error message when a create
 *   succeeded but the value cannot be read back
 * @returns {Promise<{ value: T; created: boolean }>}   the value now present
 *   and whether this call created it
 */
async function readOrCreate<T>({
  read,
  create,
  unreadable
}: {
  read: () => Promise<T | null>
  create: () => Promise<T | undefined>
  unreadable: string
}): Promise<{ value: T; created: boolean }> {
  const current = await read()
  if (current !== null) {
    return { value: current, created: false }
  }
  let created = false
  let failure: unknown
  try {
    const value = await create()
    created = true
    if (value !== undefined) {
      return { value, created }
    }
  } catch (err) {
    failure = err
  }
  const latest = await read()
  if (latest !== null) {
    return { value: latest, created }
  }
  if (created) {
    throw new ValidationError(unreadable)
  }
  throw failure
}

/**
 * Ensures the controller's Space exists and one synced collection is
 * configured, without overwriting anything already there. The Space is
 * described first and created only when absent -- an existing Space keeps
 * its name AND its controller, so `controllerDid` is used only at creation
 * (a joined client re-running this never rewrites the description). The
 * collection likewise: when absent, an `'edv'` collection is created with the
 * encryption descriptor `{ scheme: 'edv', version: EDV_SCHEME_VERSION }`, so
 * the server stores only ciphertext it can never decrypt and validates every
 * write against the declared envelope wire format -- the same version the
 * cipher binds into each envelope's AEAD-protected header, so descriptor and
 * envelopes cannot drift; a `'plaintext'` or `'governed'` collection is created
 * without one. Both creates are guarded (`If-None-Match: *`), so two clients
 * booting at once cannot both create, and the loser adopts the winner's
 * description instead of failing. Against a server that ignores the
 * precondition the create is an unconditional upsert, and the loser of a race
 * can overwrite the winner's display name; the server merges the rest of the
 * winner's description forward.
 *
 * An existing collection that lacks the descriptor an `'edv'` spec calls for
 * gets the late in-place declaration (set-once on the server); one that
 * already carries a descriptor -- possibly with appended key epochs -- is
 * left untouched, epochs and display name included. An existing `'governed'`
 * collection is never written to: the server refuses to govern a Description
 * that carries a client-written descriptor (`encryption-immutable`), and a
 * governed Collection's served `encryption` is the derived member, which a
 * Description PUT may not carry (`encryption-history-log-governed`). So an
 * existing collection whose descriptor is client-written (no `history`
 * member) cannot become governed, and a `'governed'` spec over it throws
 * `ValidationError` here rather than letting the caller's log create fail
 * with the server's 409. A public collection gets the collection-level
 * world-read grant (`setPublic`, what makes a resource URL in it resolve for
 * anyone) only when its policy does not already say so. Every request invokes
 * the root capability, or `capability` when the caller holds a delegated one.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.controllerDid {string}   the Space controller (e.g. `did:key`);
 *   used only when the Space does not exist yet
 * @param options.collectionId {string}    the WAS collection id
 * @param [options.encryption] {'edv' | 'plaintext' | 'governed'}   how the
 *   collection's `encryption` member is settled; defaults to `'edv'`.
 *   `'edv'` declares the descriptor here, `'plaintext'` declares none, and
 *   `'governed'` leaves the member to the server, which derives it from the
 *   collection's history log. Declaring that governance is the caller's next
 *   step, through the log's guarded create --
 *   `logGovernedDescriptorStore(...).create` or
 *   `resourceLogStore({ collection }).create`
 * @param [options.isPublic] {boolean}   grant collection-level world read
 * @param [options.spaceName] {string}   the Space display name, applied only at
 *   Space creation; defaults to `'WAS Space'`
 * @param [options.collectionName] {string}   the collection display name,
 *   applied only at collection creation; defaults to the collection id
 * @param [options.spaceDescription] {SpaceDescription}   the Space's
 *   description, when the caller has already ensured the Space (with
 *   {@link ensureSpace}). Supplying it skips the Space half entirely, which is
 *   what keeps a caller provisioning N collections from ensuring one Space N
 *   times over; omit it and the Space is ensured here as before. Its `id` must
 *   be `spaceId` -- a description of some other Space throws
 *   `ValidationError`, since skipping the ensure would leave that Space
 *   unprovisioned
 * @param [options.capability] {IZcap}   an invocation capability every
 *   request rides (a delegated Space-subtree zcap, say); the root capability
 *   is invoked otherwise. A capability scoped below the bare Space URL cannot
 *   reach the Space half, so a caller holding one supplies `spaceDescription`
 * @returns {Promise<void>}
 */
export async function ensureSpaceAndCollection({
  was,
  spaceId,
  controllerDid,
  collectionId,
  encryption = 'edv',
  isPublic = false,
  spaceName = DEFAULT_SPACE_NAME,
  collectionName = collectionId,
  spaceDescription,
  capability
}: {
  was: WasClient
  spaceId: string
  controllerDid: string
  collectionId: string
  encryption?: 'edv' | 'plaintext' | 'governed'
  isPublic?: boolean
  spaceName?: string
  collectionName?: string
  spaceDescription?: SpaceDescription
  capability?: IZcap
}): Promise<void> {
  const space = was.space(spaceId, { capability })

  if (spaceDescription === undefined) {
    await ensureSpace({ was, spaceId, controllerDid, spaceName, capability })
  } else if (spaceDescription.id !== spaceId) {
    // Supplying a description skips the Space half entirely, so a caller
    // holding descriptions for several Spaces that passes the wrong one
    // provisions a collection into a Space this call never ensured. Caught
    // here, that is a misuse with a name; caught later, it is an opaque
    // collection-configure failure.
    throw new ValidationError(
      `Space description id "${spaceDescription.id}" does not name the space ` +
        `being provisioned ("${spaceId}").`
    )
  }

  try {
    const collection = space.collection(collectionId)
    // A `'governed'` or `'plaintext'` collection takes the descriptor-less
    // create: a governed `encryption` member is the server's to derive.
    const { value: read, created } = await readOrCreate({
      read: () => collection.describeWithEtag(),
      create: () =>
        collection.replaceDescription(
          encryption === 'edv'
            ? { name: collectionName, encryption: EDV_DESCRIPTOR }
            : { name: collectionName },
          { ifNoneMatch: true }
        ),
      unreadable:
        `Collection "${collectionId}" in space "${spaceId}" was ` +
        'created but cannot be read back.'
    })
    const current = read.description
    if (
      encryption === 'governed' &&
      current.encryption !== undefined &&
      !isGovernedDescriptor(current.encryption)
    ) {
      throw new ValidationError(
        `Collection "${collectionId}" in space "${spaceId}" carries a ` +
          'client-written encryption descriptor, so it cannot be governed by ' +
          'a history log: the server keeps a declared descriptor immutable.'
      )
    }
    if (!created && encryption === 'edv' && current.encryption === undefined) {
      // The late in-place declaration: adding a descriptor to a collection
      // that lacks one is allowed (set-once), while re-sending one over an
      // existing descriptor would drop its appended key epochs -- which is
      // exactly why an existing descriptor is never touched. The write is
      // compare-and-swapped against the description just read, so a rival
      // declaration landing in between is re-read and adopted as-is rather
      // than tripping `encryption-immutable` or being overwritten.
      let reusable: typeof read | null = read
      await compareAndSwap<CollectionDescription>({
        store: {
          read: async () => {
            const latest =
              reusable !== null ? reusable : await collection.describeWithEtag()
            reusable = null
            if (latest === null) {
              throw new ValidationError(
                `Collection "${collectionId}" in space "${spaceId}" vanished ` +
                  'while its encryption was being declared.'
              )
            }
            return { value: latest.description, etag: latest.etag }
          },
          // Replace semantics: every writable field is carried forward.
          replace: async (next, { ifMatch }) => {
            await collection.replaceDescription(
              {
                name: next.name,
                backend: next.backend,
                encryption: next.encryption
              },
              { ifMatch }
            )
          }
        },
        operation: 'Encryption declaration',
        mutate: latest =>
          latest.encryption === undefined
            ? {
                ...latest,
                name: latest.name ?? collectionName,
                encryption: EDV_DESCRIPTOR
              }
            : null
      })
    }
    // A collection this call just created has no policy document yet, so the
    // read that would find it non-public is skipped.
    if (isPublic && (created || !(await collection.isPublic()))) {
      await collection.setPublic()
    }
  } catch (err) {
    rethrowProvisioningFailure(
      err,
      `Failed to configure collection "${collectionId}" in space "${spaceId}".`
    )
  }
}

/**
 * Ensures the controller's Space exists, without overwriting anything already
 * there -- the Space half of {@link ensureSpaceAndCollection}, split out so a
 * caller provisioning SEVERAL collections into one Space pays for it once
 * rather than once per collection. An existing Space keeps its name AND its
 * controller, so `controllerDid` is used only at creation. The create is
 * guarded (`If-None-Match: *`), so a Space created concurrently keeps its
 * `type` array (accepted at creation only) and is adopted by the loser.
 *
 * Costs one `GET` on a settled Space, and one `GET` plus one guarded `PUT`
 * (`If-None-Match: *`) on a fresh one; a lost create race costs one more `GET`
 * to adopt the winner.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.controllerDid {string}   the Space controller (e.g.
 *   `did:key`); used only when the Space does not exist yet
 * @param [options.spaceName] {string}   the Space display name, applied only at
 *   Space creation; defaults to `'WAS Space'`
 * @param [options.capability] {IZcap}   an invocation capability both
 *   requests ride; the root capability is invoked otherwise
 * @returns {Promise<SpaceDescription>}   the Space's description, existing or
 *   just written -- pass it to {@link ensureSpaceAndCollection} as
 *   `spaceDescription` so each collection skips the Space ensure
 */
export async function ensureSpace({
  was,
  spaceId,
  controllerDid,
  spaceName = DEFAULT_SPACE_NAME,
  capability
}: {
  was: WasClient
  spaceId: string
  controllerDid: string
  spaceName?: string
  capability?: IZcap
}): Promise<SpaceDescription> {
  const space = was.space(spaceId, { capability })
  try {
    const { value } = await readOrCreate({
      read: () => space.describe(),
      create: async () =>
        (
          await space.replaceDescription(
            { name: spaceName, controller: controllerDid },
            { ifNoneMatch: true }
          )
        ).description,
      unreadable: `Space "${spaceId}" was created but cannot be read back.`
    })
    return value
  } catch (err) {
    rethrowProvisioningFailure(
      err,
      `Failed to configure WAS space "${spaceId}" for "${controllerDid}".`
    )
  }
}
