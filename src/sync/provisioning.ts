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
 */
import type { SpaceDescription } from '../types.js'
import type { WasClient } from '../WasClient.js'
// A direct module import (not the `./edv` subpath entry), so the crypto-free
// sync module does not pull the EDV crypto graph for one number.
import { EDV_SCHEME_VERSION } from '../edv/constants.js'
import { ValidationError, WasError } from '../errors.js'

/**
 * The Space display name applied at creation when the caller names none.
 */
const DEFAULT_SPACE_NAME = 'WAS Space'

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
 * Ensures the controller's Space exists and one synced collection is
 * configured, without overwriting anything already there. The Space is
 * described first and configured only when absent -- an existing Space keeps
 * its name AND its controller, so `controllerDid` is used only at creation
 * (a joined client re-running this never rewrites the description). The
 * collection likewise: when absent, an `'edv'` collection is created with the
 * encryption descriptor `{ scheme: 'edv', version: EDV_SCHEME_VERSION }`, so
 * the server stores only ciphertext it can never decrypt and validates every
 * write against the declared envelope wire format -- the same version the
 * cipher binds into each envelope's AEAD-protected header, so descriptor and
 * envelopes cannot drift; a `'plaintext'` collection is created without one,
 * with `force` so the descriptor-less upsert can create a fresh collection
 * (running full-tier, a 404 from the pre-merge describe really means absent).
 * An existing collection that lacks a descriptor an `'edv'` spec calls for
 * gets the late in-place declaration (set-once on the server); one that
 * already carries a descriptor -- possibly with appended key epochs -- is
 * left untouched, epochs and display name included. A public collection gets
 * the collection-level world-read grant (`setPublic`, what makes a resource
 * URL in it resolve for anyone) only when its policy does not already say so.
 * Runs full-tier -- the client invokes its own root authority.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.controllerDid {string}   the Space controller (e.g. `did:key`);
 *   used only when the Space does not exist yet
 * @param options.collectionId {string}    the WAS collection id
 * @param [options.encryption] {'edv' | 'plaintext'}   defaults to `'edv'`
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
  spaceDescription
}: {
  was: WasClient
  spaceId: string
  controllerDid: string
  collectionId: string
  encryption?: 'edv' | 'plaintext'
  isPublic?: boolean
  spaceName?: string
  collectionName?: string
  spaceDescription?: SpaceDescription
}): Promise<void> {
  const space = was.space(spaceId)

  if (spaceDescription === undefined) {
    await ensureSpace({ was, spaceId, controllerDid, spaceName })
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
    const current = await collection.describe()
    if (current === null) {
      await collection.configure(
        encryption === 'edv'
          ? {
              name: collectionName,
              current,
              encryption: { scheme: 'edv', version: EDV_SCHEME_VERSION }
            }
          : { name: collectionName, current, force: true }
      )
    } else if (encryption === 'edv' && current.encryption === undefined) {
      // The late in-place declaration: adding a descriptor to a collection
      // that lacks one is allowed (set-once), while re-sending one over an
      // existing descriptor would drop its appended key epochs -- which is
      // exactly why an existing descriptor is never touched.
      await collection.configure({
        name: current.name ?? collectionName,
        current,
        encryption: { scheme: 'edv', version: EDV_SCHEME_VERSION }
      })
    }
    if (isPublic && !(await collection.isPublic())) {
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
 * controller, so `controllerDid` is used only at creation.
 *
 * Costs one `GET` on a settled Space, and one `GET` plus one `PUT` on a fresh
 * one: the description read here is threaded into `configure`, which therefore
 * does not re-read it.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.controllerDid {string}   the Space controller (e.g.
 *   `did:key`); used only when the Space does not exist yet
 * @param [options.spaceName] {string}   the Space display name, applied only at
 *   Space creation; defaults to `'WAS Space'`
 * @returns {Promise<SpaceDescription>}   the Space's description, existing or
 *   just written -- pass it to {@link ensureSpaceAndCollection} as
 *   `spaceDescription` so each collection skips the Space ensure
 */
export async function ensureSpace({
  was,
  spaceId,
  controllerDid,
  spaceName = DEFAULT_SPACE_NAME
}: {
  was: WasClient
  spaceId: string
  controllerDid: string
  spaceName?: string
}): Promise<SpaceDescription> {
  const space = was.space(spaceId)
  try {
    const current = await space.describe()
    if (current !== null) {
      return current
    }
    return await space.configure({
      name: spaceName,
      controller: controllerDid,
      current
    })
  } catch (err) {
    rethrowProvisioningFailure(
      err,
      `Failed to configure WAS space "${spaceId}" for "${controllerDid}".`
    )
  }
}
