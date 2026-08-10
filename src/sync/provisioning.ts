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
import type { WasClient } from '../WasClient.js'
// A direct module import (not the `./edv` subpath entry), so the crypto-free
// sync module does not pull the EDV crypto graph for one number.
import { EDV_SCHEME_VERSION } from '../edv/constants.js'

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
 * @returns {Promise<void>}
 */
export async function ensureSpaceAndCollection({
  was,
  spaceId,
  controllerDid,
  collectionId,
  encryption = 'edv',
  isPublic = false,
  spaceName = 'WAS Space',
  collectionName = collectionId
}: {
  was: WasClient
  spaceId: string
  controllerDid: string
  collectionId: string
  encryption?: 'edv' | 'plaintext'
  isPublic?: boolean
  spaceName?: string
  collectionName?: string
}): Promise<void> {
  const space = was.space(spaceId)

  try {
    if ((await space.describe()) === null) {
      await space.configure({ name: spaceName, controller: controllerDid })
    }
  } catch (err) {
    throw new Error(
      `Failed to configure WAS space "${spaceId}" for "${controllerDid}".`,
      { cause: err }
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
              encryption: { scheme: 'edv', version: EDV_SCHEME_VERSION }
            }
          : { name: collectionName, force: true }
      )
    } else if (encryption === 'edv' && current.encryption === undefined) {
      // The late in-place declaration: adding a descriptor to a collection
      // that lacks one is allowed (set-once), while re-sending one over an
      // existing descriptor would drop its appended key epochs -- which is
      // exactly why an existing descriptor is never touched.
      await collection.configure({
        name: current.name ?? collectionName,
        encryption: { scheme: 'edv', version: EDV_SCHEME_VERSION }
      })
    }
    if (isPublic && !(await collection.isPublic())) {
      await collection.setPublic()
    }
  } catch (err) {
    throw new Error(
      `Failed to configure collection "${collectionId}" in space "${spaceId}".`,
      { cause: err }
    )
  }
}
