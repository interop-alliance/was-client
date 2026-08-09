/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Idempotent Space + Collection provisioning for a synced collection. Re-running
 * is safe: the server upserts the Space and allows a late encryption-descriptor
 * declaration, so reconnecting an existing account is a no-op upgrade.
 */
import type { WasClient } from '../WasClient.js'
// A direct module import (not the `./edv` subpath entry), so the crypto-free
// sync module does not pull the EDV crypto graph for one number.
import { EDV_SCHEME_VERSION } from '../edv/constants.js'

/**
 * Ensures the controller's Space exists and one synced collection is
 * configured. An `'edv'` collection declares the encryption descriptor `{
 * scheme: 'edv', version: EDV_SCHEME_VERSION }`, so the server stores only
 * ciphertext it can never decrypt and validates every write against the
 * declared envelope wire format -- the same version the cipher binds into each
 * envelope's AEAD-protected header, so descriptor and envelopes cannot drift;
 * a `'plaintext'` collection is configured without one, with `force` so the
 * descriptor-less upsert can create a fresh collection (running with the root
 * capability, a 404 from the pre-merge describe really means absent). A public
 * collection additionally gets a collection-level world-read grant
 * (`setPublic`), which is what makes a resource URL in it resolve for anyone.
 * Runs full-tier -- the client invokes its own root capability.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.controllerDid {string}   the Space controller (e.g. `did:key`)
 * @param options.collectionId {string}    the WAS collection id
 * @param [options.encryption] {'edv' | 'plaintext'}   defaults to `'edv'`
 * @param [options.isPublic] {boolean}   grant collection-level world read
 * @param [options.spaceName] {string}   the Space display name; defaults to
 *   `'WAS Space'`
 * @param [options.collectionName] {string}   the collection display name;
 *   defaults to the collection id
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
    await space.configure({ name: spaceName, controller: controllerDid })
  } catch (err) {
    throw new Error(
      `Failed to configure WAS space "${spaceId}" for "${controllerDid}".`,
      { cause: err }
    )
  }

  try {
    const collection = space.collection(collectionId)
    await collection.configure(
      encryption === 'edv'
        ? {
            name: collectionName,
            encryption: { scheme: 'edv', version: EDV_SCHEME_VERSION }
          }
        : { name: collectionName, force: true }
    )
    if (isPublic) {
      await collection.setPublic()
    }
  } catch (err) {
    throw new Error(
      `Failed to configure collection "${collectionId}" in space "${spaceId}".`,
      { cause: err }
    )
  }
}
