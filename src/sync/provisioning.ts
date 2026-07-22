/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Idempotent Space + Collection provisioning for a synced collection. Re-running
 * is safe: the server upserts the Space and allows a late encryption-marker
 * declaration, so reconnecting an existing account is a no-op upgrade.
 */
import type { WasClient } from '../WasClient.js'

/**
 * Ensures the controller's Space exists and one synced collection is configured.
 * An `'edv'` collection declares the encryption marker `{ scheme: 'edv' }` (so
 * the server stores only ciphertext it can never decrypt); a `'plaintext'`
 * collection is configured without one, with `force` so the marker-less upsert
 * can create a fresh collection (running with the root capability, a 404 from
 * the pre-merge describe really means absent). A public collection additionally
 * gets a collection-level world-read grant (`setPublic`), which is what makes a
 * resource URL in it resolve for anyone. Runs full-tier -- the client invokes
 * its own root capability.
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
        ? { name: collectionName, encryption: { scheme: 'edv' } }
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
