/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `createEdvEncryption`: the EDV keystore for the handle seam, and the one
 * {@link EncryptionProvider} in this package that points a codec at a server.
 * It sits beside `wasTransportFactory` rather than beside the {@link EdvCodec}
 * class, because it is the online half of the codec seam: a build with no
 * server behind it (the local-replica doc cipher, `buildEdvCodec` and
 * `encryptOnlyEdvCodec`) reaches the codec without evaluating this module or
 * the transport behind it.
 */
import type { EncryptionProvider } from '../codec.js'
import { DEFAULT_CONTENT_TYPE } from './constants.js'
import {
  DEFAULT_MAX_BLOB_BYTES,
  EDV_SCHEME,
  buildEdvCodec,
  descriptorDefect,
  guardEncryptionDescriptor
} from './EdvCodec.js'
import type { EdvKeys } from './EdvCodec.js'
import { wasTransportFactory } from './transportFactory.js'

/**
 * Builds an {@link EncryptionProvider} for the `edv` scheme: a pure **keystore**
 * that turns a collection's keys into an {@link EdvCodec}. Pass the result as
 * `WasClient`'s `encryption` option.
 *
 * It does **not** decide which collections are encrypted -- that policy is the
 * Collection's `encryption` descriptor (or a per-handle override). Core calls
 * `codecFor` only for a collection already known to be encrypted; this provider
 * then supplies the keys: the override-supplied `keys` when present, else
 * `resolveKeys({ spaceId, collectionId })`. `resolveKeys` returning `null` means
 * "I hold no keys for this collection", so core fails closed (it does **not**
 * mean plaintext -- the descriptor/override already decided that). A non-`edv`
 * scheme yields `null` (this provider does not handle it).
 *
 * @param options {object}
 * @param options.resolveKeys {function}   the keystore: returns the collection's
 *   `{ keyAgreementKey, keyResolver }`, or `null` if this client holds no keys
 *   for it (fail-closed -- not a plaintext signal)
 * @param [options.contentType] {string}   stored envelope content type;
 *   defaults to `application/json`. Pass `JOSE_CONTENT_TYPE`
 *   (`application/jose+json`) against a server that registers an
 *   `application/*+json` parser.
 * @param [options.maxBlobBytes] {number}   the size in raw bytes above which a
 *   binary `add()` is routed to the chunked-stream path instead of one document
 *   (default 512 KiB, sized so a single-document envelope stays under a
 *   server's ~1 MiB JSON body cap; raise it against a server with a larger
 *   limit). A routing threshold, not a hard cap.
 * @param [options.chunkSize] {number}   the size of each encrypted chunk a
 *   routed write emits, in bytes (default 1 MiB). Each chunk is one upload, so
 *   it must stay under the backend's `maxUploadBytes` constraint (the
 *   encrypted chunk is somewhat larger than `chunkSize`, so leave headroom).
 *   This is not checked client-side: the shared backend probe reads the
 *   descriptor's affordance tokens, not its `constraints`, so a chunk over the
 *   limit is rejected by the server with a `PayloadTooLargeError` (413) and
 *   the failed write's document stub is then cleaned up.
 * @param [options.idDerivation] {string}   how `add()` mints a document id.
 *   `'random'` (default) is the classic mutable-document model: a random
 *   `generateId()` id, updated in place via `sequence`. `'content'` derives the
 *   id from the encrypted envelope's JWE ciphertext
 *   (`EdvDocumentCipher.deriveId`), making documents content-addressed and
 *   therefore immutable (an "update" is delete-old + add-new) -- the model a
 *   replicating store wants, since the id is stable across replicas with no
 *   mapping table. Both formats pass the same EDV id check; the explicit-id
 *   `put(id, ...)` path is unaffected either way.
 * @returns {EncryptionProvider}
 */
export function createEdvEncryption({
  resolveKeys,
  contentType = DEFAULT_CONTENT_TYPE,
  maxBlobBytes = DEFAULT_MAX_BLOB_BYTES,
  chunkSize,
  idDerivation = 'random'
}: {
  resolveKeys: (ref: {
    spaceId: string
    collectionId: string
  }) => Promise<EdvKeys | null>
  contentType?: string
  maxBlobBytes?: number
  chunkSize?: number
  idDerivation?: 'random' | 'content'
}): EncryptionProvider {
  return {
    canRoute({ scheme, encryption }) {
      return scheme === EDV_SCHEME && descriptorDefect(encryption) === null
    },

    async codecFor({ spaceId, collectionId, scheme, encryption, keys }) {
      if (scheme !== EDV_SCHEME) {
        return null
      }
      // Guard the descriptor before consulting the keystore, so a collection
      // whose descriptor cannot be opened reports THAT rather than the vaguer
      // "holds no keys" the null return below would produce. `buildEdvCodec`
      // guards again for callers that reach it directly; the guard is pure, so
      // running it twice costs nothing.
      guardEncryptionDescriptor({
        label: `${spaceId}/${collectionId}`,
        encryption
      })
      // Prefer override-supplied keys; otherwise consult the keystore.
      const resolved =
        (keys as EdvKeys | undefined) ??
        (await resolveKeys({ spaceId, collectionId }))
      if (!resolved) {
        return null
      }
      return buildEdvCodec({
        label: `${spaceId}/${collectionId}`,
        transportFactory: wasTransportFactory({
          spaceId,
          collectionId,
          contentType
        }),
        collectionId,
        encryption,
        keys: resolved,
        contentType,
        maxBlobBytes,
        ...(chunkSize !== undefined && { chunkSize }),
        idDerivation
      })
    }
  }
}
