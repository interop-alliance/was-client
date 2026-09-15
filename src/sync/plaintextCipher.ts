/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The no-encryption (identity) {@link DocCipher} for a plaintext, content-
 * addressed collection: the stored "envelope" IS the document, and the resource
 * id is the document's content id, so the content id is also the only
 * integrity check a read has: `decrypt` recomputes it and refuses a document
 * stored under an id it does not hash to. Kept free of the `@interop/was-client/edv`
 * crypto graph so a plaintext-only consumer imports nothing it does not need.
 */
import { IntegrityError, requireResourceId } from '../errors.js'
import { contentCid } from './cid.js'
import type { DocCipher, Json } from './types.js'

/**
 * Builds the identity {@link DocCipher} for a plaintext, content-addressed,
 * insert-only collection. `encrypt` is the identity transform with a content-id
 * key; `decrypt` returns the stored body unchanged once its content id matches
 * the resource id it was stored under, and throws {@link IntegrityError}
 * otherwise (`ValidationError` when no id is passed); `encryptUpdate` throws -- a content-addressed document is never
 * updated in place (a changed document is a different id).
 *
 * @param options {object}
 * @param options.collectionId {string}   labels the `encryptUpdate` and
 *   `decrypt` errors
 * @returns {DocCipher}
 */
export function createPlaintextDocCipher({
  collectionId
}: {
  collectionId: string
}): DocCipher {
  return {
    async encrypt({ data }: { data: Json }) {
      return { id: contentCid(data), envelope: data }
    },

    async encryptUpdate() {
      throw new Error(
        `Collection "${collectionId}" is content-addressed plaintext; ` +
          'documents are never updated in place.'
      )
    },

    async decrypt({ id, envelope }: { id: string; envelope: Json }) {
      requireResourceId({ id, collectionId })
      const derived = contentCid(envelope)
      if (derived !== id) {
        throw new IntegrityError(
          `Cannot read resource "${id}" of collection "${collectionId}": its ` +
            `content id is "${derived}", so the document was stored under an ` +
            'id it was not written for. The server altered the document or ' +
            'served it under another id.'
        )
      }
      return envelope
    }
  }
}
