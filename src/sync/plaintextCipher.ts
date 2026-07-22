/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The no-encryption (identity) {@link DocCipher} for a plaintext, content-
 * addressed collection: the stored "envelope" IS the document, and the resource
 * id is the document's content id. Kept free of the `@interop/was-client/edv`
 * crypto graph so a plaintext-only consumer imports nothing it does not need.
 */
import { contentCid } from './cid.js'
import type { DocCipher, Json } from './types.js'

/**
 * Builds the identity {@link DocCipher} for a plaintext, content-addressed,
 * insert-only collection. `encrypt` is the identity transform with a content-id
 * key; `decrypt` returns the stored body unchanged; `encryptUpdate` throws -- a
 * content-addressed document is never updated in place (a changed document is a
 * different id).
 *
 * @param options {object}
 * @param options.collectionId {string}   labels the `encryptUpdate` error
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

    async decrypt({ envelope }: { envelope: Json }) {
      return envelope
    }
  }
}
