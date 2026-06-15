/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The identity (plaintext) resource codec and the per-collection codec
 * resolver. The identity codec wraps the existing `prepareBody` / `parseResource`
 * helpers so plaintext writes and reads are byte-for-byte unchanged. The
 * resolver binds an encrypting codec for a collection iff the injected
 * `EncryptionProvider` supplies one for it (i.e. the client holds keys for it);
 * otherwise it falls back to identity. Encryption is a per-collection client
 * concern, not a backend capability, so this needs no backend round-trip.
 */
import type { HttpResponse } from '@interop/http-client'
import type { EncodedWrite, ResourceCodec } from '../codec.js'
import type { ClientContext } from './request.js'
import { prepareBody, parseResource } from './content.js'
import type { Json } from '../types.js'

/**
 * The default codec: passes plaintext through unchanged. `encode` echoes the
 * caller's `id` (so `put(id, ...)` is a `PUT` and `add(...)`, with no id, stays
 * a server-minting `POST`) and reuses `prepareBody` -- including the
 * filename-extension content-type guess when an id is present. `decode` reuses
 * `parseResource`.
 */
export const identityCodec: ResourceCodec = {
  allowsServerMetadata: true,

  async encode({
    id,
    data,
    contentType
  }: {
    id?: string
    data: Json | Blob | Uint8Array
    contentType?: string
  }): Promise<EncodedWrite> {
    const prepared = prepareBody(data, { contentType, filename: id })
    return {
      id,
      json: prepared.json,
      body: prepared.body,
      contentType: prepared.contentType
    }
  },

  async decode(response: HttpResponse): Promise<Json | Blob> {
    return (await parseResource(response)) as Json | Blob
  }
}

/**
 * Resolves the codec for a collection. Returns {@link identityCodec} unless an
 * {@link EncryptionProvider} is injected and returns a codec for the collection
 * (i.e. the client holds keys for it). No backend round-trip: whether a
 * collection is encrypted is a client/key concern, not a backend capability.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @returns {Promise<ResourceCodec>}
 */
export async function resolveCodec(
  context: ClientContext,
  { spaceId, collectionId }: { spaceId: string; collectionId: string }
): Promise<ResourceCodec> {
  const provider = context.encryption
  if (!provider) {
    return identityCodec
  }
  const codec = await provider.resolveCodec({ spaceId, collectionId })
  return codec ?? identityCodec
}
