/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared write orchestration. `sendEncodedWrite` turns a codec's
 * {@link EncodedWrite} plus a conditional-write precondition into request
 * headers and sends it (the shape `Collection.add` and `Resource.put` would
 * otherwise each re-implement). `upsertResource` layers the upsert flow on
 * top: the conditional-codec pre-read of the current document, the
 * codec-vs-caller precondition selection, and the masked-404 policy for a
 * document that exists but is not readable with the bound capability.
 */
import type { HttpResponse } from '@interop/http-client'
import type { EncodedWrite, ResourceCodec } from '../codec.js'
import { PreconditionFailedError, ValidationError } from '../errors.js'
import type { IZcap, ResourceData } from '../types.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { encodedPrecondition, writeHeaders } from './conditional.js'
import type { WritePrecondition } from './conditional.js'

/**
 * Sends an encoded write (`PUT`/`POST`) to a resource path, applying the
 * encoded body (`json` or `body`), its content-type, and the conditional-write
 * precondition. A write is never a `read`, so the response is always present
 * (errors throw via `send`).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.path {string}                  the resource path to write
 * @param options.method {string}                `PUT` or `POST`
 * @param options.encoded {EncodedWrite}         the codec's encoded write
 * @param [options.capability] {IZcap}
 * @param [options.precondition] {WritePrecondition}   conditional-write headers
 * @returns {Promise<HttpResponse>}
 */
export async function sendEncodedWrite(
  context: ClientContext,
  {
    path,
    method,
    encoded,
    capability,
    precondition
  }: {
    path: string
    method: string
    encoded: EncodedWrite
    capability?: IZcap
    precondition?: WritePrecondition
  }
): Promise<HttpResponse> {
  const response = await send(context, {
    path,
    method,
    capability,
    json: encoded.json,
    body: encoded.body,
    headers: writeHeaders({
      contentType: encoded.contentType,
      precondition,
      epoch: encoded.epoch
    })
  })
  return response as HttpResponse
}

/**
 * Creates or replaces a resource by id (upsert) through its codec, owning the
 * conditional-write orchestration in one place:
 *
 * - A conditional codec (e.g. the EDV codec) needs the current stored document
 *   to advance its sequence and pin the write to the current ETag, so the
 *   current document is pre-read; the codec then computes the precondition
 *   itself. A plaintext codec needs no pre-read and defers to the caller's
 *   explicit precondition.
 * - The pre-read cannot distinguish "absent" from "unreadable with this
 *   capability" (WAS masks unauthorized reads as 404), so a conditional codec
 *   encodes a fresh insert (`If-None-Match: *`) in both cases. When the target
 *   in fact exists, a conditional-writes backend rejects that insert with 412;
 *   that 412 is re-thrown here with a message naming the real cause, instead
 *   of surfacing as an inexplicable failed create. Conditional codecs
 *   therefore need read access to update an existing document.
 * - A backend that does NOT advertise `conditional-writes` ignores the
 *   `If-None-Match: *` guard, so the 412 safety net above never fires there: a
 *   masked-404 insert would silently overwrite the existing document and reset
 *   its sequence. The insert-after-null-pre-read is therefore refused (fail
 *   closed) unless the backend advertises the feature.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.path {string}                  the resource path to write
 * @param options.codec {ResourceCodec}          the collection's resolved codec
 * @param options.id {string}                    the resource id
 * @param options.data {ResourceData}            the plaintext value
 * @param options.features {function}            resolves the backend's
 *   advertised feature tokens (the handle's shared `BackendFeatures` probe);
 *   consulted only for a conditional codec's insert-after-null-pre-read
 * @param [options.contentType] {string}         caller-supplied content type
 * @param [options.capability] {IZcap}
 * @param [options.precondition] {WritePrecondition}   the caller's explicit
 *   precondition (used only for a non-conditional codec)
 * @returns {Promise<HttpResponse>}
 */
export async function upsertResource(
  context: ClientContext,
  {
    path,
    codec,
    id,
    data,
    features,
    contentType,
    capability,
    precondition
  }: {
    path: string
    codec: ResourceCodec
    id: string
    data: ResourceData
    features: () => Promise<string[]>
    contentType?: string
    capability?: IZcap
    precondition?: WritePrecondition
  }
): Promise<HttpResponse> {
  let current: HttpResponse | null | undefined
  if (codec.conditionalWrites) {
    current = await send(context, {
      path,
      method: 'GET',
      capability,
      read: true
    })
    if (
      current === null &&
      !(await features()).includes('conditional-writes')
    ) {
      // The write would be encoded as a fresh insert guarded only by
      // `If-None-Match: *`, which this backend ignores -- so if the document in
      // fact exists but is unreadable with this capability (the masked-404
      // ambiguity), the PUT would silently destroy it. Refuse rather than risk
      // the clobber.
      throw new ValidationError(
        `Cannot create the document at "${path}": no current document is ` +
          'readable there, which cannot distinguish "absent" from "exists ' +
          'but unreadable with this capability" (WAS masks unauthorized ' +
          "reads as 404), and the collection's backend does not advertise " +
          "the 'conditional-writes' feature -- so the server could not " +
          'reject the write either, and an existing document would be ' +
          'silently overwritten. Use a backend with conditional writes, a ' +
          'capability that can read the current document and the backend ' +
          'descriptor, or add() to mint a fresh document id.'
      )
    }
  }
  const encoded = await codec.encode({ id, data, contentType, current })
  // A conditional codec computes the precondition itself (from the sequence /
  // ETag); a plaintext codec defers to the caller's explicit options.
  const chosen = codec.conditionalWrites
    ? encodedPrecondition(encoded)
    : precondition
  try {
    return await sendEncodedWrite(context, {
      path,
      method: 'PUT',
      capability,
      encoded,
      precondition: chosen
    })
  } catch (err) {
    if (
      err instanceof PreconditionFailedError &&
      codec.conditionalWrites &&
      current === null
    ) {
      const { status, type, title, details, requestUrl } = err
      throw new PreconditionFailedError(
        `Cannot update the document at "${path}": it exists, but its current ` +
          'version is not readable with this capability (WAS masks ' +
          'unauthorized reads as 404), so the write was encoded as a fresh ' +
          'insert and the server rejected it. A conditional-writes codec ' +
          '(e.g. the EDV codec) needs read access to update an existing ' +
          'document.',
        { status, type, title, details, requestUrl, cause: err }
      )
    }
    throw err
  }
}
