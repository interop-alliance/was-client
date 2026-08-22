/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared write orchestration. `sendEncodedWrite` turns a codec's
 * {@link EncodedWrite} plus a conditional-write precondition into request
 * headers and sends it (the shape `Collection.add` and `Resource.put` would
 * otherwise each re-implement). Two flows layer on top: `insertResource` (the
 * create path behind `Collection.add` -- encode, the minted-id `PUT` vs
 * server-minting `POST` branch, and the precondition selection) and
 * `upsertResource` (the write-by-id path behind `Resource.put` -- the
 * conditional-codec pre-read of the current document, the codec-vs-caller
 * precondition selection, and the masked-404 policy for a document that exists
 * but is not readable with the bound capability).
 *
 * A codec may also answer `encode` with a multi-request `ChunkedWrite` plan
 * rather than an `EncodedWrite`. `insertResource` runs the plan over the
 * signed-request context built here (`codecRequestContext`); `upsertResource`
 * refuses one, since auto-routing is an insert-path affordance.
 */
import type { HttpResponse } from '@interop/http-client'
import type {
  CodecRequestContext,
  EncodedWrite,
  ResourceCodec
} from '../codec.js'
import { isChunkedWrite } from '../codec.js'
import { PreconditionFailedError, ValidationError } from '../errors.js'
import type { IZcap, ResourceData } from '../types.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import type { FeatureProbe } from './features.js'
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
 * Builds the {@link CodecRequestContext} core hands a codec that drives its own
 * I/O: the signed-request primitive bound to this handle's capability, plus the
 * handle's memoized backend-feature probe. The codec never sees the zcap
 * machinery, and the raw `HttpResponse` it gets back matches the
 * `was.request()` escape hatch, which is what `WasTransport` consumes.
 *
 * Requests go through the same mapped `send` path the core write paths use, so
 * a codec-driven write fails with the typed `WasError` subclasses the calling
 * method documents (a document `PUT` that 404s is a `NotFoundError`, not a raw
 * ky/ezcap error). The typed errors carry the HTTP `status`, so a consumer that
 * dispatches on status keeps working.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.features {FeatureProbe}   the handle's memoized backend-feature
 *   probe
 * @param [options.capability] {IZcap}     capability attached to each request
 * @returns {CodecRequestContext}
 */
export function codecRequestContext(
  context: ClientContext,
  { features, capability }: { features: FeatureProbe; capability?: IZcap }
): CodecRequestContext {
  return {
    async request(input) {
      // `send` only resolves `null` for the `read`/`idempotent` flags, which
      // this surface never sets, so the response is always present.
      const response = await send(context, { capability, ...input })
      return response as HttpResponse
    },
    features
  }
}

/**
 * The outcome of {@link insertResource}: either the ordinary single-request
 * write (the codec's encoding, the path written, and the response) or the
 * result of a codec's multi-request {@link ChunkedWrite} plan, which has no one
 * canonical response.
 */
export type InsertOutcome =
  | {
      chunked?: false
      encoded: EncodedWrite
      path: string
      response: HttpResponse
    }
  | {
      chunked: true
      id: string
      path: string
      contentType?: string
      etag?: string
    }

/**
 * Creates a resource with a codec-minted or server-minted id (insert) through
 * its codec, owning the create orchestration in one place: the encode, the
 * `PUT`-vs-`POST` branch, and the precondition selection.
 *
 * A codec may also answer the encode with a multi-request plan (the EDV codec's
 * chunked blob write). The plan is then executed over the handle's signed
 * request context instead of being sent as one request; it owns its own
 * preconditions and feature gating.
 *
 * A codec that mints its own id (e.g. the encrypting codec's EDV id) writes it
 * by `PUT` to that id's path; a codec that mints none (the identity codec)
 * `POST`s to the items path and lets the server mint one. A conditional codec
 * computes the precondition itself (the EDV codec guards its fresh insert with
 * `If-None-Match: *`); an insert through a non-conditional codec is
 * unconditional, since `add()` names no target revision to pin against.
 *
 * Returns the codec's encoded write and the path actually written alongside the
 * response, so the caller can shape its result (the created id and URL) without
 * re-deriving either.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.itemsPath {string}       the collection's items path, the
 *   `POST` target when the codec mints no id
 * @param options.pathForId {function}     builds the resource path for a
 *   codec-minted id
 * @param options.codec {ResourceCodec}    the collection's resolved codec
 * @param options.data {ResourceData}      the plaintext value
 * @param options.features {FeatureProbe}   the handle's shared backend-feature
 *   probe, handed to a codec's multi-request plan so its affordance gate costs
 *   no extra round trip
 * @param [options.contentType] {string}   caller-supplied content type
 * @param [options.capability] {IZcap}
 * @returns {Promise<InsertOutcome>}
 */
export async function insertResource(
  context: ClientContext,
  {
    itemsPath,
    pathForId,
    codec,
    data,
    features,
    contentType,
    capability
  }: {
    itemsPath: string
    pathForId: (id: string) => string
    codec: ResourceCodec
    data: ResourceData
    features: FeatureProbe
    contentType?: string
    capability?: IZcap
  }
): Promise<InsertOutcome> {
  const write = await codec.encode({ data, contentType })
  if (isChunkedWrite(write)) {
    const { id, etag } = await write.execute(
      codecRequestContext(context, { features, capability })
    )
    return {
      chunked: true,
      id,
      path: pathForId(id),
      contentType: write.resourceContentType,
      ...(etag !== undefined && { etag })
    }
  }
  const encoded = write
  const chosen = codec.conditionalWrites
    ? encodedPrecondition(encoded)
    : undefined
  const path = encoded.id !== undefined ? pathForId(encoded.id) : itemsPath
  const response = await sendEncodedWrite(context, {
    path,
    method: encoded.id !== undefined ? 'PUT' : 'POST',
    capability,
    encoded,
    precondition: chosen
  })
  return { encoded, path, response }
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
 * @param options.features {FeatureProbe}         the handle's shared
 *   `BackendFeatures` probe; consulted only for a conditional codec's
 *   insert-after-null-pre-read
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
    features: FeatureProbe
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
    if (current === null && !(await features.has('conditional-writes'))) {
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
  const write = await codec.encode({ id, data, contentType, current })
  if (isChunkedWrite(write)) {
    // Auto-routing is an insert-path affordance: a write by id would have to
    // reconcile the existing stored parts (and the codec's sequence) with the
    // new payload, which this path does not do. Refuse instead of
    // half-performing the update. The codec supplies the scheme-specific
    // recovery advice; this layer knows nothing about how it stores things.
    throw new ValidationError(
      `Cannot write this payload to "${path}": the collection's codec ` +
        'answered with a multi-request write plan, which is only auto-routed ' +
        'on the insert path (add()). Add it as a new resource' +
        (write.guidance === undefined ? '.' : `. ${write.guidance}`)
    )
  }
  const encoded = write
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
