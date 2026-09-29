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
 * signed-request context built here (`codecRequestContext`). `upsertResource`
 * runs one only to create a resource at an id that holds none, and refuses it
 * over an existing document, since a plan cannot replace one.
 */
import type { HttpResponse } from '@interop/http-client'
import type {
  ChunkedWrite,
  CodecRequestContext,
  EncodedWrite,
  ResourceCodec
} from '../codec.js'
import { isChunkedWrite } from '../codec.js'
import { PreconditionFailedError, ValidationError } from '../errors.js'
import type { IZcap, ResourceData } from '../types.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import {
  assertPreconditionAgainstPreRead,
  assertSinglePrecondition,
  encodedPrecondition,
  readEtag,
  writeHeaders,
  namedPrecondition
} from './conditional.js'
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
 * I/O: the signed-request primitive bound to this handle's capability. The
 * codec never sees the zcap machinery, and the raw `HttpResponse` it gets back
 * matches the `was.request()` escape hatch, which is what `WasTransport`
 * consumes.
 *
 * Requests go through the same mapped `send` path the core write paths use, so
 * a codec-driven write fails with the typed `WasError` subclasses the calling
 * method documents (a document `PUT` that 404s is a `NotFoundError`, not a raw
 * ky/ezcap error). The typed errors carry the HTTP `status`, so a consumer that
 * dispatches on status keeps working.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param [options.capability] {IZcap}     capability attached to each request
 * @returns {CodecRequestContext}
 */
export function codecRequestContext(
  context: ClientContext,
  { capability }: { capability?: IZcap } = {}
): CodecRequestContext {
  return {
    async request(input) {
      // `send` only resolves `null` for the `read`/`idempotent` flags, which
      // this surface never sets, so the response is always present.
      const response = await send(context, { capability, ...input })
      return response as HttpResponse
    }
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
 * preconditions.
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
    contentType,
    capability
  }: {
    itemsPath: string
    pathForId: (id: string) => string
    codec: ResourceCodec
    data: ResourceData
    contentType?: string
    capability?: IZcap
  }
): Promise<InsertOutcome> {
  const write = await codec.encode({ data, contentType })
  if (isChunkedWrite(write)) {
    const { id, etag } = await write.execute(
      codecRequestContext(context, { capability })
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
 *   in fact exists, the server rejects that insert with 412; that 412 is
 *   re-thrown here with a message naming the real cause, instead of surfacing
 *   as an inexplicable failed create. Conditional codecs therefore need read
 *   access to update an existing document.
 * - A codec may answer with a multi-request `ChunkedWrite` plan (the EDV
 *   codec's large binary write). When the pre-read found no document, the
 *   plan runs over the handle's signed-request context and creates the
 *   resource at this id, guarded like any fresh insert: a 412 surfaces as
 *   `PreconditionFailedError`, under the same masked-404 message. Over an
 *   existing document the plan is refused with `ValidationError`, since a
 *   plan cannot replace a document.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.path {string}                  the resource path to write
 * @param options.codec {ResourceCodec}          the collection's resolved codec
 * @param options.id {string}                    the resource id
 * @param options.data {ResourceData}            the plaintext value
 * @param [options.contentType] {string}         caller-supplied content type
 * @param [options.capability] {IZcap}
 * @param [options.precondition] {WritePrecondition}   the caller's explicit
 *   precondition (used only for a non-conditional codec)
 * @returns {Promise<{ etag?: string }>}   the stored resource's new ETag
 */
export async function upsertResource(
  context: ClientContext,
  {
    path,
    codec,
    id,
    data,
    contentType,
    capability,
    precondition: callerPrecondition
  }: {
    path: string
    codec: ResourceCodec
    id: string
    data: ResourceData
    contentType?: string
    capability?: IZcap
    precondition?: WritePrecondition
  }
): Promise<{ etag?: string }> {
  // An empty precondition object (the handle's default) names no baseline.
  const precondition = namedPrecondition(callerPrecondition)
  // Checked before the pre-read, whose comparison would otherwise answer the
  // pair with a 412 either way.
  assertSinglePrecondition(precondition)
  let current: HttpResponse | null | undefined
  if (codec.conditionalWrites) {
    current = await send(context, {
      path,
      method: 'GET',
      capability,
      read: true
    })
    // The caller's own compare-and-swap baseline is checked against what the
    // pre-read just observed, so a lost race fails here rather than being
    // encoded into a sequence advance the server would then reject.
    assertPreconditionAgainstPreRead({ path, current, precondition })
  }
  const write = await codec.encode({
    id,
    data,
    contentType,
    current,
    // Hand a conditional codec the caller's baseline so it pins the write to
    // that revision instead of to the one its own pre-read observed.
    ...(codec.conditionalWrites &&
      precondition !== undefined && {
        precondition
      })
  })
  if (isChunkedWrite(write)) {
    return await runChunkedCreate(context, {
      path,
      write,
      capability,
      current
    })
  }
  const encoded = write
  // A conditional codec computes the precondition itself (from the sequence /
  // ETag, or from the caller's baseline handed to `encode` above); a plaintext
  // codec defers to the caller's explicit options.
  const chosen = codec.conditionalWrites
    ? encodedPrecondition(encoded)
    : precondition
  try {
    const response = await sendEncodedWrite(context, {
      path,
      method: 'PUT',
      capability,
      encoded,
      precondition: chosen
    })
    return { etag: readEtag(response) }
  } catch (err) {
    if (
      err instanceof PreconditionFailedError &&
      codec.conditionalWrites &&
      current === null
    ) {
      throw maskedInsertRejected({ err, path })
    }
    throw err
  }
}

/**
 * Runs a codec's multi-request plan for a write by id, which creates the
 * resource at that id. Only a pre-read that found no document (`current`
 * is `null`) lets it run: over an existing document, and after no pre-read at
 * all, the plan is refused, since a plan writes a fresh document and cannot
 * reconcile an existing one's stored parts with the new payload. The codec
 * supplies the scheme-specific recovery advice; this layer knows nothing
 * about how it stores things.
 *
 * The plan guards its own first write as create-if-absent, so a 412 means
 * the id was taken after the pre-read, or is held by a document the
 * capability cannot read. It surfaces as `PreconditionFailedError` with the
 * masked-404 message of any other fresh insert by id.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.path {string}   the resource path the plan writes
 * @param options.write {ChunkedWrite}   the codec's plan
 * @param [options.capability] {IZcap}
 * @param options.current {HttpResponse | null | undefined}   the pre-read's
 *   result, `undefined` when the codec asked for none
 * @returns {Promise<{ etag?: string }>}   the stored resource's new ETag
 */
async function runChunkedCreate(
  context: ClientContext,
  {
    path,
    write,
    capability,
    current
  }: {
    path: string
    write: ChunkedWrite
    capability?: IZcap
    current: HttpResponse | null | undefined
  }
): Promise<{ etag?: string }> {
  if (current !== null) {
    throw new ValidationError(
      `Cannot write this payload to "${path}": the collection's codec ` +
        'answered with a multi-request write plan, which can only create a ' +
        'resource at an id that holds none, and a document is stored here. ' +
        'Delete the resource first, or add the payload as a new resource ' +
        '(add())' +
        (write.guidance === undefined ? '.' : `. ${write.guidance}`)
    )
  }
  try {
    const { etag } = await write.execute(
      codecRequestContext(context, { capability })
    )
    return { etag }
  } catch (err) {
    // `current` is `null`, so a conditional codec pre-read and found nothing.
    if (err instanceof PreconditionFailedError) {
      throw maskedInsertRejected({ err, path })
    }
    throw err
  }
}

/**
 * The error for a fresh insert by id the server rejected with 412 after the
 * pre-read found nothing: the document exists, but its current version is not
 * readable with this capability (a masked 404), or it appeared since the
 * pre-read. The server's error is kept as the cause.
 *
 * @param options {object}
 * @param options.err {PreconditionFailedError}   the server's 412
 * @param options.path {string}   the resource path written
 * @returns {PreconditionFailedError}
 */
function maskedInsertRejected({
  err,
  path
}: {
  err: PreconditionFailedError
  path: string
}): PreconditionFailedError {
  const { status, type, title, details, requestUrl } = err
  return new PreconditionFailedError(
    `Cannot update the document at "${path}": it exists, but its current ` +
      'version is not readable with this capability (WAS masks ' +
      'unauthorized reads as 404), so the write was encoded as a fresh ' +
      'insert and the server rejected it. A conditional codec ' +
      '(e.g. the EDV codec) needs read access to update an existing ' +
      'document.',
    { status, type, title, details, requestUrl, cause: err }
  )
}
