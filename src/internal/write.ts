/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared write orchestration: turn a codec's {@link EncodedWrite} plus a
 * conditional-write precondition into request headers and send it. Captures the
 * `writeHeaders(...) + send(...)` shape that `Collection.add` and `Resource.put`
 * would otherwise each re-implement.
 */
import type { HttpResponse } from '@interop/http-client'
import type { EncodedWrite } from '../codec.js'
import type { IZcap } from '../types.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { writeHeaders } from './conditional.js'
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
    headers: writeHeaders(encoded.contentType, precondition)
  })
  return response as HttpResponse
}
