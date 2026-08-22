/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Overlaps codec resolution with the signed request it decodes, which every
 * read on a handle needs: the request is the same whatever the codec turns out
 * to be, so the two round trips are independent and there is no reason to pay
 * for them in series.
 *
 * The await order is the load-bearing part. The codec is awaited first so a
 * codec failure takes precedence over a read failure, and the no-op handler
 * attached to the request keeps an abandoned read from surfacing as an
 * unhandled rejection when the codec throws. The request is still awaited
 * afterwards, so its own error is never swallowed.
 */
import type { ResourceCodec } from '../codec.js'

/**
 * Runs a codec resolution and an independent request concurrently, returning
 * both once they settle.
 *
 * @param codecPromise {Promise<ResourceCodec>}   the codec being resolved
 * @param responsePromise {Promise<Response>}   the request to overlap with it
 * @returns {Promise<[ResourceCodec, Response]>}
 */
export async function withCodec<Response>(
  codecPromise: Promise<ResourceCodec>,
  responsePromise: Promise<Response>
): Promise<[ResourceCodec, Response]> {
  responsePromise.catch(() => {})
  const codec = await codecPromise
  const response = await responsePromise
  return [codec, response]
}
