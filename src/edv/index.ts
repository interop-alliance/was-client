/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/edv` subpath entry: encrypted (EDV-over-WAS) storage
 * support. Kept off the core `@interop/was-client` entry so plaintext consumers
 * do not pull the `@interop/edv-client` / `@interop/minimal-cipher` crypto graph
 * unless they opt in by importing this subpath.
 *
 * Two integration levels:
 *
 * - `createEdvEncryption` -- the encrypting codec for the handle
 *   seam. Pass its result as `WasClient`'s `encryption` option to make
 *   `collection.put`/`get` transparently encrypt the collections the client
 *   holds keys for.
 * - `WasTransport` -- the standalone `@interop/edv-client`
 *   transport, for driving an `EdvClient` directly against WAS.
 */
export { createEdvEncryption, EdvCodec } from './EdvCodec.js'
export { WasTransport, EDV_CONTENT_TYPE } from './WasTransport.js'
