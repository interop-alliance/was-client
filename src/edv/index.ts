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
 * - `createEdvEncryption` -- the EDV keystore for the handle seam. Pass its
 *   result as `WasClient`'s `encryption` option; it supplies keys for the
 *   collections declared encrypted (by their `encryption` marker or a per-handle
 *   override), so `collection.put`/`get` transparently encrypt/decrypt.
 * - `WasTransport` -- the standalone `@interop/edv-client`
 *   transport, for driving an `EdvClient` directly against WAS.
 *
 * Multi-recipient (key-epoch) collections layer on top: `initRecipients` /
 * `addRecipient` / `removeRecipient` manage the readers and rotate the epoch
 * key, so the same `createEdvEncryption` provider transparently encrypts each
 * write under the current epoch and decrypts any epoch a reader still holds.
 */
export { createEdvEncryption, EdvCodec } from './EdvCodec.js'
export type { EdvKeys } from './EdvCodec.js'
export { WasTransport, JOSE_CONTENT_TYPE } from './WasTransport.js'
export { initRecipients, addRecipient, removeRecipient } from './recipients.js'
export type { OwnerKey, RecipientPublicKey } from './recipients.js'
export { mintEpoch, epochKeyIdFor, epochIdFromKid } from './epochCrypto.js'
