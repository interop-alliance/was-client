/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/edv/cipher` subpath entry: the log-free part of the
 * offline half of encrypted (EDV-over-WAS) storage support. Everything here
 * works on bytes and keys a caller already holds -- the codec, the doc
 * ciphers, the key epochs, the recipient operations, `resourceDescriptorStore`
 * and the blinding keys -- with no server and no resource log in the graph. A
 * consumer that opens archived bytes, derives keys, or decrypts rows it
 * already has imports this entry and evaluates no transport module and no
 * `@interop/vh-resource-log` / `@interop/did-method-webvh` module. The one
 * gated exception is `createEdvDocCipher({ spaceId })`, which loads the
 * transport factory through `import()` for the chunked paths. A call that
 * names no Space loads nothing.
 *
 * `@interop/was-client/edv/core` re-exports all of it and adds the
 * log-governed descriptor stores, which read through a resource log verified
 * by `@interop/vh-resource-log`. `@interop/was-client/edv` re-exports core in
 * turn and adds the online set on top.
 *
 * Every encrypted collection carries a key-epoch roster from birth:
 * `ensureFirstEpoch` installs epoch[0] at provision time (create-if-absent;
 * the crypto-free `ensureSpaceAndCollection` only ensures the container), and
 * `initRecipients` / `addRecipient` / `removeRecipient` manage the readers and
 * rotate the epoch key, so the same key material transparently encrypts each
 * write under the current epoch and decrypts any epoch a reader still holds.
 * They mutate the descriptor through the descriptor-store seam: any
 * `EncryptionDescriptorStore` -- e.g. `resourceDescriptorStore` for a
 * descriptor hosted as a plain JSON Resource, or `./edv/core`'s
 * `logGovernedDescriptorStore` for one governed by a resource log.
 *
 * A collection provisioned with `ensureFirstEpoch({ blindedIndex: true })` also
 * carries a blinded-index HMAC key, distributed to recipients exactly like an
 * epoch key (see `hmacKey.ts`). It is installed at provisioning or never, and
 * never rotates.
 *
 * `hasKeyEpochs` and `epochRostersEqual` are the crypto-free predicates over a
 * descriptor: whether it carries a usable roster, and whether two descriptors
 * carry the same epoch configuration (`scheme`, `version`, `currentEpoch`, and
 * the ordered epoch ids; recipients and the `hmac` member deliberately
 * excluded).
 *
 * `x25519RecipientFromDidKey` is the one rule for turning a grantee named only
 * by its Ed25519 `did:key` controller into a `RecipientPublicKey`, so a
 * recipient key is always derived from an identifier both sides already hold
 * rather than transmitted. `didKeyResolver` is the reverse direction, the
 * resolver the codec hands the cipher.
 *
 * A decrypt that finds no key raises one of two classes, and a caller scanning
 * rows must tell them apart: `UnknownEpochError` when the envelope's epoch is
 * not on the descriptor the reader holds (a re-read may fix it) and
 * `KeyUnwrapError` when the epoch IS listed but this reader has no key for it
 * (never a recipient, or removed and the epoch rotated since -- re-reading
 * cannot help). Both ship from this entry beside the cipher that raises them,
 * so a consumer classifying what a cipher threw need not reach for the package
 * root. Both assign their `name` explicitly, and a consumer whose cipher
 * arrives through an injected seam matches on that name rather than
 * `instanceof`, since the seam may resolve to a second copy of this package:
 * `isKeyUnwrapError` here, and `isUnknownEpochError` on `./sync`, are those
 * matchers.
 */
export { EdvCodec } from './EdvCodec.js'
export type { CodecTransportFactory, EdvKeys } from './EdvCodec.js'
export { EDV_SCHEME_VERSION, JOSE_CONTENT_TYPE } from './constants.js'
export {
  ensureFirstEpoch,
  initRecipients,
  addRecipient,
  removeRecipient,
  replaceRecipient
} from './recipients.js'
export type { RecipientPublicKey } from './recipients.js'
export {
  isEd25519DidKey,
  x25519RecipientFromDidKey
} from './didKeyRecipient.js'
export { resourceDescriptorStore } from './descriptorStore.js'
export type { EncryptionDescriptorStore } from './descriptorStore.js'
export {
  didKeyResolver,
  mintEpoch,
  epochKeyIdFor,
  unwrapEpochSecret,
  wrapEpochSecret
} from './epochCrypto.js'
export { hasKeyEpochs, epochRostersEqual } from './epochRoster.js'
export { resolveEpochKeys } from './epochKeys.js'
export type { ResolvedEpochKeys } from './epochKeys.js'
export {
  HMAC_KEY_TYPE,
  mintHmacKey,
  hmacKeyFromSecret,
  resolveHmacKey
} from './hmacKey.js'
export type { BlindingKey } from './hmacKey.js'
export {
  createEdvDocCipher,
  createEdvEncryptOnlyDocCipher,
  ownerRecipient,
  EncryptOnlyCipherError,
  KeyUnwrapError,
  UnknownEpochError,
  isEncryptedEnvelope
} from './docCipher.js'
export type { DocCipher, EdvDocCipher } from './docCipher.js'
export { isKeyUnwrapError } from '../sync/predicates.js'
