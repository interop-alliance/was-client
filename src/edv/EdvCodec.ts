/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The EDV (Encrypted Data Vault) resource codec and its `EncryptionProvider`
 * factory -- the encrypting half of the codec seam. Bound to an
 * encrypted collection, it encrypts a caller's value into an EDV envelope
 * (`{ id, sequence, indexed, jwe }`) on write and decrypts it on read, so
 * `collection.put(id, obj)` / `collection.get(id)` transparently round-trip
 * ciphertext. Keys live in the wallet and are supplied per-collection by the
 * app's `resolveKeys`; they never reach the server, which stores only opaque
 * JWE envelopes.
 *
 * This reuses `EdvClientCore`'s transport-free `documentCipher` (its public
 * `EdvDocumentCipher` -- the same JWE machinery as the standalone
 * `WasTransport`), but here the WAS Resource CRUD -- the transport role -- is
 * played by core was-client's `Collection`/`Resource` I/O, so the codec is a
 * pure encode/decode transform and needs no transport of its own.
 *
 * Scope (documents-only):
 *
 * - **Restrict-mode ids.** `add()` mints a 128-bit multibase EDV id; the WAS
 *   resource id IS that EDV id. `put(id, ...)` accepts only an EDV-format id --
 *   a human-readable id is rejected (it would leak onto the URL). Carry a
 *   human-readable label inside the encrypted content instead. By default the
 *   minted id is random (`generateId()`, the classic mutable-document model);
 *   with `idDerivation: 'content'` it is content-derived instead -- encrypt
 *   first, then `deriveId()` a truncated SHA-256 of the JWE ciphertext and
 *   stamp it on the envelope -- making the document content-addressed (and so
 *   immutable: an "update" is delete-old + add-new). Both formats pass the same
 *   EDV id check and are indistinguishable on the wire.
 * - **Inline non-JSON as a single JWE.** A `Blob`/`Uint8Array` under the size cap
 *   is encrypted as one document -- stored as a legible UTF-8 string for a
 *   text-family type (else base64) -- with the plaintext content type and the
 *   encoding carried in the document `meta`. An oversized one is
 *   rejected (large chunked encrypted blobs need the server's `chunked-streams`
 *   affordance).
 * - **Enforced sequence (conditional writes).** The codec sets
 *   `conditionalWrites`, so the write path pre-reads the current envelope and
 *   hands it to `encode`: an update advances `sequence` from its prior value and
 *   pins the write to the server's current ETag via `If-Match`, while a fresh
 *   insert (`sequence: 0`) is guarded by `If-None-Match: *`. A stale write
 *   surfaces as a `PreconditionFailedError` (412) -- the lost-update guard --
 *   rather than the old advisory last-writer-wins. Against a backend that does
 *   not advertise `conditional-writes` (no ETag) an update degrades to
 *   advisory, and a create-by-put is refused by the write path (the masked-404
 *   pre-read could otherwise silently clobber; see `upsertResource`).
 * - **Encrypted metadata.** A Resource's user-writable `custom`
 *   (`name`/`tags`, via `setName`/`setTags`/`setMeta`) is
 *   encrypted into an EDV Document envelope with the same `documentCipher` used
 *   for content and stored opaquely under `/meta`; the server never sees
 *   plaintext `name`/`tags`. A reader with the keys decrypts it back
 *   transparently via `meta()`.
 */
import { base64, base64urlnopad } from '@scure/base'
import { EdvClientCore, assertDocId } from '@interop/edv-client'
import type { HttpResponse } from '@interop/http-client'
import type {
  IEncryptedDocument,
  IKeyAgreementKey,
  IKeyResolver,
  IRecipientTemplate
} from '@interop/data-integrity-core'
import type {
  EncodedWrite,
  EncryptionProvider,
  ResourceCodec
} from '../codec.js'
import {
  EncryptionError,
  IntegrityError,
  KeyUnwrapError,
  ValidationError
} from '../errors.js'
import { readEtag } from '../internal/conditional.js'
import { resolveEpochKeys } from './epochKeys.js'
import { didKeyResolver } from './epochCrypto.js'
import {
  ENCODER,
  isBlob,
  isTextContentType,
  readJsonData,
  resolvePayload
} from '../internal/content.js'
import type { Json, ResourceData, ResourceMetadataCustom } from '../types.js'
import { DEFAULT_CONTENT_TYPE, envelopeBytes } from './constants.js'

/**
 * Default ceiling for a single-document (unchunked) encrypted binary or text
 * write, measured in raw (pre-base64) bytes. Past this a `Blob`/`Uint8Array`
 * is rejected with guidance toward the chunked-stream path. 512 KiB: the
 * envelope is stored as a JSON-family content type routed through the server's
 * in-memory JSON body parser (a ~1 MiB cap), and a binary payload inflates
 * ~33% inside the document (base64) and again ~33% in the JWE ciphertext
 * (base64url) -- ~1.78x total, so 512 KiB raw stays safely under the cap.
 * Raise `maxBlobBytes` against a server with a larger JSON body limit.
 */
const DEFAULT_MAX_BLOB_BYTES = 512 * 1024

/**
 * A shared strict UTF-8 decoder used to test whether a non-JSON payload is
 * valid UTF-8 (so it can be stored legibly as text rather than base64).
 * `fatal: true` makes `decode` throw on malformed input; `ignoreBOM: true`
 * keeps a leading BOM (`EF BB BF`) in the decoded string -- without it the
 * decoder silently strips those 3 bytes and the text round-trip is no longer
 * byte-exact. The decoder is stateless across non-streaming calls, so one
 * instance is reused.
 */
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

/**
 * Whether a decrypt error means "this candidate key does not open the envelope"
 * (so the loop should try the next key) rather than an integrity failure. True
 * for the upstream typed key-miss error -- `@interop/minimal-cipher` /
 * `@interop/edv-client` raise a `KeyMissError` (the null-CEK unwrap path and the
 * kid-mismatch path) when a candidate key is simply the wrong or a rotated key,
 * not a corrupted envelope. It is matched by `err.name === 'KeyMissError'`
 * rather than `instanceof`: name-dispatch survives pnpm installing two copies of
 * the cipher package (a second copy's `KeyMissError` is a distinct class but
 * carries the same `name`), so was-client need not import the class at all.
 *
 * Also true for a {@link KeyUnwrapError} raised by a candidate itself -- a lazy
 * epoch key whose recipient entry turned out corrupt when its first decrypt
 * forced the unwrap (see `lazyEpochKey`): that says nothing about the stored
 * envelope, so the loop must move on to the next candidate rather than report
 * tampering. Every other error means the key DID select a recipient and unwrap,
 * but the content's AEAD tag did not verify -- a data-integrity failure
 * (WebCrypto's `OperationError` in browsers, Node's "unable to authenticate
 * data") -- which must surface as an {@link IntegrityError}, not be masked as a
 * key miss.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isKeyMiss(err: unknown): boolean {
  return (
    err instanceof KeyUnwrapError ||
    (err instanceof Error && err.name === 'KeyMissError')
  )
}

/**
 * A {@link ResourceCodec} that encrypts on write and decrypts on read using an
 * `EdvClientCore`'s public `documentCipher`. One instance is bound per encrypted
 * collection handle.
 */
export class EdvCodec implements ResourceCodec {
  readonly conditionalWrites = true

  readonly #edv: EdvClientCore
  /**
   * The static JWE recipient descriptor every write encrypts to (the write
   * key's `{ kid, alg }` header; the ephemeral `epk` is minted later inside
   * `encrypt`). Deterministic per codec, so computed once here instead of per
   * write.
   */
  readonly #recipients: IRecipientTemplate[]
  readonly #readKeys: IKeyAgreementKey[]
  readonly #writeEpoch?: string
  readonly #contentType: string
  readonly #maxBlobBytes: number
  readonly #idDerivation: 'random' | 'content'
  /**
   * The EDV-over-WAS scheme version this codec binds into every envelope's
   * `was.v` protected-header parameter (the marker's `version`, `1` when
   * absent). Read side rejects an envelope stamped with a greater version.
   */
  readonly #version: number
  /**
   * Whether this codec's collection has key epochs. When it does, an envelope's
   * `was.epoch` binding is checked on decode against the epoch of the key that
   * actually decrypted it.
   */
  readonly #hasEpochs: boolean

  /**
   * @param options {object}
   * @param options.edv {EdvClientCore}             holds the cipher + key resolver
   * @param options.keyAgreementKey {IKeyAgreementKey}   the key writes encrypt
   *   under and the default read key. On a single-key collection this is the
   *   wallet's own key-agreement key; on a multi-recipient (key-epoch)
   *   collection it is the reconstructed `currentEpoch` key pair.
   * @param [options.readKeys] {IKeyAgreementKey[]}   the candidate keys a read
   *   may decrypt with, one per epoch this reader can unwrap (defaults to just
   *   `keyAgreementKey`). A read selects the one whose id matches the stored
   *   envelope's recipient, so a resource written under an older epoch still
   *   decrypts.
   * @param [options.writeEpoch] {string}   the key-epoch id to stamp on writes
   *   (the `currentEpoch`), surfaced as {@link EncodedWrite.epoch}; absent on a
   *   single-key collection.
   * @param options.contentType {string}            stored envelope content type
   * @param options.maxBlobBytes {number}           single-document binary cap
   * @param options.idDerivation {string}           how `add()` mints a document
   *   id: `'random'` (classic `generateId()`) or `'content'` (derived from the
   *   JWE ciphertext, content-addressed)
   * @param [options.version] {number}   the EDV-over-WAS scheme version to bind
   *   into each envelope's `was.v` (defaults to `1`)
   * @param [options.hasEpochs] {boolean}   whether the collection has key
   *   epochs, so a decoded envelope's `was.epoch` binding is checked against the
   *   decrypting key's epoch (defaults to `false`)
   */
  constructor({
    edv,
    keyAgreementKey,
    readKeys,
    writeEpoch,
    contentType,
    maxBlobBytes,
    idDerivation,
    version,
    hasEpochs
  }: {
    edv: EdvClientCore
    keyAgreementKey: IKeyAgreementKey
    readKeys?: IKeyAgreementKey[]
    writeEpoch?: string
    contentType: string
    maxBlobBytes: number
    idDerivation: 'random' | 'content'
    version?: number
    hasEpochs?: boolean
  }) {
    this.#edv = edv
    this.#recipients =
      edv.documentCipher.createDefaultRecipients(keyAgreementKey)
    this.#readKeys = readKeys ?? [keyAgreementKey]
    this.#writeEpoch = writeEpoch
    this.#contentType = contentType
    this.#maxBlobBytes = maxBlobBytes
    this.#idDerivation = idDerivation
    this.#version = version ?? 1
    this.#hasEpochs = hasEpochs ?? false
  }

  /**
   * @inheritdoc
   */
  async encode({
    id,
    data,
    contentType,
    current
  }: {
    id?: string
    data: ResourceData
    contentType?: string
    current?: HttpResponse | null
  }): Promise<EncodedWrite> {
    if (id !== undefined) {
      try {
        // A full multibase decode + multihash length check (the same assertion
        // the EDV core applies), tighter than a charset heuristic: it rejects a
        // human-readable id, which would otherwise leak onto the URL.
        assertDocId(id)
      } catch {
        throw new ValidationError(
          `Cannot write a human-readable id "${id}" to an encrypted ` +
            'collection -- it would leak onto the URL. Use add() to mint an ' +
            'EDV document id, or carry the human-readable label inside the ' +
            'encrypted content.'
        )
      }
    }
    // `add()` (no caller id): mint a random id up front, or -- in `'content'`
    // mode -- leave it unset and stamp the content-derived id after encryption
    // (the id is a function of the ciphertext, which does not exist yet).
    let docId =
      id ??
      (this.#idDerivation === 'content'
        ? undefined
        : ((await this.#edv.generateId()) as string))
    const { content, meta } = await this.#toDocument(data, contentType, docId)

    // When the write path pre-read a current envelope, advance `sequence` from
    // its prior value (`encrypt({ update: true })` increments it) and pin the
    // write to the server's current ETag with `If-Match`. With no prior envelope
    // this is a fresh insert (`sequence: 0`) guarded by `If-None-Match: *`
    // (create-if-absent), so a concurrent first writer cannot be clobbered.
    let priorDoc: IEncryptedDocument | null = null
    if (current) {
      const read = await readJsonData(
        current as Parameters<typeof readJsonData>[0]
      )
      this.#assertEnvelope(read, 'update')
      priorDoc = read
    }

    const { documentCipher } = this.#edv
    // Bind an AEAD-authenticated `was` parameter into the JWE protected header:
    // the scheme version, the resource id when known at encrypt time (omitted
    // for a content-derived id, which does not exist until after encryption),
    // and the write epoch on a multi-recipient collection. A server that swaps
    // two envelopes between ids (or replays one under a rolled-back epoch) is
    // then detected on decrypt.
    const was: { v: number; resource?: string; epoch?: string } = {
      v: this.#version
    }
    if (docId !== undefined) {
      was.resource = docId
    }
    if (this.#writeEpoch !== undefined) {
      was.epoch = this.#writeEpoch
    }
    const encrypted = await documentCipher.encrypt({
      doc: {
        ...(docId !== undefined && { id: docId }),
        content,
        // `content` and `meta` are both sealed inside the JWE; `meta` carries the
        // plaintext content type and the inline-encoding discriminator, taken
        // fresh from this write (the new type/encoding wins on update).
        meta,
        ...(priorDoc && { sequence: priorDoc.sequence })
      },
      recipients: this.#recipients,
      keyResolver: this.#edv.keyResolver,
      hmac: undefined,
      update: priorDoc !== null,
      additionalProtectedParams: { was }
    })
    if (docId === undefined) {
      // Encrypt-then-stamp: the id lives in the cleartext envelope, outside the
      // JWE, so deriving it from the ciphertext and setting it afterwards does
      // not invalidate the envelope.
      docId = await documentCipher.deriveId({ jwe: encrypted.jwe })
      encrypted.id = docId
    }
    return {
      id: docId,
      body: envelopeBytes(encrypted),
      contentType: this.#contentType,
      // Surface the plaintext content type (the server-opaque envelope type stays
      // `contentType`) so `add()` reports the real resource type.
      resourceContentType: meta.contentType as string,
      // Pin an update to the server's current ETag; guard a fresh insert with
      // create-if-absent. An update's `If-Match` carries a server-provided ETag,
      // so it degrades to an advisory write against a backend without the
      // conditional-writes feature (the ETag is absent). A fresh insert's
      // `If-None-Match: *` needs no server-provided validator and so is emitted
      // unconditionally by design -- it expresses the insert's intent
      // (create-only-if-absent). A backend that does not honor it would ignore
      // it, so the write path refuses the insert-after-null-pre-read up front
      // on such a backend (see `upsertResource`) -- a masked-404 pre-read must
      // not silently overwrite an existing document there.
      ...(priorDoc
        ? { ifMatch: readEtag(current ?? null) }
        : { ifNoneMatch: true }),
      // Stamp the key epoch this write encrypted under (the `currentEpoch`), so
      // the server records it and a reader can pick the epoch key. Absent on a
      // single-key collection.
      ...(this.#writeEpoch !== undefined && { epoch: this.#writeEpoch })
    }
  }

  /**
   * @inheritdoc
   */
  async decode(
    response: {
      data?: unknown
      json(): Promise<unknown>
    },
    expectedId?: string
  ): Promise<Json | Blob> {
    const encryptedDoc = await readJsonData(
      response as Parameters<typeof readJsonData>[0]
    )
    this.#assertEnvelope(encryptedDoc, 'read')
    const decrypted = await this.#decrypt(encryptedDoc)
    await this.#verifyBinding({
      jwe: encryptedDoc.jwe,
      expectedId,
      keyId: decrypted.keyId
    })
    return this.#fromDocument(decrypted.content, decrypted.meta)
  }

  /**
   * Decrypts a stored EDV envelope, selecting which read key to use by matching
   * the envelope's JWE recipient `kid` against this reader's candidate keys
   * (one per epoch it can unwrap). On a single-key collection there is exactly
   * one candidate; on a multi-recipient collection a resource written under an
   * older epoch selects that epoch's key, so history stays readable.
   *
   * A stored envelope naming an epoch this reader holds no key for (it was never
   * a recipient of that epoch, or was removed and the epoch rotated) fails with
   * {@link KeyUnwrapError} -- the **read** axis only; it says nothing about
   * whether the server will still serve (pull) the ciphertext.
   *
   * Also returns the `id` of the key that actually decrypted the envelope (its
   * JWE recipient `kid`), so {@link _verifyBinding} can check a `was.epoch`
   * binding against the epoch of the decrypting key.
   *
   * @param encryptedDoc {IEncryptedDocument}
   * @returns {Promise<{ content?: unknown; meta?: Record<string, unknown>;
   *   keyId?: string }>}
   */
  async #decrypt(encryptedDoc: IEncryptedDocument): Promise<{
    content?: unknown
    meta?: Record<string, unknown>
    keyId?: string
  }> {
    const recipients =
      (
        encryptedDoc.jwe as {
          recipients?: Array<{ header?: { kid?: string } }>
        }
      ).recipients ?? []
    const kids = new Set(
      recipients
        .map(recipient => recipient.header?.kid)
        .filter((kid): kid is string => typeof kid === 'string')
    )
    // Prefer the read key whose id names a recipient of this envelope. The
    // `rest` fallback then tries the remaining candidates: it serves an envelope
    // whose recipient `kid` matches no local key id -- format drift, or a
    // single-key envelope read with a differently-labeled key -- where the
    // exact-match partition is empty even though a candidate can still unwrap it.
    // For a well-formed epoch envelope the exact match always hits, so `rest` is
    // normally unreached.
    const preferred = this.#readKeys.filter(key => kids.has(key.id))
    const rest = this.#readKeys.filter(key => !kids.has(key.id))
    for (const keyAgreementKey of [...preferred, ...rest]) {
      try {
        const decrypted = await this.#edv.documentCipher.decrypt({
          encryptedDoc,
          keyAgreementKey
        })
        return { ...decrypted, keyId: keyAgreementKey.id }
      } catch (err) {
        if (isKeyMiss(err)) {
          // This candidate is not a recipient of this envelope, or could not
          // unwrap its content-encryption key; try the next candidate.
          continue
        }
        // The candidate DID select a recipient and unwrap the CEK, but the
        // content's AEAD tag failed to authenticate: the stored ciphertext is
        // corrupt or has been tampered with. Surface this immediately as an
        // integrity failure rather than masking it as a membership/key miss by
        // continuing into `rest` (a real key miss never reaches AEAD, so this
        // can only be a genuine integrity failure on a key that matched).
        throw new IntegrityError(
          'Cannot decrypt this resource: its ciphertext failed to authenticate ' +
            '(the AEAD integrity tag did not verify). This reader holds a key ' +
            'that unwrapped the envelope, so this is not a key-epoch/membership ' +
            'problem -- the stored envelope is corrupt or has been tampered ' +
            'with.',
          { cause: err }
        )
      }
    }
    throw new KeyUnwrapError(
      "Cannot decrypt this resource: none of this reader's epoch keys unwrap " +
        'it. It was encrypted under a key epoch this reader holds no key for ' +
        '(it was never a recipient of that epoch, or it was removed from the ' +
        'collection and the epoch was rotated). This is the read axis only -- ' +
        'the server may still serve the ciphertext (a separate zcap decision).'
    )
  }

  /**
   * Verifies the AEAD-authenticated `was` binding on a successfully-decrypted
   * envelope (spec "Request Body Integrity"'s envelope half). Decrypt success
   * proves the protected header authentic, so this runs only after a decrypt
   * succeeds. Enforces, in order:
   *
   * - No `was` parameter at all: a legacy envelope, accepted unchanged (this
   *   client wrote it before the binding existed, or a foreign EDV writer did).
   * - `was.v` greater than this codec's scheme version: a future-scheme envelope
   *   this client does not implement -- {@link EncryptionError}.
   * - `was.resource` present and the expected id known: a mismatch is a server-side
   *   swap of two resources' envelopes -- {@link IntegrityError}.
   * - `was` present but `resource` absent (a content-derived write) and the expected
   *   id known: the envelope's ciphertext must re-derive to the expected id
   *   ({@link EdvDocumentCipher.deriveId}); a mismatch means the envelope was
   *   copied under a different id -- {@link IntegrityError}. This check is NEVER
   *   applied to an envelope with no `was` at all (a legacy random-id envelope
   *   would fail it wrongly).
   * - On a collection with epochs, `was.epoch` present: it must equal the epoch
   *   (the `did:key` before the `#`) of the key that actually decrypted -- a
   *   mismatch is a replay under a different epoch's key -- {@link IntegrityError}.
   *
   * @param options {object}
   * @param options.jwe {unknown}   the envelope's JWE (its `protected` header is
   *   parsed for `was`)
   * @param [options.expectedId] {string}   the resource id the read targeted
   * @param [options.keyId] {string}   the id of the key that decrypted, for the
   *   epoch check
   * @returns {Promise<void>}
   */
  async #verifyBinding({
    jwe,
    expectedId,
    keyId
  }: {
    jwe: unknown
    expectedId?: string
    keyId?: string
  }): Promise<void> {
    const was = parseWasHeader(jwe)
    if (was === undefined) {
      // Legacy envelope (no `was`): accept unchanged for back-compat.
      return
    }
    if (typeof was.v === 'number' && was.v > this.#version) {
      throw new EncryptionError(
        `Cannot decrypt this resource: its envelope is stamped with ` +
          `EDV-over-WAS scheme version ${was.v}, which this client (version ` +
          `${this.#version}) does not implement. Upgrade the client.`
      )
    }
    if (typeof was.resource === 'string') {
      if (expectedId !== undefined && was.resource !== expectedId) {
        throw new IntegrityError(
          `Cannot decrypt this resource: the stored envelope is bound to a ` +
            `different resource id ("${was.resource}") than the one requested ` +
            `("${expectedId}"). The server swapped two resources' envelopes.`
        )
      }
    } else if (expectedId !== undefined) {
      // Content-derived write (no `resource`): the id is a function of the
      // ciphertext, so re-derive and compare.
      const { documentCipher } = this.#edv
      const derived = await documentCipher.deriveId({
        jwe: jwe as Parameters<typeof documentCipher.deriveId>[0]['jwe']
      })
      if (derived !== expectedId) {
        throw new IntegrityError(
          `Cannot decrypt this resource: its content-derived id ("${derived}") ` +
            `does not match the requested id ("${expectedId}"). The server ` +
            'served this envelope under an id it was not written for.'
        )
      }
    }
    if (this.#hasEpochs && typeof was.epoch === 'string' && keyId) {
      const decryptedEpoch = keyId.split('#')[0]
      if (decryptedEpoch !== was.epoch) {
        throw new IntegrityError(
          `Cannot decrypt this resource: its envelope is bound to key epoch ` +
            `"${was.epoch}" but was decrypted with a key from epoch ` +
            `"${decryptedEpoch}". The server replayed it under a different ` +
            'epoch.'
        )
      }
    }
  }

  /**
   * @inheritdoc
   *
   * Encrypts the user-writable `custom` into an EDV Document envelope
   * (`{ jwe, ... }`) with the same `documentCipher.encrypt` used for content --
   * `custom` becomes the document `content`. The envelope's own `sequence` is
   * inert (metadata concurrency is the server's plaintext `metaVersion`, not the
   * envelope), so each write re-encrypts fresh with no `update`.
   */
  async encodeMeta({
    custom,
    id: resourceId
  }: {
    custom: ResourceMetadataCustom
    id?: string
  }): Promise<{ custom: object }> {
    const { documentCipher } = this.#edv
    // The document needs an EDV id (the cipher asserts one on decrypt). It is
    // opaque to the server -- carried inside the un-decryptable envelope -- and
    // minted fresh each write, since the metadata envelope is never updated in
    // place (concurrency is the server's plaintext `metaVersion`, Decision 3).
    const id = (await this.#edv.generateId()) as string
    // Bind the `was` parameter to the RESOURCE id (not the metadata envelope's
    // own random EDV id), so a server-side swap of two resources' metadata is
    // AEAD-detected on decode. The metadata envelope always knows the resource
    // id at encrypt time, so `resource` is always present here (never content-
    // derived) and it carries no `epoch`.
    const was: { v: number; resource?: string } = { v: this.#version }
    if (resourceId !== undefined) {
      was.resource = resourceId
    }
    const encrypted = await documentCipher.encrypt({
      doc: { id, content: custom as Record<string, unknown> },
      recipients: this.#recipients,
      keyResolver: this.#edv.keyResolver,
      hmac: undefined,
      additionalProtectedParams: { was }
    })
    return { custom: encrypted }
  }

  /**
   * @inheritdoc
   *
   * Decrypts the stored `custom` envelope back to plaintext `{ name, tags }`. An
   * absent `custom` (no metadata written yet, or cleared) decodes to `{}`; a
   * present value must be an EDV envelope (else {@link EncryptionError}, the
   * `_assertEnvelope` guard), so a foreign plaintext `custom` fails closed.
   */
  async decodeMeta(
    {
      custom
    }: {
      custom?: unknown
    },
    expectedId?: string
  ): Promise<ResourceMetadataCustom> {
    if (custom === undefined || custom === null) {
      return {}
    }
    this.#assertEnvelope(custom, 'read')
    const encryptedDoc = custom as IEncryptedDocument
    const decrypted = await this.#decrypt(encryptedDoc)
    await this.#verifyBinding({
      jwe: encryptedDoc.jwe,
      expectedId,
      keyId: decrypted.keyId
    })
    return (decrypted.content ?? {}) as ResourceMetadataCustom
  }

  /**
   * Asserts that a document read from an encrypted collection is an EDV envelope
   * (`{ jwe, ... }`) before it is handed to the cipher. A plaintext or foreign
   * resource -- one written without this codec -- carries no `jwe`, which would
   * otherwise make the EDV core throw a raw `TypeError`. Surfacing a typed
   * `EncryptionError` keeps the fail-closed contract legible to callers.
   *
   * For an `update`, the envelope's `sequence` is also validated: the cipher
   * requires a non-negative safe integer to advance from, so a foreign envelope
   * without one (or with a malformed one) must fail here as a typed
   * `EncryptionError` rather than as the cipher's raw `Error`.
   *
   * @param doc {unknown}
   * @param context {string}   the operation in progress (`read` / `update`),
   *   for the message
   * @returns {asserts doc is IEncryptedDocument}
   */
  #assertEnvelope(
    doc: unknown,
    context: string
  ): asserts doc is IEncryptedDocument {
    const jwe =
      doc !== null && typeof doc === 'object'
        ? (doc as { jwe?: unknown }).jwe
        : undefined
    if (jwe === null || typeof jwe !== 'object') {
      throw new EncryptionError(
        `Cannot ${context} an encrypted resource: the stored document is not ` +
          'an EDV envelope (it carries no `jwe` field). It was likely written ' +
          'as plaintext, or by a writer that did not use this encrypted ' +
          'collection.'
      )
    }
    if (context === 'update') {
      const { sequence } = doc as { sequence?: unknown }
      if (
        typeof sequence !== 'number' ||
        !Number.isSafeInteger(sequence) ||
        sequence < 0
      ) {
        throw new EncryptionError(
          'Cannot update an encrypted resource: the stored EDV envelope ' +
            'carries no valid `sequence` (a non-negative safe integer is ' +
            'required to advance it). It was likely written by a foreign ' +
            'tool that did not maintain the EDV document sequence.'
        )
      }
    }
  }

  /**
   * Splits a caller value into a decrypted EDV document `{ content, meta }`,
   * carrying the plaintext content type and inline-encoding discriminator in
   * `meta`. Three cases:
   *
   * 1. JSON object/array to `content` verbatim, `meta = { contentType }` (no
   *   `encoding`); the shape of `content` is never inspected on read, so a
   *   caller object shaped like `{ text }` / `{ bytes }` round-trips as itself.
   * 2. Text (`Blob`/`Uint8Array` of a text-family type that is valid UTF-8)
   *   to `content = { text }`, `meta = { contentType, encoding: 'utf-8' }`;
   *   stored legibly with no base64 inflation.
   * 3. Binary (any other `Blob`/`Uint8Array`) to `content = { bytes: base64 }`,
   *   `meta = { contentType, encoding: 'base64' }`.
   *
   * A bare primitive is rejected (mirroring the plaintext `prepareBody`
   * contract). The binary/text detection and content-type precedence are the
   * shared `resolvePayload` rules, so the plaintext and encrypted write paths
   * cannot drift.
   *
   * @param data {ResourceData}
   * @param [contentType] {string}   caller-supplied content type
   * @param [id] {string}            resource id, for the extension guess
   * @returns {Promise<{ content: Record<string, unknown>; meta:
   *   Record<string, unknown> }>}
   */
  async #toDocument(
    data: ResourceData,
    contentType?: string,
    id?: string
  ): Promise<{
    content: Record<string, unknown>
    meta: Record<string, unknown>
  }> {
    const payload = resolvePayload({ data, contentType, id })

    if (payload.kind === 'binary') {
      const bytes = isBlob(payload.data)
        ? new Uint8Array(await payload.data.arrayBuffer())
        : payload.data
      const resolvedType = payload.contentType
      if (bytes.length > this.#maxBlobBytes) {
        throw new ValidationError(
          `Encrypted binary write of ${bytes.length} bytes exceeds the ` +
            `single-document limit of ${this.#maxBlobBytes} bytes. The codec ` +
            'seam is a single-request transform and cannot chunk. To store a ' +
            'blob this large, write it through the chunked-stream path -- ' +
            '`EdvClientCore.insert({ doc, stream, transport })` with a ' +
            '`WasTransport`, read back with `getStream` -- against a server ' +
            "whose backend advertises the 'chunked-streams' feature."
        )
      }
      // Text-family AND valid UTF-8 to store as a legible string. The UTF-8 gate
      // guarantees the bytes survive the string round-trip exactly; anything
      // else falls through to base64, which is always byte-safe.
      if (isTextContentType(resolvedType)) {
        const text = decodeUtf8(bytes)
        if (text !== null) {
          return {
            content: { text },
            meta: { contentType: resolvedType, encoding: 'utf-8' }
          }
        }
      }
      return {
        content: { bytes: base64.encode(bytes) },
        meta: { contentType: resolvedType, encoding: 'base64' }
      }
    }

    if (payload.kind === 'json') {
      // JSON object/array: content verbatim, no encoding (the read side treats an
      // absent `meta.encoding` as JSON). EDV models `content` as an object
      // record; a JSON array is also a valid encrypted value here, so widen it.
      return {
        content: data as Record<string, unknown>,
        meta: { contentType: contentType ?? 'application/json' }
      }
    }

    throw new ValidationError(
      'Encrypted resource data must be a plain object/array (JSON) or a ' +
        'Blob/Uint8Array (binary).'
    )
  }

  /**
   * Reconstructs a caller value from a decrypted EDV document, discriminating
   * on `meta.encoding`:
   *
   * - `'utf-8'` to a `Blob` typed `meta.contentType` from `content.text`.
   * - `'base64'` to a `Blob` typed `meta.contentType` from `content.bytes`.
   * - absent (or `meta` absent) to `content` returned verbatim as JSON.
   *
   * A malformed inner shape (an encoding that does not match its container key's
   * type) throws {@link EncryptionError} -- the decrypted-document analogue of
   * `_assertEnvelope`'s outer guard.
   *
   * @param content {unknown}
   * @param [meta] {Record<string, unknown>}
   * @returns {Json | Blob}
   */
  #fromDocument(content: unknown, meta?: Record<string, unknown>): Json | Blob {
    const encoding = meta?.encoding
    const contentType =
      typeof meta?.contentType === 'string' ? meta.contentType : undefined
    if (encoding === 'utf-8') {
      const text = (content as { text?: unknown } | null)?.text
      if (typeof text !== 'string') {
        throw new EncryptionError(
          'Malformed encrypted text document: meta.encoding is "utf-8" but ' +
            'content.text is not a string.'
        )
      }
      return new Blob([ENCODER.encode(text) as BlobPart], { type: contentType })
    }
    if (encoding === 'base64') {
      const base64Text = (content as { bytes?: unknown } | null)?.bytes
      if (typeof base64Text !== 'string') {
        throw new EncryptionError(
          'Malformed encrypted binary document: meta.encoding is "base64" but ' +
            'content.bytes is not a string.'
        )
      }
      return new Blob([base64.decode(base64Text) as BlobPart], {
        type: contentType
      })
    }
    return content as Json
  }
}

/**
 * Decodes bytes as strict UTF-8, returning `null` when they are not valid UTF-8
 * (so the caller can fall back to base64). Uses the shared fatal decoder.
 *
 * @param bytes {Uint8Array}
 * @returns {string | null}
 */
function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return UTF8_DECODER.decode(bytes)
  } catch {
    return null
  }
}

/**
 * Parses the `was` binding out of a JWE's protected header. The header is
 * base64url (no padding) JSON; a successful decrypt has already proven it
 * authentic, so this parse is trusted. Returns the `was` object, or `undefined`
 * when the header is absent/unparseable or carries no `was` member (a legacy
 * envelope that predates the binding).
 *
 * @param jwe {unknown}
 * @returns {Record<string, unknown> | undefined}
 */
function parseWasHeader(jwe: unknown): Record<string, unknown> | undefined {
  const protectedHeader = (jwe as { protected?: unknown } | null)?.protected
  if (typeof protectedHeader !== 'string') {
    return undefined
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(
      new TextDecoder().decode(base64urlnopad.decode(protectedHeader))
    )
  } catch {
    return undefined
  }
  const was = (parsed as { was?: unknown } | null)?.was
  if (was === null || typeof was !== 'object') {
    return undefined
  }
  return was as Record<string, unknown>
}

/**
 * The EDV scheme tag this provider handles (matches the Collection marker).
 */
const EDV_SCHEME = 'edv'

/**
 * The per-collection key material an EDV codec is built from.
 */
export interface EdvKeys {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}

/**
 * Builds an {@link EncryptionProvider} for the `edv` scheme: a pure **keystore**
 * that turns a collection's keys into an {@link EdvCodec}. Pass the result as
 * `WasClient`'s `encryption` option.
 *
 * It does **not** decide which collections are encrypted -- that policy is the
 * Collection's `encryption` marker (or a per-handle override). Core calls
 * `codecFor` only for a collection already known to be encrypted; this provider
 * then supplies the keys: the override-supplied `keys` when present, else
 * `resolveKeys({ spaceId, collectionId })`. `resolveKeys` returning `null` means
 * "I hold no keys for this collection", so core fails closed (it does **not**
 * mean plaintext -- the marker/override already decided that). A non-`edv`
 * scheme yields `null` (this provider does not handle it).
 *
 * @param options {object}
 * @param options.resolveKeys {function}   the keystore: returns the collection's
 *   `{ keyAgreementKey, keyResolver }`, or `null` if this client holds no keys
 *   for it (fail-closed -- not a plaintext signal)
 * @param [options.contentType] {string}   stored envelope content type;
 *   defaults to `application/json`. Pass `JOSE_CONTENT_TYPE`
 *   (`application/jose+json`) against a server that registers an
 *   `application/*+json` parser.
 * @param [options.maxBlobBytes] {number}   single-document binary cap in raw
 *   bytes (default 512 KiB, sized so the encrypted envelope stays under a
 *   server's ~1 MiB JSON body cap; raise it against a server with a larger
 *   limit)
 * @param [options.idDerivation] {string}   how `add()` mints a document id.
 *   `'random'` (default) is the classic mutable-document model: a random
 *   `generateId()` id, updated in place via `sequence`. `'content'` derives the
 *   id from the encrypted envelope's JWE ciphertext
 *   (`EdvDocumentCipher.deriveId`), making documents content-addressed and
 *   therefore immutable (an "update" is delete-old + add-new) -- the model a
 *   replicating store wants, since the id is stable across replicas with no
 *   mapping table. Both formats pass the same EDV id check; the explicit-id
 *   `put(id, ...)` path is unaffected either way.
 * @returns {EncryptionProvider}
 */
export function createEdvEncryption({
  resolveKeys,
  contentType = DEFAULT_CONTENT_TYPE,
  maxBlobBytes = DEFAULT_MAX_BLOB_BYTES,
  idDerivation = 'random'
}: {
  resolveKeys: (ref: {
    spaceId: string
    collectionId: string
  }) => Promise<EdvKeys | null>
  contentType?: string
  maxBlobBytes?: number
  idDerivation?: 'random' | 'content'
}): EncryptionProvider {
  return {
    async codecFor({ spaceId, collectionId, scheme, encryption, keys }) {
      if (scheme !== EDV_SCHEME) {
        return null
      }
      // Refuse a marker from a future scheme version: this client does not
      // implement it, and silently operating on it could mis-handle the data.
      const markerVersion = encryption?.version
      if (typeof markerVersion === 'number' && markerVersion > 1) {
        throw new EncryptionError(
          `Collection ${spaceId}/${collectionId} declares EDV-over-WAS scheme ` +
            `version ${markerVersion}, which this client (version 1) does not ` +
            'implement. Upgrade the client.'
        )
      }
      // Prefer override-supplied keys; otherwise consult the keystore.
      const resolved =
        (keys as EdvKeys | undefined) ??
        (await resolveKeys({ spaceId, collectionId }))
      if (!resolved) {
        return null
      }
      // Single-key collection (no epochs on the marker): the wallet's own
      // key-agreement key encrypts and decrypts directly.
      let keyAgreementKey = resolved.keyAgreementKey
      let keyResolver: IKeyResolver = resolved.keyResolver
      let readKeys: IKeyAgreementKey[] | undefined
      let writeEpoch: string | undefined
      // Multi-recipient (key-epoch) collection: resolve the reader's per-epoch
      // keys from the marker -- the `currentEpoch` key pair for writes, every
      // epoch key it can unwrap for reads -- and drive the cipher with those.
      // The reader's own key-agreement key is used only to unwrap the epoch
      // keys, never to encrypt resources.
      if (encryption?.epochs && encryption.epochs.length > 0) {
        const epochKeys = await resolveEpochKeys({
          encryption,
          keyAgreementKey: resolved.keyAgreementKey
        })
        if (epochKeys) {
          // Epoch keys are self-describing did:key key-agreement keys, so a
          // resource's recipient (the epoch public key) resolves through the
          // standard did:key resolver, independent of the reader's own keystore.
          keyAgreementKey = epochKeys.writeKey
          keyResolver = didKeyResolver
          readKeys = epochKeys.readKeys
          writeEpoch = epochKeys.writeEpoch
        }
      }
      const edv = new EdvClientCore({ keyAgreementKey, keyResolver })
      return new EdvCodec({
        edv,
        keyAgreementKey,
        readKeys,
        writeEpoch,
        contentType,
        maxBlobBytes,
        idDerivation,
        version: markerVersion ?? 1,
        hasEpochs: !!(encryption?.epochs && encryption.epochs.length > 0)
      })
    }
  }
}
