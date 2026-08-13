# Low-level EDV-over-WAS: using WasTransport

> Most callers want the higher-level
> [pass-through encryption via the WAS client](../README.md#encrypted-collections-edv-over-was-pass-through-encryption-via-the-was-client-recommended),
> which folds encryption into the ordinary `Collection`/`Resource` handles.
> Reach for `WasTransport` only when you need to drive an `EdvClientCore`
> directly -- for example, to share encryption code with a non-WAS EDV backend
> through the same `@interop/edv-client` API, or to use EDV client features not
> yet surfaced through the pass-through codec.

Client-side end-to-end encryption, where the server stores only opaque
ciphertext and the keys never leave the client. This is the "EDV-over-WAS"
layout profile (Layer 1): it maps
[Encrypted Data Vault](https://digitalbazaar.github.io/encrypted-data-vaults/)
documents onto ordinary WAS resources, so it works against **any** WAS server
with no server changes. It is shipped on the opt-in `@interop/was-client/edv`
subpath so plaintext consumers do not pull the crypto dependencies.

`WasTransport` is an `@interop/edv-client` `Transport`: pair it with
`EdvClientCore`, which does all encryption, decryption, and key handling
client-side. The WAS Collection is the vault; each encrypted document is one WAS
resource (its EDV id is used verbatim as the resource id).

This example assumes a WAS server is already running and you have created (or
have access to) a collection to use as the vault:

```ts
import { WasClient } from '@interop/was-client'
import { WasTransport } from '@interop/was-client/edv'
import { EdvClientCore } from '@interop/edv-client'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'

const was = WasClient.fromSigner({ serverUrl, signer })
const space = await was.createSpace({ name: 'My Wallet' })
const collection = await space.createCollection({ id: 'vault', name: 'Vault' })

// Client-side key material (never sent to the server). In a real app these come
// from the wallet's key store; here we generate a key-agreement key.
const kak = await X25519KeyAgreementKey2020.generate({
  controller: was.controllerDid
})
const keyResolver = async ({ id }: { id: string }) => {
  if (id !== kak.id) throw new Error(`Unknown key id "${id}".`)
  return {
    id: kak.id,
    type: kak.type,
    publicKeyMultibase: kak.publicKeyMultibase
  }
}

const edv = new EdvClientCore({ keyAgreementKey: kak, keyResolver })
const transport = new WasTransport({
  was,
  spaceId: space.id,
  collectionId: collection.id
})

// Encrypt + write: the server stores a JWE envelope, not the cleartext.
const doc = await edv.insert({ doc: { content: { secret: 42 } }, transport })

// Read + decrypt:
const decrypted = await edv.get({ id: doc.id, transport })
console.log(decrypted.content) // { secret: 42 }
```

Scope and caveats (this is the first, documents-only increment):

- **Server affordances.** `insert` / `update` / `get` work against any WAS
  server. Blinded `find` / `count` and chunked blob streams need server-side EDV
  affordances -- a blinded `/query` endpoint (`blinded-index-query`) and the
  `/{id}/chunks/{n}` sub-segment (`chunked-streams`) -- and throw the typed
  `NotSupportedError` (from `@interop/was-client`) where the backend does not
  advertise them. Index updates
  throw unconditionally: in this profile the `indexed` entries ride inside the
  stored envelope, so an ordinary `update()` re-indexes a document.
- **Chunked streams.** `insert({ doc, stream, transport })` and
  `getStream({ doc, transport })` drive chunked encrypted blobs over this
  transport. Use this path when the blob should never be held whole in memory,
  or when the write is an update. The
  [pass-through codec](../README.md#encrypted-collections-edv-over-was-pass-through-encryption-via-the-was-client-recommended)
  routes an oversized `collection.add()` here for you, streaming the payload
  rather than buffering it. Each chunk is one upload, so `chunkSize` must stay
  under the backend's `maxUploadBytes` -- that constraint is not advertised
  through the feature probe, so an oversized chunk surfaces as the server's 413.
  The write is two-phase (document, then chunks), so a driver that fails partway
  should delete the document it wrote; the codec's plan does this for you.
- **Advisory `sequence`.** On this raw `WasTransport` path the EDV `sequence` is
  advisory: a stale `update` is not rejected (last-writer-wins), so it is safe
  for single-writer use only. (The
  [pass-through codec](../README.md#encrypted-collections-edv-over-was-pass-through-encryption-via-the-was-client-recommended)
  is lost-update-safe instead -- it drives the server's conditional writes via
  `If-Match`, surfacing a stale write as a `PreconditionFailedError`.)
- **Content type.** Envelopes are stored as `application/json` by default so any
  WAS server accepts them. The preferred marker `application/jose+json`
  (exported as `JOSE_CONTENT_TYPE`) needs the server to register an
  `application/*+json` content-type parser -- the reference was-teaching-server
  does; pass `contentType: JOSE_CONTENT_TYPE` to opt in.
