# Wallet Attached Storage Client _(@interop/was-client)_

[![NPM Version](https://img.shields.io/npm/v/@interop/was-client.svg)](https://npm.im/@interop/was-client)

> A developer-friendly client for Wallet Attached Storage (WAS) servers, with a
> MongoDB-driver-inspired navigational API over zcap-authorized HTTP.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
  - [Construction](#construction)
  - [The handle model](#the-handle-model)
  - [Resources: JSON and binary](#resources-json-and-binary)
  - [Delegation and sharing](#delegation-and-sharing)
  - [Export and import](#export-and-import)
  - [The manual-request escape hatch](#the-manual-request-escape-hatch)
- [Errors and the 404/null caveat](#errors-and-the-404null-caveat)
- [Contribute](#contribute)
- [License](#license)

## Background

The WAS protocol exposes a containment model --
`SpacesRepository > Space > Collection > Resource` -- over HTTP, authorized with
[Authorization Capabilities (zcaps)](https://w3c-ccg.github.io/zcap-spec/). The
low-level transport is an
[`@interop/ezcap`](https://www.npmjs.com/package/@interop/ezcap) `ZcapClient`,
where every operation hand-builds a URL, picks a trailing-slash variant, threads
JSON vs binary bodies, and reasons about delegation inline.

`@interop/was-client` wraps that `ZcapClient` and exposes the containment model
through cheap, lazy navigational handles modeled on the MongoDB driver's DX
(`client > db > collection`), using WAS-specific verbs
(`add`/`get`/`put`/`list`/`delete`) rather than `insertOne`/`findOne` (WAS has
no query-by-filter yet).

| MongoDB driver                      | WAS client                                 |
| ----------------------------------- | ------------------------------------------ |
| `new MongoClient(url)`              | `new WasClient({ serverUrl, zcapClient })` |
| `client.db('app')`                  | `was.space(spaceId)`                       |
| `db.collection('users')`            | `space.collection(collectionId)`           |
| `collection.insertOne(doc)`         | `collection.add(doc)`                      |
| `collection.findOne({ _id })`       | `collection.get(resourceId)`               |
| `collection.replaceOne({ _id }, d)` | `collection.put(resourceId, data)`         |
| `collection.find().toArray()`       | `collection.list()`                        |
| `collection.deleteOne({ _id })`     | `collection.resource(resourceId).delete()` |

## Install

- Node.js 24+ is recommended.

```
pnpm install @interop/was-client
```

## Usage

### Construction

```ts
import { WasClient } from '@interop/was-client'

// Primary form: wrap an existing ezcap ZcapClient (which holds the signer).
const was = new WasClient({ serverUrl, zcapClient })

// Convenience: build the ZcapClient internally from a signer
// (uses the Ed25519Signature2020 suite).
const was = WasClient.fromSigner({ serverUrl, signer })
```

`serverUrl` is the base for both URL building and zcap `invocationTarget`s, so
the "server URL must equal the invocation target host:port" constraint holds by
construction.

### The handle model

Handles are lazy and synchronous to obtain -- only the verb methods hit the
network. Lazy chains never throw: `was.space(x).collection(y)` does no I/O and
just accumulates URL context. Existence is checked on the first network verb.

```ts
const space = await was.createSpace({ name: 'Home' }) // POST /spaces/

const collection = await space.createCollection({
  id: 'credentials',
  name: 'Verifiable Credentials'
})

await collection.put('vc-1', {
  type: ['VerifiableCredential'],
  name: 'Diploma'
})
const vc = await collection.get('vc-1') // parsed JSON object, or null on a miss

const listing = await collection.list() // { id, url, totalItems, items, ... }

await collection.resource('vc-1').delete() // delete one resource by id
await space.delete() // delete the whole space (idempotent)
```

`delete()` is uniform at every level, takes no argument, and always deletes the
thing the handle points at -- so there is no "delete the collection" vs "delete
one item" footgun.

### Resources: JSON and binary

Writes detect the payload: a plain object/array is sent as JSON; a
`Blob`/`Uint8Array`/`Buffer` is sent as binary, with the content-type taken from
`options.contentType`, the `Blob.type`, or `application/octet-stream`.

```ts
// JSON
await collection.put('doc', { hello: 'world' })

// Binary
const bytes = new TextEncoder().encode('plain text body')
await collection.put('note.txt', bytes, { contentType: 'text/plain' })

const resource = collection.resource('note.txt')
await resource.get() // a Blob (whose .type carries the content-type)
await resource.getText() // 'plain text body'
await resource.getBytes() // Uint8Array
```

Reads auto-parse: `get()` returns a parsed object for a JSON content-type and a
`Blob` otherwise; `getText()` / `getBytes()` are explicit escape hatches.

### Delegation and sharing

`was.grant(...)` is the general delegation primitive; `space.grant(...)` and
`collection.grant(...)` are sugar that prefill the grant `target` with the
handle's URL. The recipient rebuilds access from the received zcap with
`fromCapability()`.

```ts
// Alice grants Bob read access to a resource.
const added = await collection.add({ secret: 'value' })
const zcap = await was.grant({
  to: bobDid,
  actions: ['GET'], // HTTP verbs: 'GET' | 'PUT' | 'POST' | 'DELETE'
  target: added.url
})

// Bob, holding the zcap, rebuilds a handle at the right depth.
const handle = bobWas.fromCapability(zcap) // a Resource here
await handle.get() // succeeds; a write would be denied by the GET-only grant
```

Actions are HTTP verbs (`GET` / `PUT` / `POST` / `DELETE`). The WAS server
authorizes on these case-sensitively (uppercase), but `grant()` also accepts the
lowercase forms and normalizes them to uppercase in the signed zcap -- so
`actions: ['get']` still validates server-side.

### Public sharing and access-control policies

A Space, Collection, or Resource can carry an access-control **policy** that
grants read access beyond capabilities -- most commonly making it world-readable
("share via public link"). The policy methods live on all three handles:

```ts
// Make a whole collection world-readable (the "create public link" case).
await collection.setPublic() // sugar for setPolicy({ type: 'PublicCanRead' })

// Anyone (even unauthenticated) can now read its resources.
const link = added.url // hand this URL out; a plain GET resolves it

// Inspect or revoke.
const policy = await collection.getPolicy() // { type: 'PublicCanRead' } | null
await collection.clearPolicy() // revert to capability-only access (idempotent)

// setPolicy() is the generic, forward-compatible primitive; setPublic() is sugar.
await space.setPolicy({ type: 'PublicCanRead' }) // inherited by all contents
await resource.setPublic() // a single public resource
```

Policies are resolved most-specific-first (Resource over Collection over Space)
and are permissive-only -- they broaden access, never restrict a valid capability
holder. Managing a policy is a controller-level operation. Discover a policy via
`space.linkset()` / `collection.linkset()` (RFC9264) or the `linkset` property on
a description.

### Export and import

```ts
const archive = await space.export() // Uint8Array (application/x-tar)
const stats = await otherSpace.import(archive)
// { collectionsCreated, collectionsSkipped, resourcesCreated, resourcesSkipped,
//   policiesCreated, policiesSkipped }
```

### The manual-request escape hatch

`was.request(...)` mirrors ezcap's generic `request()` for hand-built calls. As
a deliberate escape hatch it returns the raw `HttpResponse` and throws raw
ezcap/ky errors -- it does not apply the null-on-404 or typed-error
conveniences.

```ts
const response = await was.request({ path: `/space/${spaceId}`, method: 'GET' })
```

## Errors and the 404/null caveat

Read methods (`describe`/`get`/`list`) return `null` on a 404, following
MongoDB's `findOne` semantics. **WAS returns 404 for both not-found and
unauthorized**, so `null` means "not visible to you" rather than strictly "does
not exist". Write/delete methods throw a typed error instead.

| Status | Read methods          | Write / delete methods |
| ------ | --------------------- | ---------------------- |
| 404    | `null`                | `NotFoundError`        |
| 400    | `ValidationError`     | `ValidationError`      |
| 401    | `AuthRequiredError`   | `AuthRequiredError`    |
| 501    | `NotImplementedError` | `NotImplementedError`  |
| 5xx    | `WasServerError`      | `WasServerError`       |

All error classes extend `WasError` (carrying `status`, `title`, `details`, and
`requestUrl`). `delete()` additionally treats a 404 as success, so it is
idempotent.

Some spec endpoints (`listSpaces()`, `meta`, `query`, ...) are not yet
implemented by the reference server and currently surface `NotImplementedError`.

## Contribute

PRs accepted. See [CONTRIBUTING.md](CONTRIBUTING.md) for editor setup (Prettier,
ESLint, and EditorConfig) and how it maps to CI.

## License

[MIT License](LICENSE.md) © 2026 Interop Alliance.
