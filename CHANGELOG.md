# @interop/was-client Changelog

## 0.3.0 - TBD

### Added

- `isPublic()` on the `Space`, `Collection`, and `Resource` handles: a read-only
  convenience that resolves `true` when the handle's own access-control policy is
  `{ type: 'PublicCanRead' }`.

## 0.2.0 - 2026-06-06

### Added

- Access-control policy methods on the `Space`, `Collection`, and `Resource`
  handles: `getPolicy()`, `setPolicy(policy)`, `clearPolicy()`, and the
  `setPublic()` convenience (sugar for `setPolicy({ type: 'PublicCanRead' })`)
  for the "share via public link" case. `setPolicy()` is the generic,
  forward-compatible primitive; `setPublic()` is sugar over it.
- `space.linkset()` / `collection.linkset()` read the RFC9264 linkset
  (policy discovery); `SpaceDescription` / `CollectionDescription` gain an
  optional `linkset` property.
- New exported types `PolicyDocument`, `LinkSet`, `LinkSetEntry`; path builders
  `spacePolicy` / `collectionPolicy` / `resourcePolicy` and `spaceLinkset` /
  `collectionLinkset`.

### Changed

- `ImportStats` gains `policiesCreated` / `policiesSkipped` (policies now
  round-trip through space export/import on the reference server).

## 0.1.0-0.1.1 - 2026-06-06

### Added

- Initial implementation of the Wallet Attached Storage client.
- `WasClient` wrapping an `@interop/ezcap` `ZcapClient`, with `fromSigner()`
  convenience constructor.
- Lazy navigational handles: `Space`, `Collection`, `Resource`, with
  self-lifecycle (`describe`/`configure`/`delete`) and contained-item verbs
  (`add`/`get`/`put`/`list`).
- First-class JSON and binary resources (auto content-type detection on write;
  auto-parse plus `getText()`/`getBytes()` on read).
- Delegation: the general `was.grant()` primitive, `space`/`collection` grant
  sugar, `fromCapability()`, and capability-bound handles.
- `space.export()` / `space.import()`.
- Typed error hierarchy (`WasError` base plus `NotFoundError`,
  `ValidationError`, `AuthRequiredError`, `NotImplementedError`,
  `WasServerError`) with null-on-404 read semantics and idempotent `delete()`.
- Reserved path-segment id guard on `createCollection`/`put`.
- The `was.request()` signed escape hatch.
