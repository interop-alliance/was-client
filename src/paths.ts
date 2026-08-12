/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/paths` subpath entry: the WAS URL grammar as
 * standalone functions, for a consumer that has to form a WAS path or a zcap
 * `invocationTarget` without going through a navigational handle.
 *
 * The path builders own the trailing-slash canonicalization (item-create and
 * listing endpoints carry a trailing slash; get/put/delete-by-id endpoints do
 * not) and the per-segment percent-encoding, and the zcap `invocationTarget` is
 * derived from the request URL -- so a caller that hand-assembles a path is
 * re-deriving rules that must match the server's `allowedTarget` byte for byte.
 * Exporting the builders instead is what keeps that from happening.
 *
 * `parseSpacePath` / `parseSpaceTarget` are the inverse grammar (a pathname or
 * an absolute URL back to the containment depth it addresses), and
 * `rootCapabilityId` / `rootCapability` mint the `urn:zcap:root:` capability a
 * target's own root invocation names -- the id form for parenting an unparented
 * grant, the object form for invoking it (`@interop/ezcap` accepts a bare root
 * capability id only for an `https:` target, which would break against an
 * `http://localhost` server).
 *
 * Kept off the core entry so a consumer opts in; every export here is a pure
 * function with no I/O and no client state.
 */
export {
  spacePath,
  collectionPath,
  collectionItems,
  collectionMeta,
  collectionQuery,
  resourcePath,
  resourceMeta,
  toUrl,
  parseSpacePath,
  parseSpaceTarget
} from './internal/paths.js'
export type { ParsedSpacePath } from './internal/paths.js'

export { rootCapabilityId, rootCapability } from './internal/revoke.js'
