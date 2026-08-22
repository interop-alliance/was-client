/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/log` subpath entry: the WAS binding of
 * `@interop/vh-resource-log`'s store port -- `resourceLogStore` maps the
 * port's read-with-etag, compare-and-swap append, and guarded genesis create
 * onto one WAS Resource's conditional writes, rethrowing a lost race as the
 * library's `ResourceLogConflictError`. Everything else about resource logs
 * (the Resource Log Profile, encrypted-collections-spec
 * `#resource-log-profile`) lives in that library: the JSON Lines codec, the
 * `ResourceLogStore` port itself, the read-back `confirmAppend`, chain
 * verification, and the chain-head pin. The wire types live in
 * `@interop/storage-core`. This subpath re-exports none of them: one owner
 * per name.
 *
 * The subpath stays off the `/edv` graph. It is no longer crypto-free: the
 * library's graph includes `@interop/did-method-webvh` and `@noble/curves`
 * -- the hashing and proof kernel only, with no DID resolution.
 */
export { LOG_CONTENT_TYPE, resourceLogStore } from './logStore.js'
