/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/edv` subpath entry: encrypted (EDV-over-WAS) storage
 * support. Kept off the core `@interop/was-client` entry so plaintext consumers
 * do not pull the `@interop/edv-client` / `@interop/minimal-cipher` crypto graph
 * unless they opt in by importing this subpath.
 */
export { WasTransport, EDV_CONTENT_TYPE } from './WasTransport.js'
