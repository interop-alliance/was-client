/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/was-client/identity` subpath: the did:key data-identity
 * derivation (`agents.ts`, which documents the derivation itself) and the
 * one-key resolver it pairs with (`keyResolver.ts`). Kept off the core entry
 * because it pulls the webkms-client / x25519-key-agreement-key dependency
 * graph. `zcapClientForSigner` is a core export; import it from the package
 * root.
 */
export {
  BOOTSTRAP_HANDLE,
  BOOTSTRAP_KEY_NAME,
  agentsFromKeyAgent,
  agentsFromSecret,
  agentsFromSeed
} from './agents.js'
export type { ProfileAgents } from './agents.js'
export { singleKeyResolver } from './keyResolver.js'
