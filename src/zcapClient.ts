/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one `ZcapClient` construction site: every zcap a was-client consumer
 * mints through it -- invocations and delegations alike -- is signed under
 * `eddsa-jcs-2022`. `WasClient.fromSigner` and the `./identity` derivations
 * both build their client here.
 */
import { EddsaJcs2022 } from '@interop/ed25519-signature/eddsa-jcs-2022'
import { ZcapClient } from '@interop/ezcap'
import type { ISigner } from '@interop/data-integrity-core'

/**
 * A `ZcapClient` signing invocations and delegations alike with one signer,
 * under `eddsa-jcs-2022` -- the suite every zcap this library and its
 * consumers mint is signed with. The suite is hard-coded rather than threaded
 * as a caller option: a wrong setting would surface only as an interop failure
 * at the server, so a second copy is a setting someone has to remember.
 * Callers that sign under a different key id (a did:webvh verification
 * method, a ladder VM) build the signer and hand it here.
 *
 * @param options {object}
 * @param options.signer {ISigner}   signs invocations and delegations alike
 * @returns {ZcapClient}
 */
export function zcapClientForSigner({
  signer
}: {
  signer: ISigner
}): ZcapClient {
  return new ZcapClient({
    SuiteClass: EddsaJcs2022,
    invocationSigner: signer,
    delegationSigner: signer
  })
}
