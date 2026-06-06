/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The delegation primitive shared by `was.grant()` and the `space`/`collection`
 * grant sugar. Maps `GrantOptions` onto `zcapClient.delegate(...)`, normalizing
 * action verbs to uppercase so a lowercase grant (`'get'`) still validates on
 * the server (which matches actions case-sensitively against `'GET'`).
 */
import type { ClientContext } from './request.js'
import type { GrantOptions, IDelegatedZcap } from '../types.js'

/**
 * Delegates a capability per `GrantOptions`, returning the signed zcap to hand
 * off out-of-band.
 *
 * @param context {ClientContext}
 * @param options {GrantOptions}
 * @returns {Promise<IDelegatedZcap>}
 */
export async function delegateGrant(
  context: ClientContext,
  options: GrantOptions
): Promise<IDelegatedZcap> {
  const { to, actions, expires, target, capability } = options
  return context.zcapClient.delegate({
    controller: to,
    invocationTarget: target,
    allowedActions: actions.map(action => action.toUpperCase()),
    expires,
    capability
  })
}
