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
import { toUrl } from './paths.js'
import type { GrantOptions, IDelegatedZcap, IZcap } from '../types.js'

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
  { to, actions, expires, target, capability }: GrantOptions
): Promise<IDelegatedZcap> {
  return context.zcapClient.delegate({
    controller: to,
    invocationTarget: target,
    allowedActions: actions.map(action => action.toUpperCase()),
    expires,
    capability
  })
}

/**
 * The scoped-grant sugar shared by `Space.grant` and `Collection.grant`:
 * delegates per `GrantOptions` with the grant `target` prefilled from the
 * handle's `path` (and the handle's bound `capability`, if any, as the parent
 * for re-delegation). Explicit options win over both prefills.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.path {string}           the handle's path (target fallback)
 * @param options.options {GrantOptions}  the caller's grant options
 * @param [options.capability] {IZcap}    the handle's bound capability
 * @returns {Promise<IDelegatedZcap>}
 */
export async function delegateGrantAt(
  context: ClientContext,
  {
    path,
    options,
    capability
  }: { path: string; options: GrantOptions; capability?: IZcap }
): Promise<IDelegatedZcap> {
  return delegateGrant(context, {
    ...options,
    target: options.target ?? toUrl({ serverUrl: context.serverUrl, path }),
    capability: options.capability ?? capability
  })
}
