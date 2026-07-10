/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The delegation primitive shared by `was.grant()` and the `space`/`collection`
 * grant sugar. Maps `GrantOptions` onto `zcapClient.delegate(...)`, normalizing
 * action verbs to uppercase so a lowercase grant (`'get'`) still validates on
 * the server (which matches actions case-sensitively against `'GET'`).
 *
 * An unparented grant whose target lies in the server's Space tree is delegated
 * from that **Space's** root capability, with the target carried as an
 * attenuated `invocationTarget`, rather than from the target's own root
 * capability. Both forms grant the same access (the server verifies WAS routes
 * with target attenuation allowed), but only a Space-rooted chain can be revoked
 * -- revocation is Space-scoped, and the endpoint requires the chain to root
 * exactly in the Space (see `revoke.ts`).
 */
import type { ClientContext } from './request.js'
import { parseSpaceTarget, spacePath, toUrl } from './paths.js'
import type { GrantOptions, IDelegatedZcap, IZcap } from '../types.js'

/**
 * The root capability id (`urn:zcap:root:<encoded target>`) of the Space
 * containing `target`, or `undefined` when `target` is not a URL beneath this
 * server's `/space` tree (e.g. a `/kms` target, or another origin) -- in which
 * case the caller lets ezcap default to the target's own root capability.
 *
 * The id is returned as a string, which `zcapClient.delegate(...)` accepts for a
 * root parent capability. (Its sibling `request(...)` does not, for a non-`https:`
 * target -- hence the object form in `revoke.ts`.)
 *
 * @param options {object}
 * @param options.serverUrl {string}   the client's server base URL
 * @param options.target {string}      the absolute grant target URL
 * @returns {string | undefined}
 */
function spaceRootCapabilityId({
  serverUrl,
  target
}: {
  serverUrl: string
  target: string
}): string | undefined {
  const parsed = parseSpaceTarget({ serverUrl, target })
  if (parsed === null) {
    return undefined
  }
  const spaceUrl = toUrl({ serverUrl, path: spacePath(parsed.spaceId) })
  return `urn:zcap:root:${encodeURIComponent(spaceUrl)}`
}

/**
 * Delegates a capability per `GrantOptions`, returning the signed zcap to hand
 * off out-of-band. An explicit `capability` (re-delegation of a parent zcap)
 * always wins; otherwise a Space-tree target is rooted at its Space, so the
 * resulting capability is revocable via `space.revoke()` / `was.revoke()`.
 *
 * @param context {ClientContext}
 * @param options {GrantOptions}
 * @returns {Promise<IDelegatedZcap>}
 */
export async function delegateGrant(
  context: ClientContext,
  { to, actions, expires, target, capability }: GrantOptions
): Promise<IDelegatedZcap> {
  const parent =
    capability ??
    (target === undefined
      ? undefined
      : spaceRootCapabilityId({ serverUrl: context.serverUrl, target }))
  return context.zcapClient.delegate({
    controller: to,
    invocationTarget: target,
    allowedActions: actions.map(action => action.toUpperCase()),
    expires,
    capability: parent
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
