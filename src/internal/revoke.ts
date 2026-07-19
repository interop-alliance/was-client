/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The revocation primitive shared by `was.revoke()` and `space.revoke()` -- the
 * inverse of `grant.ts`. Submits a delegated capability to its Space's
 * revocation endpoint (`POST /space/:spaceId/zcaps/revocations/:capabilityId`),
 * where the URL names the capability's `id` and the body is that capability
 * verbatim, proof and capability chain included.
 *
 * The submission invokes the revocation URL's **own** root capability, whose
 * controller the server synthesizes as every controller in the to-be-revoked
 * capability's delegation chain. That chain is dereferenced root-first, so it
 * includes the root capability -- whose controller is the Space controller.
 * A single invocation therefore authorizes both legitimate callers of the
 * server's dual-root rule ("the delegator revokes" and "a delegee revokes its
 * own capability"), with no need to know which one this client is.
 */
import { spaceRevocation, toUrl, parseSpaceTarget } from './paths.js'
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { ValidationError } from '../errors.js'
import type { IDelegatedZcap, IRootZcap, IZcap } from '../types.js'

/**
 * The zcap JSON-LD context URL, the sole `@context` of a root capability.
 */
const ZCAP_CONTEXT_URL = 'https://w3id.org/zcap/v1'

/**
 * The root capability id for an invocation target URL
 * (`urn:zcap:root:<encoded target>`) -- the id grammar shared by revocation
 * (which invokes the revocation URL's own root capability in object form) and
 * grant rooting (which parents an unparented grant on its Space's root
 * capability id).
 *
 * @param target {string}   the absolute invocation target URL
 * @returns {string}
 */
export function rootCapabilityId(target: string): string {
  return `urn:zcap:root:${encodeURIComponent(target)}`
}

/**
 * Builds the root capability for `target` in **object** form.
 *
 * The object form is load-bearing: `@interop/ezcap` accepts a *string* root
 * capability id only when its invocation target is `https:`, which would break
 * against an `http://localhost` server. Both forms reduce to the same
 * `zcap id="..."` invocation header.
 *
 * `controller` is client-side only -- the server re-derives the real controller
 * when it synthesizes the root capability -- so the caller's own DID is fine.
 *
 * @param options {object}
 * @param options.target {string}       the absolute invocation target URL
 * @param options.controller {string}   the invoking client's DID
 * @returns {IRootZcap}
 */
function rootCapability({
  target,
  controller
}: {
  target: string
  controller: string
}): IRootZcap {
  return {
    '@context': ZCAP_CONTEXT_URL,
    id: rootCapabilityId(target),
    invocationTarget: target,
    controller
  }
}

/**
 * Derives the id of the Space a capability is rooted in, from its
 * `invocationTarget`. A Space-rooted capability's target is the Space URL or a
 * path beneath it (the server enforces this when it verifies the chain), so
 * every depth `parseSpaceTarget` recognizes -- Space, Collection, Resource, or a
 * reserved sub-resource such as `/space/s/c/r/meta` -- carries the Space id.
 *
 * @param context {ClientContext}
 * @param zcap {IZcap}   the capability to locate
 * @returns {string}
 */
export function spaceIdOf(context: ClientContext, zcap: IZcap): string {
  const parsed = parseSpaceTarget({
    serverUrl: context.serverUrl,
    target: zcap.invocationTarget
  })
  if (parsed === null) {
    throw new ValidationError(
      `Cannot derive a Space from invocationTarget ` +
        `"${zcap.invocationTarget}": it does not address a Space on ` +
        `"${context.serverUrl}". Revocation is scoped to one Space.`
    )
  }
  return parsed.spaceId
}

/**
 * Revokes a Space-rooted delegated capability: `POST`s it to
 * `/space/:spaceId/zcaps/revocations/:capabilityId`, invoking that URL's own
 * root capability. Resolves on the server's 204.
 *
 * The `action` is deliberately left unset: `send()` defaults it to the HTTP
 * method, and this route expects `POST` (WAS capabilities are scoped by HTTP
 * method, unlike the webkms `/kms` revocation route's `write`).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.spaceId {string}          the Space the capability is rooted in
 * @param options.zcap {IDelegatedZcap}     the capability to revoke
 * @returns {Promise<void>}
 */
export async function submitRevocation(
  context: ClientContext,
  { spaceId, zcap }: { spaceId: string; zcap: IDelegatedZcap }
): Promise<void> {
  if (!('parentCapability' in zcap)) {
    throw new ValidationError(
      'A root capability cannot be revoked; only a delegated capability can.'
    )
  }
  const url = toUrl({
    serverUrl: context.serverUrl,
    path: spaceRevocation(spaceId, zcap.id)
  })
  await send(context, {
    url,
    method: 'POST',
    capability: rootCapability({
      target: url,
      controller: context.controllerDid
    }),
    json: zcap
  })
}
