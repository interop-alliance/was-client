/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared access-control policy I/O for the Space / Collection / Resource
 * handles, which differ only in the policy sub-resource path. Each handle wraps
 * these with its own JSDoc and the trivial `isPublic` / `setPublic` sugar.
 */
import type { ClientContext } from './request.js'
import { send } from './request.js'
import { dataOrNull } from './content.js'
import type { IZcap, PolicyDocument } from '../types.js'

/**
 * Reads the access-control policy at `policyPath`. Returns `null` when no policy
 * is set (or it is not visible to you).
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyPath {string}   the policy sub-resource path
 * @param [options.capability] {IZcap}
 * @returns {Promise<PolicyDocument | null>}
 */
export async function readPolicy(
  context: ClientContext,
  { policyPath, capability }: { policyPath: string; capability?: IZcap }
): Promise<PolicyDocument | null> {
  const response = await send(context, {
    path: policyPath,
    method: 'GET',
    capability,
    read: true
  })
  return dataOrNull<PolicyDocument>(response)
}

/**
 * Sets (creates or replaces) the access-control policy at `policyPath`.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyPath {string}   the policy sub-resource path
 * @param options.policy {PolicyDocument}
 * @param [options.capability] {IZcap}
 * @returns {Promise<void>}
 */
export async function writePolicy(
  context: ClientContext,
  {
    policyPath,
    policy,
    capability
  }: { policyPath: string; policy: PolicyDocument; capability?: IZcap }
): Promise<void> {
  await send(context, {
    path: policyPath,
    method: 'PUT',
    capability,
    json: policy
  })
}

/**
 * Whether the policy at `policyPath` is `PublicCanRead` -- the shared body of
 * the `isPublic()` sugar on the three handle classes.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyPath {string}   the policy sub-resource path
 * @param [options.capability] {IZcap}
 * @returns {Promise<boolean>}
 */
export async function isPublicPolicy(
  context: ClientContext,
  options: { policyPath: string; capability?: IZcap }
): Promise<boolean> {
  const policy = await readPolicy(context, options)
  return policy?.type === 'PublicCanRead'
}

/**
 * Sets the policy at `policyPath` to `PublicCanRead` -- the shared body of the
 * `setPublic()` sugar on the three handle classes.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyPath {string}   the policy sub-resource path
 * @param [options.capability] {IZcap}
 * @returns {Promise<void>}
 */
export async function setPublicPolicy(
  context: ClientContext,
  { policyPath, capability }: { policyPath: string; capability?: IZcap }
): Promise<void> {
  await writePolicy(context, {
    policyPath,
    policy: { type: 'PublicCanRead' },
    capability
  })
}

/**
 * Removes the access-control policy at `policyPath`, reverting to
 * capability-only access. Idempotent.
 *
 * @param context {ClientContext}
 * @param options {object}
 * @param options.policyPath {string}   the policy sub-resource path
 * @param [options.capability] {IZcap}
 * @returns {Promise<void>}
 */
export async function deletePolicy(
  context: ClientContext,
  { policyPath, capability }: { policyPath: string; capability?: IZcap }
): Promise<void> {
  await send(context, {
    path: policyPath,
    method: 'DELETE',
    capability,
    idempotent: true
  })
}
