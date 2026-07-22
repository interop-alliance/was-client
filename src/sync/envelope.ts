/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The pure EDV-envelope predicate, kept dependency-free (no crypto graph) so a
 * plaintext consumer can import it without pulling the `@interop/was-client/edv`
 * stack.
 */
import type { Json } from '../types.js'

/**
 * Whether a stored body is an EDV encryption envelope (carries an object `jwe`)
 * rather than a plaintext document. Lets read paths stay tolerant of legacy
 * plaintext rows (written before a collection's encryption marker was declared)
 * and lets a one-time migration find the rows it must re-key.
 *
 * @param data {Json | undefined}   the stored resource body
 * @returns {boolean}
 */
export function isEncryptedEnvelope(data: Json | undefined): boolean {
  if (data === undefined || data === null || typeof data !== 'object') {
    return false
  }
  const jwe = (data as { jwe?: unknown }).jwe
  return jwe !== null && typeof jwe === 'object'
}
