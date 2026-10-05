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
 * rather than a plaintext document.
 *
 * This is a shape test, not a routing decision. It does not decide whether a
 * body should be decrypted. Whether a collection is encrypted is settled by its
 * descriptor, and a read from an encrypted collection must refuse a body that
 * fails this test (`EdvCodec.decode` does so with an `EncryptionError`). A
 * read path that hands a non-envelope body through as plaintext because the
 * descriptor was declared after the row was written accepts whatever the
 * server serves, with no decrypt and no binding check. That tolerance belongs
 * on an explicit migration path, where this predicate finds the rows to
 * re-key, and nowhere else.
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
