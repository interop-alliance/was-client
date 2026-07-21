/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Authenticated epoch configuration for multi-recipient encrypted Collections:
 * a MAC over a Collection `encryption` marker's epoch configuration, keyed from
 * the current epoch's secret (which the server never holds). It lets a reader
 * detect a server-side rollback of `currentEpoch` or a fabricated epoch list --
 * a malicious server cannot forge a valid MAC without the epoch secret.
 *
 * The MAC covers only `scheme`, `version`, `currentEpoch`, and the ordered list
 * of epoch ids -- deliberately NOT the recipient entries, so adding a recipient
 * (which cannot be forged without the epoch secret anyway) does not invalidate
 * the MAC. Covering `version` makes stripping the marker's scheme version
 * MAC-detectable.
 *
 * Documented limitation (mirrors Cryptomator's versionMac): a server can still
 * replay an ENTIRE prior consistent configuration (an old epoch list with its
 * matching old MAC). Detecting that needs client-side monotonic state, which is
 * out of scope here.
 */
import { base64urlnopad } from '@scure/base'
import type {
  CollectionEncryption,
  CollectionEncryptionEpochsMac
} from '../types.js'

const TEXT_ENCODER = new TextEncoder()

/**
 * The HKDF `info` string binding the derived key to this MAC construction.
 */
const MAC_KEY_INFO = TEXT_ENCODER.encode('was-epoch-config-mac/v1')

/**
 * The domain-separation prefix prepended to the JSON payload before it is MACed.
 */
const MAC_PAYLOAD_PREFIX = 'was-epoch-config/v1.'

/**
 * Derives the HMAC-SHA256 key from a 32-byte epoch secret:
 * HKDF-SHA256(ikm = the epoch secret, salt = empty, info =
 * "was-epoch-config-mac/v1", length 32 bytes). Uses WebCrypto (`crypto.subtle`)
 * so it works unchanged in Node 24 and browsers.
 *
 * @param epochSecret {Uint8Array}   the 32-byte current epoch secret
 * @returns {Promise<CryptoKey>}   the derived HMAC key (sign + verify)
 */
async function deriveMacKey(epochSecret: Uint8Array): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey(
    'raw',
    epochSecret as unknown as ArrayBuffer,
    'HKDF',
    false,
    ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: MAC_KEY_INFO
    },
    ikm,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify']
  )
}

/**
 * Builds the MACed payload bytes for a marker's epoch configuration:
 * `UTF8("was-epoch-config/v1." + JSON.stringify({ scheme, version,
 * currentEpoch, epochs }))`, with `version` normalized to `null` when absent
 * and `epochs` the ordered list of epoch id strings. The object member order is
 * fixed so both sides serialize identically.
 *
 * @param marker {CollectionEncryption}   the marker whose epoch configuration is
 *   being authenticated
 * @returns {Uint8Array}
 */
function macPayload(marker: CollectionEncryption): ArrayBuffer {
  const payload = {
    scheme: marker.scheme,
    version: marker.version ?? null,
    currentEpoch: marker.currentEpoch,
    epochs: (marker.epochs ?? []).map(epoch => epoch.id)
  }
  const bytes = TEXT_ENCODER.encode(
    MAC_PAYLOAD_PREFIX + JSON.stringify(payload)
  )
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer
}

/**
 * Computes the `epochsMac` field for a marker under the current epoch's secret.
 * Compute this over the exact marker state being written (member fields already
 * stamped), since a compare-and-swap retry re-reads the marker.
 *
 * @param options {object}
 * @param options.marker {CollectionEncryption}   the marker being written
 * @param options.epochSecret {Uint8Array}   the 32-byte current epoch secret
 * @returns {Promise<CollectionEncryptionEpochsMac>}
 */
export async function computeEpochsMac({
  marker,
  epochSecret
}: {
  marker: CollectionEncryption
  epochSecret: Uint8Array
}): Promise<CollectionEncryptionEpochsMac> {
  const key = await deriveMacKey(epochSecret)
  const signature = await crypto.subtle.sign('HMAC', key, macPayload(marker))
  return {
    v: 1,
    alg: 'HS256',
    mac: base64urlnopad.encode(new Uint8Array(signature))
  }
}

/**
 * Verifies a marker's `epochsMac` against a recomputation from the current
 * epoch's secret. Returns `false` on any mismatch (or a malformed `mac`); the
 * caller decides the error semantics. The MAC construction's own version/alg
 * (`v` / `alg`) is validated by the caller before this is called.
 *
 * @param options {object}
 * @param options.marker {CollectionEncryption}   the marker to verify (its
 *   `epochsMac.mac` is the tag under test)
 * @param options.epochSecret {Uint8Array}   the 32-byte current epoch secret
 * @returns {Promise<boolean>}
 */
export async function verifyEpochsMac({
  marker,
  epochSecret
}: {
  marker: CollectionEncryption
  epochSecret: Uint8Array
}): Promise<boolean> {
  const epochsMac = marker.epochsMac
  if (!epochsMac) {
    return false
  }
  let mac: Uint8Array
  try {
    mac = base64urlnopad.decode(epochsMac.mac)
  } catch {
    return false
  }
  const key = await deriveMacKey(epochSecret)
  return crypto.subtle.verify(
    'HMAC',
    key,
    mac as unknown as ArrayBuffer,
    macPayload(marker)
  )
}
