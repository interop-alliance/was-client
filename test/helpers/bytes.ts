/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Byte fixtures and sinks shared by the binary and streaming tests.
 */

/**
 * A deterministic pseudo-random payload, so a byte-exact comparison is
 * meaningful.
 *
 * @param size {number}
 * @returns {Uint8Array}
 */
export function bytesOf(size: number): Uint8Array {
  return new Uint8Array(size).map((_value, index) => (index * 7 + 3) % 251)
}

/**
 * Drains a byte stream into one `Uint8Array`.
 *
 * @param stream {ReadableStream<Uint8Array>}
 * @returns {Promise<Uint8Array>}
 */
export async function drain(
  stream: ReadableStream<Uint8Array>
): Promise<Uint8Array> {
  return new Uint8Array(await new Response(stream).arrayBuffer())
}
