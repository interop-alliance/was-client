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
export function bytesOf(size: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(size)
  for (let index = 0; index < size; index++) {
    bytes[index] = (index * 7 + 3) % 251
  }
  return bytes
}

/**
 * A stream that yields `bytes` in pieces of `pieceSize`, so the source shape
 * differs from the chunk size the consumer reads or writes with.
 *
 * @param options {object}
 * @param options.bytes {Uint8Array}
 * @param options.pieceSize {number}
 * @returns {ReadableStream<Uint8Array>}
 */
export function streamOf({
  bytes,
  pieceSize
}: {
  bytes: Uint8Array
  pieceSize: number
}): ReadableStream<Uint8Array> {
  let offset = 0
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close()
        return
      }
      const end = Math.min(offset + pieceSize, bytes.length)
      controller.enqueue(bytes.subarray(offset, end))
      offset = end
    }
  })
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
