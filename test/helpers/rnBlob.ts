/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared test helpers for the React Native `Blob` shape. RN's built-in `Blob`
 * implements neither `text()` nor `arrayBuffer()` (calling either throws
 * `TypeError: undefined is not a function`) but the runtime does provide a
 * global `FileReader`. Node's `Blob` is complete and Node has no `FileReader`,
 * so a suite that wants to exercise the fallback has to build both halves:
 * `rnBlob` produces a real `Blob` with the two native methods shadowed away
 * (still `instanceof Blob`, so the library's `isBlob` guard and the codec's
 * size routing behave exactly as on device), and `installFileReader` supplies
 * a minimal event-based reader over it.
 */

/**
 * A real `Blob` with `text()` and `arrayBuffer()` shadowed to `undefined` --
 * the RN shape. The bytes are still there; only the reader can get at them.
 *
 * @param parts {Array<string | Uint8Array>}   the blob's contents
 * @param [options] {object}
 * @param [options.type] {string}              the blob's content-type
 * @returns {Blob}
 */
export function rnBlob(
  parts: Array<string | Uint8Array>,
  { type }: { type?: string } = {}
): Blob {
  const blob = new Blob(parts as BlobPart[], type === undefined ? {} : { type })
  for (const method of ['text', 'arrayBuffer'] as const) {
    Object.defineProperty(blob, method, {
      value: undefined,
      configurable: true,
      writable: true
    })
  }
  return blob
}

/**
 * Installs a minimal `FileReader` on `globalThis`, mimicking RN's: construct,
 * attach `onload` / `onerror`, call `readAsText` / `readAsArrayBuffer`, read
 * `result` (or `error`) from the handler. It gets at an {@link rnBlob}'s bytes
 * through `Blob.prototype`, which the shadowing left untouched.
 *
 * @param [options] {object}
 * @param [options.fail] {boolean}   when true, every read fires `onerror`
 *   instead of `onload`, for the rejection path
 * @returns {function}   restores the previous global; call it in a `finally`
 *   or an `afterEach`
 */
export function installFileReader({
  fail = false
}: { fail?: boolean } = {}): () => void {
  const globals = globalThis as { FileReader?: unknown }
  const previous = globals.FileReader
  const had = 'FileReader' in globals

  class StubFileReader {
    result: unknown = null
    error: unknown = null
    onload: (() => void) | null = null
    onerror: (() => void) | null = null

    #read(blob: Blob, as: 'text' | 'arrayBuffer'): void {
      // Asynchronous, like the real reader: the caller attaches its handlers
      // after the read call returns.
      void (async () => {
        if (fail) {
          this.error = new Error('stub FileReader failure')
          this.onerror?.()
          return
        }
        const buffer = await Blob.prototype.arrayBuffer.call(blob)
        this.result = as === 'text' ? new TextDecoder().decode(buffer) : buffer
        this.onload?.()
      })()
    }

    readAsText(blob: Blob): void {
      this.#read(blob, 'text')
    }

    readAsArrayBuffer(blob: Blob): void {
      this.#read(blob, 'arrayBuffer')
    }
  }

  globals.FileReader = StubFileReader
  return () => {
    if (had) {
      globals.FileReader = previous
    } else {
      delete globals.FileReader
    }
  }
}
