/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Portable `Blob` reads.
 *
 * A `Blob` in a browser or in Node implements `text()` and `arrayBuffer()`, so
 * reading one is a single await. React Native's built-in `Blob` implements
 * neither -- calling them throws `TypeError: undefined is not a function` --
 * but RN does provide a global `FileReader` with `readAsText` /
 * `readAsArrayBuffer`, which reads its own `Blob` type. That asymmetry is
 * invisible in tests (they run on Node, where the native methods exist) and in
 * the browser wallet, so every `Blob` read in this library goes through the two
 * helpers here rather than calling the native methods directly.
 *
 * Each helper prefers the native method when it is present and falls back to a
 * `FileReader` otherwise. The fallback is Promise-wrapped by hand because
 * `FileReader` is event-based: it resolves on `onload` with `reader.result` and
 * rejects on `onerror` with the reader's own error.
 */

/**
 * The subset of the event-based `FileReader` surface the fallback drives,
 * declared structurally so the helpers do not depend on the DOM `FileReader`
 * constructor's exact type (React Native's implementation is its own class).
 */
interface FileReaderLike {
  result: unknown
  error: unknown
  onload: (() => void) | null
  onerror: (() => void) | null
  readAsText(blob: Blob): void
  readAsArrayBuffer(blob: Blob): void
}

/**
 * The global `FileReader` constructor, or `undefined` where the runtime has
 * none (plain Node, which needs no fallback since its `Blob` is complete).
 *
 * @returns {(new () => FileReaderLike) | undefined}
 */
function fileReaderConstructor(): (new () => FileReaderLike) | undefined {
  const ctor = (globalThis as { FileReader?: unknown }).FileReader
  return typeof ctor === 'function'
    ? (ctor as new () => FileReaderLike)
    : undefined
}

/**
 * Runs one `FileReader` read to completion as a Promise. The reader is created
 * and its handlers attached before the read is started, so a synchronously
 * completing implementation cannot fire before anything is listening.
 *
 * @param options {object}
 * @param options.blob {Blob}                           the blob to read
 * @param options.read {Function}                       starts the read on the
 *   reader (`readAsText` or `readAsArrayBuffer`)
 * @param options.what {string}                         named in the error when
 *   the read fails or yields an unusable `result`
 * @returns {Promise<unknown>}   the reader's `result`
 */
async function readWithFileReader({
  blob,
  read,
  what
}: {
  blob: Blob
  read: (reader: FileReaderLike, blob: Blob) => void
  what: string
}): Promise<unknown> {
  const FileReaderCtor = fileReaderConstructor()
  if (FileReaderCtor === undefined) {
    throw new TypeError(
      `Cannot read ${what} from a Blob: this Blob implements neither the ` +
        'native read methods nor is a global FileReader available.'
    )
  }
  return await new Promise<unknown>((resolve, reject) => {
    const reader = new FileReaderCtor()
    reader.onload = () => {
      resolve(reader.result)
    }
    reader.onerror = () => {
      reject(
        reader.error instanceof Error
          ? reader.error
          : new Error(`Failed to read ${what} from a Blob.`)
      )
    }
    read(reader, blob)
  })
}

/**
 * A blob's contents as text, decoded as UTF-8.
 *
 * @param blob {Blob}
 * @returns {Promise<string>}
 */
export async function blobText(blob: Blob): Promise<string> {
  if (typeof blob.text === 'function') {
    return await blob.text()
  }
  const result = await readWithFileReader({
    blob,
    read: (reader, target) => {
      reader.readAsText(target)
    },
    what: 'text'
  })
  if (typeof result !== 'string') {
    throw new TypeError('FileReader.readAsText did not yield a string.')
  }
  return result
}

/**
 * A blob's contents as bytes.
 *
 * @param blob {Blob}
 * @returns {Promise<Uint8Array>}
 */
export async function blobBytes(blob: Blob): Promise<Uint8Array> {
  if (typeof blob.arrayBuffer === 'function') {
    return new Uint8Array(await blob.arrayBuffer())
  }
  const result = await readWithFileReader({
    blob,
    read: (reader, target) => {
      reader.readAsArrayBuffer(target)
    },
    what: 'bytes'
  })
  // RN's reader yields an ArrayBuffer; tolerate a typed-array result too,
  // since some polyfills hand back a view rather than the buffer itself.
  if (result instanceof ArrayBuffer) {
    return new Uint8Array(result)
  }
  if (ArrayBuffer.isView(result)) {
    return new Uint8Array(
      result.buffer as ArrayBuffer,
      result.byteOffset,
      result.byteLength
    )
  }
  throw new TypeError(
    'FileReader.readAsArrayBuffer did not yield an ArrayBuffer.'
  )
}
