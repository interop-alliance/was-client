/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Minimal ambient declarations for the in-process WAS test server. The
 * `was-teaching-server` package ships compiled JS without `.d.ts`, so these
 * declarations give the type-checker just enough to wire up the integration
 * harness. The real implementation is loaded by Vitest at runtime.
 */
declare module 'was-teaching-server/dist/server.js' {
  interface TestApp {
    listen(options: { port: number }): Promise<string>
    close(): Promise<void>
  }
  export function createApp(options?: {
    serverUrl?: string
    backend?: unknown
  }): TestApp
}

declare module 'was-teaching-server/dist/backends/filesystem.js' {
  export class FileSystemBackend {
    constructor(options: { dataDir: string })
  }
}
