import { test, expect } from '@playwright/test'

/**
 * Browser smoke test: confirms the bundle loads in a real browser and that the
 * lazy navigational handles build synchronously (no network, no key material).
 */
test('WasClient builds lazy handles in the browser', async ({ page }) => {
  await page.goto('/test/index.html')
  const result = await page.evaluate(async () => {
    const { WasClient } = await import('/src/index.ts')
    // The constructor only stores serverUrl + zcapClient; a minimal stub is
    // enough to exercise synchronous, network-free handle construction.
    const stubZcapClient = {
      invocationSigner: { id: 'did:example:1#key-1' }
    } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient']
    const was = new WasClient({
      serverUrl: 'https://was.example',
      zcapClient: stubZcapClient
    })
    const resource = was.space('s').collection('c').resource('r')
    return {
      spaceId: resource.spaceId,
      collectionId: resource.collectionId,
      resourceId: resource.id,
      controllerDid: was.controllerDid
    }
  })
  expect(result).toEqual({
    spaceId: 's',
    collectionId: 'c',
    resourceId: 'r',
    controllerDid: 'did:example:1'
  })
})
