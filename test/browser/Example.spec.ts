import { test, expect } from '@playwright/test'

test('Example class works in browser', async ({ page }) => {
  await page.goto('/test/index.html')
  const result = await page.evaluate(async () => {
    const { Example } = await import('/src/index.ts')
    return new Example().hello()
  })
  expect(result).toBe('world')
})
