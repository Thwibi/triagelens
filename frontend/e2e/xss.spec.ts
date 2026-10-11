import { expect, test } from '@playwright/test'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createCase, runDetection, uploadFiles } from './helpers'

const SCRIPT_PAYLOAD = '<script>alert(1)</script>'
const IMG_PAYLOAD = '"><img src=x onerror=alert(1)>'

function accessLine(index: number, requestPath: string): string {
  const second = String(index).padStart(2, '0')
  return `192.0.2.60 - - [01/Mar/2026:12:00:${second} +0000] "GET ${requestPath} HTTP/1.1" 200 128 "-" "Mozilla/5.0"`
}

// Spec 09 section 9, S-02: hostile log content must render as inert text.
test('S-02: HTML/script payloads in logs render as inert text, never a dialog', async ({
  page,
}) => {
  let dialogFired = false
  page.on('dialog', async (dialog) => {
    dialogFired = true
    await dialog.dismiss()
  })

  const lines: string[] = []
  for (let index = 0; index < 12; index += 1) {
    lines.push(accessLine(index, `/product.php?id=${String(index)}`))
  }
  lines.push(accessLine(20, `/${SCRIPT_PAYLOAD}`))
  lines.push(accessLine(21, `/x?q=${IMG_PAYLOAD}`))

  const dir = mkdtempSync(join(tmpdir(), 'triagelens-xss-'))
  const file = join(dir, 'access_xss.log')
  writeFileSync(file, `${lines.join('\n')}\n`, 'utf8')

  const caseId = await createCase(page, 'E2E XSS')
  await uploadFiles(page, caseId, [file])
  await runDetection(page, caseId, 'fast')

  await page.goto(`/cases/${encodeURIComponent(caseId)}/events`)
  await expect(page.getByLabel('Search events')).toBeVisible()

  await page.locator('button').filter({ hasText: 'apache_access' }).first().click()
  const raw = page.getByLabel('Raw event (highlighted)')
  await expect(raw).toBeVisible()
  await expect(raw).toContainText('alert(1)')
  await expect(page.locator('script', { hasText: 'alert(1)' })).toHaveCount(0)
  expect(dialogFired).toBe(false)
})
