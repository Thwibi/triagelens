import { expect, test } from '@playwright/test'

import { expectAlert, importAttackBundle, ingestAndDetect } from './helpers'

// Spec 09 section 7, Scenario B: web attack against Apache combined logs.
test.beforeAll(async () => {
  await importAttackBundle()
})

test('Scenario B: web attack produces the expected alerts and IOCs', async ({ page }) => {
  const caseId = await ingestAndDetect(page, 'E2E Scenario B', ['web/access_combined.log'])

  await expectAlert(page, caseId, 'Web SQL Injection Patterns')
  await expect(
    page.getByRole('button', { name: 'Web Path Traversal Attempt' }).first(),
  ).toBeVisible()
  await expect(
    page.getByRole('button', { name: 'Known Scanner or Attack Tool User-Agent' }).first(),
  ).toBeVisible()
  await expect(
    page.getByRole('button', { name: 'Web Shell-Like Request (script upload paths)' }).first(),
  ).toBeVisible()

  await page.getByRole('button', { name: 'Web SQL Injection Patterns' }).first().click()
  const drawer = page.getByRole('dialog', { name: 'Alert detail' })
  await expect(drawer).toBeVisible()
  await expect(drawer.getByRole('heading', { name: 'ATT&CK' })).toBeVisible()
  await expect(drawer.getByText(/45\.155\.205\.233/).first()).toBeVisible()
  await drawer.getByRole('button', { name: 'Close alert' }).click()

  await page.goto(`/cases/${encodeURIComponent(caseId)}/iocs`)
  await expect(page.getByRole('heading', { name: 'Indicators' })).toBeVisible()
  await expect(page.getByText('45.155.205.233').first()).toBeVisible()
})
