import { expect, test } from '@playwright/test'
import { readFile } from 'node:fs/promises'

import { expectAlert, importAttackBundle, ingestAndDetect } from './helpers'

// Spec 09 section 7, Scenario A: SSH brute force then successful login.
test.beforeAll(async () => {
  await importAttackBundle()
})

test('Scenario A: SSH brute force produces the expected alerts, IOCs and ATT&CK cells', async ({
  page,
}) => {
  const caseId = await ingestAndDetect(page, 'E2E Scenario A', ['linux/auth.log'])

  await expectAlert(page, caseId, 'SSH Brute Force From Single Source')
  await expect(
    page.getByRole('button', { name: 'SSH Successful Login After Failures From Same Source' }).first(),
  ).toBeVisible()
  await expect(
    page.getByRole('button', { name: 'Local User Account Created (Linux)' }).first(),
  ).toBeVisible()

  await page.getByRole('button', { name: 'SSH Brute Force From Single Source' }).first().click()
  const drawer = page.getByRole('dialog', { name: 'Alert detail' })
  await expect(drawer).toBeVisible()
  await expect(drawer.getByRole('heading', { name: 'ATT&CK' })).toBeVisible()
  await expect(drawer.getByRole('link', { name: /T1110/ }).first()).toBeVisible()
  await expect(drawer.getByText(/185\.220\.101\.45/).first()).toBeVisible()
  await drawer.getByRole('button', { name: 'Close alert' }).click()

  await page.goto(`/cases/${encodeURIComponent(caseId)}/mitre`)
  await expect(page.getByRole('region', { name: 'Credential Access' })).toBeVisible()
  await expect(page.getByRole('link', { name: /T1110/ }).first()).toBeVisible()

  await page.goto(`/cases/${encodeURIComponent(caseId)}/iocs`)
  await expect(page.getByRole('heading', { name: 'Indicators' })).toBeVisible()
  await expect(page.getByText('185.220.101.45').first()).toBeVisible()

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    (async () => {
      await page.getByLabel('Export').selectOption('csv')
      await page.getByRole('button', { name: 'Export' }).click()
    })(),
  ])
  const downloadPath = await download.path()
  const csv = await readFile(downloadPath, 'utf8')
  expect(csv).toContain('185.220.101.45')
})
