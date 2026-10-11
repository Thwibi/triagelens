import { expect, test } from '@playwright/test'

import { expectAlert, importAttackBundle, ingestAndDetect } from './helpers'

// Spec 09 section 7, Scenario C: Windows intrusion chain (Security + Sysmon).
// The synthetic XML fixtures carry the chain: an 11-account password spray and
// a successful logon from 198.51.100.77, an encoded-PowerShell downloader, a
// Run-key persistence write, a scheduled task and an audit-log clear.
test.beforeAll(async () => {
  await importAttackBundle()
})

test('Scenario C: Windows intrusion chain is detected across EVTX sources', async ({ page }) => {
  const caseId = await ingestAndDetect(page, 'E2E Scenario C', [
    'evtx/security_logons.xml',
    'evtx/sysmon_attack.xml',
  ])

  await expectAlert(page, caseId, 'Password Spraying - Many Accounts From One Source')
  await expect(
    page.getByRole('button', { name: 'Suspicious Encoded PowerShell Command Line' }).first(),
  ).toBeVisible()
  await expect(
    page.getByRole('button', { name: 'New RUN Key Pointing to Suspicious Folder' }).first(),
  ).toBeVisible()
  await expect(
    page.getByRole('button', { name: 'Suspicious Scheduled Task Creation' }).first(),
  ).toBeVisible()
  await expect(
    page.getByRole('button', { name: 'Security Eventlog Cleared' }).first(),
  ).toBeVisible()

  await page.goto(`/cases/${encodeURIComponent(caseId)}/mitre`)
  await expect(page.getByRole('region', { name: 'Credential Access' })).toBeVisible()
  await expect(page.getByRole('link', { name: /T1110/ }).first()).toBeVisible()
  await expect(page.getByRole('link', { name: /T1059/ }).first()).toBeVisible()
  await expect(page.getByRole('link', { name: /T1547/ }).first()).toBeVisible()
  await expect(page.getByRole('link', { name: /T1053/ }).first()).toBeVisible()
  await expect(page.getByRole('link', { name: /T1070/ }).first()).toBeVisible()

  await page.goto(`/cases/${encodeURIComponent(caseId)}/iocs`)
  await expect(page.getByText('198.51.100.77').first()).toBeVisible()
  await expect(page.getByText('192.0.2.66').first()).toBeVisible()

  // The downloader domain is a documentation domain, so spec 05 section 5
  // allowlists example.org: it is extracted (as spec 09 section 7 expects) but
  // hidden until allowlisted indicators are shown (URL filter `allowlisted=1`).
  await page.goto(`/cases/${encodeURIComponent(caseId)}/iocs?allowlisted=1`)
  await expect(page.getByText('malicious-update.example.org').first()).toBeVisible()
  await expect(page.getByText('http://malicious-update.example.org/a.ps1').first()).toBeVisible()
})
