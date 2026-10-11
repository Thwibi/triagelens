import { expect, type Page, request as apiRequest } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

/** Repository root (two levels above frontend/e2e). */
export const REPO_ROOT = resolve(here, '..', '..')
/** Committed synthetic fixtures (spec 09 section 2). */
export const FIXTURES = join(REPO_ROOT, 'backend', 'tests', 'fixtures')

const E2E_PORT = process.env.TRIAGELENS_E2E_PORT ?? '8799'
const E2E_BASE_URL = `http://127.0.0.1:${E2E_PORT}`

/**
 * Import the committed ATT&CK fixture bundle so the offline suite can exercise
 * MITRE mapping. The production bundle is fetched by `scripts/update_attack.py`
 * and is not committed (spec 04 section 7.1), so the E2E run seeds the tables
 * from `tests/fixtures/enterprise-attack-e2e.json` instead: a superset of the
 * backend's `enterprise-attack-mini.json` that also carries the techniques the
 * Scenario A/B/C detections reference (T1547.001, T1053.005, T1190, ...).
 * Idempotent.
 */
export async function importAttackBundle(): Promise<void> {
  const buffer = await readFile(join(FIXTURES, 'enterprise-attack-e2e.json'))
  const context = await apiRequest.newContext({ baseURL: E2E_BASE_URL })
  try {
    const response = await context.post('/api/settings/attack/import', {
      multipart: {
        bundle: {
          name: 'enterprise-attack-e2e.json',
          mimeType: 'application/json',
          buffer,
        },
      },
    })
    if (!response.ok()) {
      throw new Error(`ATT&CK import failed: ${response.status()} ${await response.text()}`)
    }
  } finally {
    await context.dispose()
  }
}

interface Job {
  readonly kind: string
  readonly status: string
}

interface JobList {
  readonly items: readonly Job[]
}

/** Create a case through the real UI and return its id. */
export async function createCase(page: Page, name: string): Promise<string> {
  await page.goto('/')
  await page.getByRole('button', { name: 'New case' }).first().click()
  await page.getByLabel('Name').fill(name)
  await page.getByRole('button', { name: 'Create case' }).click()
  await page.waitForURL(/\/cases\/[^/]+$/)
  await expect(page.getByRole('heading', { name })).toBeVisible()
  const match = /\/cases\/([^/]+)$/.exec(new URL(page.url()).pathname)
  const caseId = match?.[1]
  if (caseId === undefined) {
    throw new Error(`could not read the case id from ${page.url()}`)
  }
  return decodeURIComponent(caseId)
}

/** Poll the jobs API until a job of `kind` reaches `status` (default done). */
export async function waitForJob(
  page: Page,
  caseId: string,
  kind: string,
  status = 'done',
): Promise<void> {
  await expect
    .poll(
      async () => {
        const response = await page.request.get(`/api/cases/${caseId}/jobs`)
        const body = (await response.json()) as JobList
        return body.items.filter((job) => job.kind === kind && job.status === status).length
      },
      { timeout: 120000, message: `waiting for a ${kind} job to finish` },
    )
    .toBeGreaterThan(0)
}

/** Upload absolute file paths through the dropzone and wait for ingest to finish. */
export async function uploadFiles(
  page: Page,
  caseId: string,
  absolutePaths: readonly string[],
): Promise<void> {
  await page.goto(`/cases/${encodeURIComponent(caseId)}/sources`)
  await page.getByLabel('Choose files to ingest').setInputFiles([...absolutePaths])
  await expect(page.getByText(/Queued \d+ file/)).toBeVisible()
  await waitForJob(page, caseId, 'ingest')
}

/** Upload fixture files (relative to the fixtures directory) and wait for ingest. */
export async function uploadFixtures(
  page: Page,
  caseId: string,
  relativePaths: readonly string[],
): Promise<void> {
  await uploadFiles(
    page,
    caseId,
    relativePaths.map((relative) => join(FIXTURES, relative)),
  )
}

/** Click "Run detection" at the given profile and wait for it to finish. */
export async function runDetection(
  page: Page,
  caseId: string,
  profile: 'fast' | 'standard' | 'full' = 'full',
): Promise<void> {
  await page.getByLabel('Profile').selectOption(profile)
  await page.getByRole('button', { name: 'Run detection' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Detection queued.' })).toBeVisible()
  await waitForJob(page, caseId, 'detect')
}

/** Create a case, ingest the fixtures and run detection. Returns the case id. */
export async function ingestAndDetect(
  page: Page,
  name: string,
  relativePaths: readonly string[],
  profile: 'fast' | 'standard' | 'full' = 'full',
): Promise<string> {
  const caseId = await createCase(page, name)
  await uploadFixtures(page, caseId, relativePaths)
  await runDetection(page, caseId, profile)
  return caseId
}

/** Open the Alerts screen and assert the named alert is present. */
export async function expectAlert(page: Page, caseId: string, title: string): Promise<void> {
  await page.goto(`/cases/${encodeURIComponent(caseId)}/alerts`)
  await expect(page.getByRole('heading', { name: 'Alerts' })).toBeVisible()
  await expect(page.getByRole('button', { name: title }).first()).toBeVisible()
}
