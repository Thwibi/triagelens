import { expect, test } from '@playwright/test'
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { createCase } from './helpers'

// Spec 09 section 8 requires the Alerts screen to reach first meaningful paint
// with 1,000 alerts in under a second. The list is virtualized and paged, so the
// screen paints one page (ALERT_PAGE_SIZE rows) while showing the full total;
// this measures time from navigation start to that table appearing. The result
// is written to an artefact that `scripts/run_perf.py --e2e` merges into
// `docs/perf-e2e-results.md`, so the target is recorded, not just asserted.

const here = dirname(fileURLToPath(import.meta.url))
const ARTIFACT = join(here, '.artifacts', 'ui-first-paint.json')

/** Rows per page fetched by the Alerts screen (see `alertFilters.ts`). */
const ALERT_PAGE_SIZE = 50
/** Alerts the case reports, so the screen renders under the spec's 1,000. */
const ALERT_TOTAL = 1000
/** The spec's budget for this target, in milliseconds. */
const LIMIT_MS = 1000

declare global {
  interface Window {
    __alertsPaintMs?: number
  }
}

interface SyntheticTechnique {
  readonly id: string
  readonly name: string
  readonly tactics: readonly string[]
  readonly source: 'tag'
}

interface SyntheticAlert {
  readonly id: string
  readonly rule_title: string
  readonly level: string
  readonly score: number
  readonly status: string
  readonly host: string
  readonly user_name: string
  readonly last_seen_ms: number
  readonly match_count: number
  readonly techniques: readonly SyntheticTechnique[]
}

function syntheticAlerts(count: number): SyntheticAlert[] {
  return Array.from({ length: count }, (_unused, index) => ({
    id: `perf-alert-${index}`,
    rule_title: `Synthetic detection rule ${index}`,
    level: 'high',
    score: 90 - (index % 40),
    status: 'new',
    host: `host-${index % 10}`,
    user_name: `user-${index % 7}`,
    last_seen_ms: 1_700_000_000_000 + index * 1000,
    match_count: index + 1,
    techniques: [
      { id: 'T1059.001', name: 'PowerShell', tactics: ['execution'], source: 'tag' },
    ],
  }))
}

test('the alerts screen first-paints 1,000 alerts within the spec budget', async ({ page }) => {
  const caseId = await createCase(page, 'E2E perf alerts')
  const encoded = encodeURIComponent(caseId)

  await page.route(`**/api/cases/${encoded}/alerts*`, (route) =>
    route.fulfill({ json: { items: syntheticAlerts(ALERT_PAGE_SIZE), total: ALERT_TOTAL } }),
  )

  // Record the first moment the alerts table enters the DOM, relative to the
  // navigation's time origin. The observer disconnects after the first hit.
  await page.addInitScript(() => {
    const mark = (): void => {
      const table = document.querySelector('[role="table"][aria-label="Alerts"]')
      if (table !== null && window.__alertsPaintMs === undefined) {
        window.__alertsPaintMs = performance.now()
      }
    }
    const observer = new MutationObserver(mark)
    observer.observe(document.documentElement, { childList: true, subtree: true })
  })

  await page.goto(`/cases/${encoded}/alerts`)
  await expect(page.getByRole('table', { name: 'Alerts' })).toBeVisible()
  await expect(page.getByRole('row').nth(1)).toBeVisible()

  const paintMs = Math.round(await page.evaluate(() => window.__alertsPaintMs ?? performance.now()))
  expect(paintMs, `first paint with ${ALERT_TOTAL} alerts`).toBeLessThan(LIMIT_MS)

  await mkdir(dirname(ARTIFACT), { recursive: true })
  await writeFile(
    ARTIFACT,
    `${JSON.stringify(
      {
        targets: [
          {
            name: 'ui.alerts_first_paint',
            value: paintMs,
            unit: 'ms',
            limit: LIMIT_MS,
            comparator: 'max',
            passed: paintMs < LIMIT_MS,
            note: `Playwright first paint of the Alerts table with ${ALERT_TOTAL} alerts (${ALERT_PAGE_SIZE} rows rendered)`,
          },
        ],
      },
      null,
      2,
    )}\n`,
    'utf8',
  )
})
