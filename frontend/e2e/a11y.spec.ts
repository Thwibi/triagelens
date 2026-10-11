import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Locator, type Page } from '@playwright/test'

import { ingestAndDetect, importAttackBundle } from './helpers'

// Spec 07 requires accessibility on the main screens (Lighthouse >= 95 in the
// spec; axe-core WCAG 2.1 A/AA is the deterministic, offline equivalent). A
// serious or critical violation fails the suite; minor/moderate findings are
// reported by axe but not enforced here.
interface Screen {
  readonly name: string
  readonly path: string
  /** Something that proves the screen's data finished loading. */
  readonly ready: (page: Page) => Locator
}

const heading = (page: Page): Locator => page.locator('main h1').first()

const screens: readonly Screen[] = [
  { name: 'cases', path: '/', ready: heading },
  { name: 'status', path: '/status', ready: heading },
  {
    name: 'overview',
    path: '/cases/{id}/overview',
    ready: heading,
  },
  {
    name: 'sources',
    path: '/cases/{id}/sources',
    ready: heading,
  },
  {
    name: 'events',
    path: '/cases/{id}/events',
    ready: (page) => page.getByLabel('Search events'),
  },
  {
    name: 'timeline',
    path: '/cases/{id}/timeline',
    ready: heading,
  },
  {
    name: 'alerts',
    path: '/cases/{id}/alerts',
    ready: heading,
  },
  {
    name: 'iocs',
    path: '/cases/{id}/iocs',
    ready: heading,
  },
  {
    name: 'mitre',
    path: '/cases/{id}/mitre',
    ready: heading,
  },
  {
    name: 'entities',
    path: '/cases/{id}/entities',
    ready: heading,
  },
  {
    name: 'rules',
    path: '/cases/{id}/rules',
    ready: heading,
  },
  {
    name: 'reports',
    path: '/cases/{id}/reports',
    ready: heading,
  },
  {
    name: 'settings',
    path: '/cases/{id}/settings',
    ready: heading,
  },
]

async function seriousViolations(page: Page): Promise<string[]> {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze()
  return results.violations
    .filter((violation) => violation.impact === 'serious' || violation.impact === 'critical')
    .map((violation) => {
      const targets = violation.nodes
        .slice(0, 10)
        .map((node) => node.target.join(' '))
        .join(' | ')
      return `${violation.id} (${violation.impact}): ${violation.help} — ${violation.nodes.length} node(s): ${targets}`
    })
}

test.beforeAll(async () => {
  await importAttackBundle()
})

test('the main screens have no serious or critical accessibility violations', async ({ page }) => {
  const caseId = await ingestAndDetect(page, 'E2E a11y', ['linux/auth.log'])
  const encoded = encodeURIComponent(caseId)

  const problems: string[] = []
  for (const screen of screens) {
    const path = screen.path.replace('{id}', encoded)
    await page.goto(path)
    await expect(screen.ready(page)).toBeVisible()
    for (const violation of await seriousViolations(page)) {
      problems.push(`${screen.name}: ${violation}`)
    }
  }
  expect(problems, 'serious or critical accessibility violations').toEqual([])
})
