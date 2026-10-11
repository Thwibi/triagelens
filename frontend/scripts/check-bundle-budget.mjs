// Enforces the spec 07 bundle-size budget: the built frontend served by the API
// must stay under 1.5 MB gzipped. Run after `npm run build` (the `e2e` and
// `build` tasks do this); it reads whatever is in backend/app/static.
import { gzipSync } from 'node:zlib'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(here, '..', '..')
const staticDir = path.join(root, 'backend', 'app', 'static')

// 1.5 MB, decimal — the figure spec 07 states.
const BUDGET_BYTES = 1_500_000

if (!existsSync(staticDir)) {
  console.error(`[budget] no build at ${staticDir}; run \`npm run build\` first`)
  process.exit(1)
}

function walk(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry)
    if (statSync(full).isDirectory()) {
      out.push(...walk(full))
    } else {
      out.push(full)
    }
  }
  return out
}

const rows = walk(staticDir).map((file) => {
  const bytes = readFileSync(file)
  return {
    rel: path.relative(staticDir, file).split(path.sep).join('/'),
    gzip: gzipSync(bytes).length,
  }
})

rows.sort((a, b) => b.gzip - a.gzip)
const total = rows.reduce((sum, row) => sum + row.gzip, 0)

console.log('[budget] gzipped output under backend/app/static:')
for (const row of rows) {
  console.log(`  ${String(row.gzip).padStart(9)}  ${row.rel}`)
}
const pct = ((total / BUDGET_BYTES) * 100).toFixed(1)
console.log(`  ${String(total).padStart(9)}  TOTAL (${pct}% of ${BUDGET_BYTES} budget)`)

if (total > BUDGET_BYTES) {
  console.error(`[budget] FAIL: ${total} > ${BUDGET_BYTES} bytes gzipped`)
  process.exit(1)
}
console.log(`[budget] PASS: ${total} <= ${BUDGET_BYTES} bytes gzipped`)
