// Boots the TriageLens API on an isolated temporary data directory and serves
// the pre-built frontend from the same origin, for the Playwright suite (spec
// 09 section 7). Playwright starts this via the `webServer` block and tears it
// down when the run finishes.
import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const frontendDir = path.resolve(here, '..')
const root = path.resolve(frontendDir, '..')
const backendDir = path.join(root, 'backend')

const isWindows = process.platform === 'win32'
const python = isWindows
  ? path.join(root, '.venv', 'Scripts', 'python.exe')
  : path.join(root, '.venv', 'bin', 'python')

if (!existsSync(python)) {
  console.error('[e2e] no virtualenv interpreter at ' + python + "; run 'make install' first")
  process.exit(1)
}
if (!existsSync(path.join(backendDir, 'app', 'static', 'index.html'))) {
  console.error('[e2e] frontend is not built; run `npm run build` (or `make e2e`) first')
  process.exit(1)
}

const port = process.env.TRIAGELENS_E2E_PORT ?? '8799'
const dataDir = mkdtempSync(path.join(tmpdir(), 'triagelens-e2e-'))

const env = {
  ...process.env,
  TRIAGELENS_SERVER__HOST: '127.0.0.1',
  TRIAGELENS_SERVER__PORT: port,
  TRIAGELENS_STORAGE__DATA_DIR: dataDir,
}

console.error(`[e2e] serving http://127.0.0.1:${port} with data dir ${dataDir}`)

const child = spawn(python, ['-m', 'app.main'], { cwd: backendDir, env, stdio: 'inherit' })

const shutdown = () => {
  if (!child.killed) {
    child.kill()
  }
}

process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
process.on('exit', shutdown)
child.on('exit', (code) => {
  process.exit(code ?? 0)
})
