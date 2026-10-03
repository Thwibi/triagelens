<#
.SYNOPSIS
    Start TriageLens on Windows.

.DESCRIPTION
    Serves the API and the built frontend from a single process on
    127.0.0.1:8787. Pass -Dev to run the Vite dev server instead, with the API
    proxied.

.EXAMPLE
    .\scripts\run.ps1
    .\scripts\run.ps1 -Dev
#>
[CmdletBinding()]
param(
    [switch]$Dev
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    Write-Error "No virtual environment at $root\.venv. Run: make install"
    exit 1
}

if ($Dev) {
    $modules = Join-Path $root 'frontend\node_modules'
    if (-not (Test-Path -LiteralPath $modules)) {
        Write-Error "Frontend dependencies missing. Run: make frontend-install"
        exit 1
    }
    Push-Location (Join-Path $root 'frontend')
    try { npm run dev } finally { Pop-Location }
    exit $LASTEXITCODE
}

$shell = Join-Path $root 'backend\app\static\index.html'
if (-not (Test-Path -LiteralPath $shell)) {
    Write-Error "Frontend not built. Run: make build   (or use -Dev)"
    exit 1
}

Push-Location (Join-Path $root 'backend')
try { & $python -m app.main } finally { Pop-Location }
exit $LASTEXITCODE