# Run TriageLens through docker compose (PowerShell).
#
#   .\scripts\compose.ps1 up --build     build and start on 127.0.0.1:8787
#   .\scripts\compose.ps1 down           stop, keep the data volume
#   .\scripts\compose.ps1 --profile pdf up triagelens-pdf
#   .\scripts\compose.ps1 logs -f        follow logs
#
# The container binds 0.0.0.0 so the published port can reach it, and the app
# refuses a non-loopback bind without an auth token. Rather than making you
# export one, this wrapper generates a token into docker/.env on first use and
# reuses it afterwards, so the token is stable across restarts. The file is
# gitignored; it is a local secret.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$envFile = Join-Path $root 'docker\.env'

if (-not (Test-Path -LiteralPath $envFile)) {
    # RandomNumberGenerator.Fill is .NET Core only; Windows PowerShell 5.1 needs
    # the older instance API.
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    Set-Content -LiteralPath $envFile -Value "TRIAGELENS_TOKEN=$token" -Encoding utf8 -NoNewline
    Write-Host 'generated a token in docker\.env'
}

# docker compose writes normal progress to stderr, which Windows PowerShell
# surfaces as NativeCommandError records. Capture both streams and re-emit them as
# plain text so real output is readable, and rely on the exit code for failure.
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $output = & docker compose --env-file $envFile -f (Join-Path $root 'docker\compose.yaml') @args 2>&1
    $code = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousPreference
}
foreach ($line in $output) {
    Write-Host $line.ToString()
}
exit $code