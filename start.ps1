# Spectra local launcher (optional).
#
# Starts the backend API (http://127.0.0.1:8787) and the Vite console
# (http://localhost:5173) on this machine, and stops the backend when you
# press Ctrl+C. It only *checks* the environment and prints what it does -
# it never installs or mutates anything. The same thing by hand:
#
#     cd backend  ; python -m spectra.cli serve --port 8787
#     cd frontend ; npm run dev
#
# Usage:
#     .\start.ps1             start both
#     .\start.ps1 -Check      verify toolchain + deps + port, start nothing
#     .\start.ps1 -Port 8899  API on another port

[CmdletBinding()]
param(
    [int]$Port = 8787,
    [switch]$Check
)

function Step($msg) { Write-Host "[spectra] $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "[spectra] $msg" -ForegroundColor Yellow }

$root = $PSScriptRoot
$backend = Join-Path $root 'backend'
$frontend = Join-Path $root 'frontend'
$failed = $false

# -- 1. Python + backend dependencies -------------------------------------
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Warn 'python not found on PATH (Spectra needs Python >= 3.11)'
    $failed = $true
} else {
    $pyver = & python -c "import sys; print('%d.%d.%d' % sys.version_info[:3])"
    Step "Python $pyver"
    & python -c 'import fastapi, scapy, sklearn, numpy' *> $null
    if ($LASTEXITCODE -ne 0) {
        Warn 'backend dependencies missing - run:  cd backend; pip install -r requirements.txt'
        $failed = $true
    }
}

# -- 2. Node + frontend dependencies --------------------------------------
$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) {
    Warn 'npm not found on PATH (Vite needs Node ^20.19 or >= 22.12)'
    $failed = $true
} else {
    $nodever = & node --version
    Step "Node $nodever"
    if (-not (Test-Path (Join-Path $frontend 'node_modules'))) {
        Warn 'frontend dependencies missing - run:  cd frontend; npm install'
        $failed = $true
    }
}

# -- 3. port free ----------------------------------------------------------
$listener = $null
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
}
if ($listener) {
    Warn "port $Port is already in use - stop the other process or pass -Port"
    $failed = $true
}

if ($Check) {
    if ($failed) { Write-Host '[spectra] check FAILED' -ForegroundColor Red; exit 1 }
    Step 'check OK - ready to run .\start.ps1'
    exit 0
}
if ($failed) {
    Write-Host '[spectra] fix the items above, then run .\start.ps1 again (or .\start.ps1 -Check)' -ForegroundColor Red
    exit 1
}

# -- run: backend, then frontend in this console ---------------------------
Step "backend  -> http://127.0.0.1:$Port  (first run bootstraps the admin account)"
Step 'frontend -> http://localhost:5173   (open this URL, not 127.0.0.1)'
Write-Host '[spectra] Ctrl+C stops both; use an admin account to import a capture and train.'
$backendProc = $null
try {
    $backendProc = Start-Process -FilePath 'python' `
        -ArgumentList @('-m', 'spectra.cli', 'serve', '--port', $Port) `
        -WorkingDirectory $backend -PassThru -NoNewWindow
} catch {
    Warn "could not start the backend: $($_.Exception.Message)"
    exit 1
}

Start-Sleep -Seconds 2
if ($backendProc.HasExited) {
    Warn "backend exited early (exit code $($backendProc.ExitCode))"
    exit 1
}

Step 'starting the frontend - Ctrl+C here also shuts the backend down'
Push-Location $frontend
try {
    & npm run dev
} finally {
    Pop-Location
    if ($backendProc -and -not $backendProc.HasExited) {
        Step "stopping backend (pid $($backendProc.Id))"
        Stop-Process -Id $backendProc.Id -Force -ErrorAction SilentlyContinue
    }
}
