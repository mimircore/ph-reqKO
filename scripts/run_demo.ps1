# ph-reqKO demo launcher (Windows PowerShell).
#
# NOTE: the tokens below are DEMO-ONLY values for a local, throwaway run.
# Do not reuse them in any real deployment.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1
# The server runs in this terminal; stop it with Ctrl+C.

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot   # repo root (scripts\..)
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Error "Virtual environment not found: $python - create it first (see README, Development section)."
    exit 1
}

# Demo blocklist next to the repo root, created on first run
$blocklist = Join-Path $root "blocklist.txt"
if (-not (Test-Path $blocklist)) {
    @("ads.example.com", "doubleclick.net", "tracker.example.net") |
        Set-Content -Path $blocklist -Encoding ascii
    Write-Host "Created demo blocklist: $blocklist"
}

# Demo-only tokens (see the note at the top of this file)
$env:REQKO_ADMIN_TOKEN = "admin-secret-123"
$env:REQKO_READ_TOKEN  = "read-secret-456"
$env:REQKO_DNS_HOST = "127.0.0.1"
$env:REQKO_DNS_PORT = "5454"
$env:REQKO_DB_PATH  = Join-Path $root "reqko.db"
$env:REQKO_BLOCKLIST_FILES = $blocklist

Write-Host ""
Write-Host "ph-reqKO demo server starting (Ctrl+C to stop)"
Write-Host "  Panel:      http://127.0.0.1:8080/panel  (enter the read token)"
Write-Host "  Read token:  read-secret-456"
Write-Host "  Queries (second terminal): .\.venv\Scripts\python.exe scripts\send_queries.py"
Write-Host ""

& $python -m reqko
