# run-audit.ps1 - orchestrator. Runs all read-only sweeps, then prints the findings summary.
#
#   1. Copy .env.example to .env and fill it in
#   2. (Optional) az login   - if you are not using an app registration
#   3. ./run-audit.ps1
#
# Everything is read-only. Nothing is written to the audited environment.

param([switch]$SkipGraph, [switch]$SkipDataverse, [switch]$SkipAzure)

$here = $PSScriptRoot
Write-Host "D365 / Power Platform Security Audit (read-only)" -ForegroundColor Green
Write-Host "Output goes to ./output (git-ignored). Nothing is changed in your tenant.`n"

if (-not $SkipGraph)     { & (Join-Path $here 'scripts/graph-sweep.ps1') }
if (-not $SkipDataverse) { & (Join-Path $here 'scripts/dataverse-sweep.ps1') }
if (-not $SkipAzure)     { & (Join-Path $here 'scripts/azure-sweep.ps1') }

& (Join-Path $here 'scripts/analyze.ps1')

Write-Host "`nDone. Raw evidence: ./output/*.json   Summary: ./output/FINDINGS-summary.json" -ForegroundColor Green
Write-Host "Reminder: if you used a client secret, rotate it now and never commit .env." -ForegroundColor Yellow
