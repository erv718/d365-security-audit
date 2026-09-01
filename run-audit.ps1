# run-audit.ps1 - orchestrator. Runs all read-only sweeps, then prints the summary.
#
#   1. Copy .env.example to .env and fill it in (see docs/permissions.md)
#   2. (Optional) az login   - if you are not using an app registration
#   3. ./run-audit.ps1
#
# Everything is read-only. Nothing is written to the audited environment.

param([switch]$SkipGraph, [switch]$SkipDataverse, [switch]$SkipAzure, [switch]$SkipPowerPlatform)

$here = $PSScriptRoot
function Step($rel) {
    $p = Join-Path $here $rel
    if (Test-Path $p) { & $p } else { Write-Warning "skipped (not present): $rel" }
}

Write-Host "D365 / Power Platform Security Audit (read-only)" -ForegroundColor Green
Write-Host "Output goes to ./output (git-ignored). Nothing is changed in your tenant.`n"

if (-not $SkipGraph) {
    Step 'scripts/graph-sweep.ps1'
    Step 'scripts/graph-identity-plus.ps1'
}
if (-not $SkipPowerPlatform) {
    # discovers environments -> output/pp-environment-urls.json (used by dataverse-plus)
    Step 'scripts/powerplatform-sweep.ps1'
}
if (-not $SkipDataverse) {
    Step 'scripts/dataverse-sweep.ps1'
    Step 'scripts/dataverse-plus.ps1'
}
if (-not $SkipAzure) {
    Step 'scripts/azure-sweep.ps1'
    Step 'scripts/azure-plus.ps1'
}

Step 'scripts/analyze.ps1'
# TODO: the 29-check assessment report mapper. See docs/full-assessment-roadmap.md
# Step 'scripts/assessment-report.ps1'

Write-Host "`nDone. Raw evidence: ./output/*.json" -ForegroundColor Green
Write-Host "Check output/ for any *-ERROR.json (endpoints that need a tweak in this branch)." -ForegroundColor Yellow
Write-Host "Reminder: if you used a client secret, rotate it now and never commit .env." -ForegroundColor Yellow
