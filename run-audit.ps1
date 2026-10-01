# run-audit.ps1 - orchestrator. Runs all read-only sweeps, then prints the summary.
#
#   1. Copy .env.example to .env and fill in your read-only app (see docs/permissions.md)
#   2. ./run-audit.ps1
#
#   This tool authenticates ONLY as that read-only app registration. It never signs in
#   as a person, never opens a login prompt, and never shows a device code.
#
#   Scope (optional): -Scope <scope.json>, -Subscriptions, -ResourceGroups, -Environments,
#   -Types narrow what is read; blank everywhere means everything the app can read. The
#   preflight prints the effective scope, the report labels a scoped run as PARTIAL, and
#   -StrictScope stops the run when a selection is not visible to the app.
#
# Everything is read-only. Nothing is written to the audited environment.

param(
    [switch]$SkipGraph, [switch]$SkipDataverse, [switch]$SkipAzure, [switch]$SkipPowerPlatform,
    [string]$Scope,                 # path to a scope.json (default: ./scope.json when it exists)
    [string[]]$Subscriptions,       # subscription ids or display names
    [string[]]$ResourceGroups,      # resource group names (resource readers list per group)
    [string[]]$Environments,        # Dataverse environment URLs, ids or display names
    [string[]]$Types,               # resource readers: sql, synapse, keyvault, nsg, loganalytics, logicapps
    [switch]$StrictScope            # stop when a selected subscription, group or environment is not visible
)

$here = $PSScriptRoot
function Step($rel) {
    $p = Join-Path $here $rel
    if (Test-Path $p) { & $p } else { Write-Warning "skipped (not present): $rel" }
}

Write-Host "D365 / Power Platform Security Audit (read-only)" -ForegroundColor Green
Write-Host "Output goes to ./output (git-ignored). Nothing is changed in your tenant.`n"

# Scope parameters travel to the scripts as process variables for this run only; the previous
# values are restored at the end so an interactive session is left as it was.
if ($Scope -and (Test-Path $Scope)) { $Scope = (Resolve-Path $Scope).Path }
$scopeVars = @{
    SECAUDIT_SCOPE_FILE      = $Scope
    SECAUDIT_SUBSCRIPTIONS   = ($Subscriptions -join ',')
    SECAUDIT_RESOURCE_GROUPS = ($ResourceGroups -join ',')
    SECAUDIT_ENVIRONMENTS    = ($Environments -join ',')
    SECAUDIT_TYPES           = ($Types -join ',')
    SECAUDIT_STRICT_SCOPE    = $(if ($StrictScope) { '1' } else { '' })
}
$previous = @{}
foreach ($k in @($scopeVars.Keys)) {
    $previous[$k] = [Environment]::GetEnvironmentVariable($k)
    if ($scopeVars[$k]) { [Environment]::SetEnvironmentVariable($k, $scopeVars[$k]) }
}

try {
    # A *-ERROR.json diagnoses one run. Clear the previous run's (local files only) so a stale one
    # can never turn into a verdict now; any pull that fails again this run writes its own.
    $outDir = Join-Path $here 'output'
    if (Test-Path $outDir) { Get-ChildItem $outDir -Filter '*-ERROR.json' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue }

    # Preflight: verify the read-only app registration (the ONLY way this tool
    # authenticates), print the exact fix for anything that is not set up yet, and
    # write output/scope-effective.json (what this run covers).
    $ok = & (Join-Path $here 'scripts/check-setup.ps1')
    if (-not $ok) { return }

    if (-not $SkipGraph) {
        Step 'scripts/graph-sweep.ps1'
        Step 'scripts/graph-identity-plus.ps1'
    }
    if (-not $SkipPowerPlatform) {
        # discovers environments -> output/pp-environment-urls.json (used by the Dataverse sweeps)
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
    Step 'scripts/assessment-report.ps1'   # maps the pulls to the MS 29-check assessment + extras
    Step 'scripts/ai-analysis.ps1'         # optional; no-op unless AI_ANALYSIS=local|api in .env

    Write-Host "`nDone. Raw evidence: ./output/*.json" -ForegroundColor Green
    $eff = Join-Path $here 'output/scope-effective.json'
    if (Test-Path $eff) {
        try { $banner = (Get-Content $eff -Raw | ConvertFrom-Json).banner; if ($banner) { Write-Host $banner -ForegroundColor Yellow } } catch {}
    }
    Write-Host "Check output/ for any *-ERROR.json (endpoints that need a tweak in this branch)." -ForegroundColor Yellow
    Write-Host "Reminder: if you used a client secret, rotate it now and never commit .env." -ForegroundColor Yellow
} finally {
    foreach ($k in @($previous.Keys)) { [Environment]::SetEnvironmentVariable($k, $previous[$k]) }
}
