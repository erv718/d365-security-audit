# inventory-check.ps1 - cross-checks your own Azure inventory export against what the audit saw.
#
#   ./scripts/inventory-check.ps1 -FromInventory 'Azure.csv','Other export.csv'
#   (or: ./run-audit.ps1 -Inventory 'Azure.csv' to run it at the end of an audit)
#
# Input: Azure portal > All resources > Export to CSV (columns NAME, TYPE, ..., RESOURCE LINK),
# and output/arm-*-resources.json from the last audit run (azure-exposure.ps1). Child resources
# (Spark pools, databases, runbooks) collapse onto their parent on both sides. Reports:
#   - in your export but not visible to the audit app (no Reader there, or deleted since)
#   - visible to the app but not in your export (created since, or outside the export)
#   - each type in your export: checked by a security rule, or inventory only
# Local files only: no sign-in, no network calls. Writes output/inventory-check.md.

param([Parameter(Mandatory)][string[]]$FromInventory)

. (Join-Path $PSScriptRoot '_common.ps1')
$out = Get-OutDir

# Top-level ARM id (subscription, group, provider type, name) of a resource or one of its children.
$idRx = '/subscriptions/(?<sub>[0-9a-fA-F-]{36})/resourceGroups/(?<rg>[^/?#]+)/providers/(?<ns>[^/?#]+)/(?<type>[^/?#]+)/(?<name>[^/?#]+)'
function Get-TopKey([string]$id) {
    if ($id -notmatch $idRx) { return $null }
    return [pscustomobject]@{
        key  = ("/subscriptions/$($Matches['sub'])/resourcegroups/$($Matches['rg'])/providers/$($Matches['ns'])/$($Matches['type'])/$($Matches['name'])").ToLower()
        sub  = $Matches['sub'].ToLower(); rg = $Matches['rg']; type = "$($Matches['ns'])/$($Matches['type'])".ToLower(); name = $Matches['name']
    }
}

# --- What the audit app saw ------------------------------------------------------------
$seen = @{}; $invFiles = @(Get-ChildItem $out -Filter 'arm-*-resources.json' -ErrorAction SilentlyContinue)
if ($invFiles.Count -eq 0) {
    Write-Warning 'No output/arm-*-resources.json yet. Run the audit first (Azure only is enough: ./run-audit.ps1 -SkipGraph -SkipPowerPlatform -SkipDataverse).'
    return
}
$appSubs = @{}
foreach ($f in $invFiles) {
    try { $items = Get-Content $f.FullName -Raw | ConvertFrom-Json } catch { Write-Warning "$($f.Name) could not be read: $($_.Exception.Message)"; continue }
    foreach ($r in @($items | Where-Object { $_ -and $_.id })) {
        $k = Get-TopKey "$($r.id)"
        if ($k -and -not $seen.ContainsKey($k.key)) { $seen[$k.key] = $k; $appSubs[$k.sub] = 1 }
    }
}

# --- Your export(s) ------------------------------------------------------------------
$paths = @(); foreach ($x in $FromInventory) { if (Test-Path -LiteralPath $x -PathType Leaf) { $paths += $x } else { $paths += @(ConvertTo-ScopeList $x) } }
$mine = @{}; $rowsTotal = 0; $sources = @()
foreach ($p in $paths) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { Write-Warning "Inventory file not found: $p"; continue }
    # A locked file (still open in Excel) or a malformed header must not stop the run.
    try { $csv = @(Import-Csv -LiteralPath $p) } catch { Write-Warning "Inventory file could not be read, skipped: $p ($($_.Exception.Message))"; continue }
    $sources += "$(Split-Path $p -Leaf) ($($csv.Count) rows)"
    if ($csv.Count -eq 0) { continue }
    $cols = @($csv[0].PSObject.Properties.Name)
    $linkCol = @($cols | Where-Object { $_.Trim().TrimStart([char]0xFEFF) -eq 'RESOURCE LINK' })[0]
    if (-not $linkCol) { Write-Warning "$p has no RESOURCE LINK column (columns: $($cols -join ', ')); skipped"; continue }
    foreach ($r in $csv) {
        $rowsTotal++
        $k = Get-TopKey "$($r.$linkCol)"
        if ($k -and -not $mine.ContainsKey($k.key)) { $mine[$k.key] = $k }
    }
}
if ($mine.Count -eq 0) { Write-Warning 'No resource rows with an ARM resource link were found in the export(s).'; return }

# --- Compare ---------------------------------------------------------------------------
$notSeen = @($mine.Values | Where-Object { -not $seen.ContainsKey($_.key) } | Sort-Object type, name)
$notMine = @($seen.Values | Where-Object { -not $mine.ContainsKey($_.key) } | Sort-Object type, name)
$notSeenOtherSub = @($notSeen | Where-Object { -not $appSubs.ContainsKey($_.sub) }).Count
$byType = @($mine.Values | Group-Object type | Sort-Object Count -Descending)

$md = @()
$md += '# Inventory cross-check'
$md += ''
$md += "Your export(s): $($sources -join ', '); $($mine.Count) resource(s) after child rows collapse onto their parent. The audit app saw $($seen.Count) resource(s) in $($appSubs.Count) subscription(s) (output/arm-*-resources.json)."
$md += ''
$md += "## In your export, not seen by the audit app ($($notSeen.Count))"
$md += ''
if ($notSeen.Count) {
    if ($notSeenOtherSub) { $md += "$notSeenOtherSub of them are in a subscription the app cannot see at all: give the app Reader there (or narrow the export). The rest were deleted since the export, or sit in a resource group the run did not read." ; $md += '' }
    $md += '| Type | Name | Resource group | Subscription id |'
    $md += '|---|---|---|---|'
    foreach ($x in $notSeen) { $md += "| $($x.type) | $($x.name) | $($x.rg) | $($x.sub) |" }
} else { $md += 'None: every resource in your export was visible to the audit.' }
$md += ''
$md += "## Seen by the audit app, not in your export ($($notMine.Count))"
$md += ''
if ($notMine.Count) {
    $md += '| Type | Name | Resource group |'
    $md += '|---|---|---|'
    foreach ($x in $notMine) { $md += "| $($x.type) | $($x.name) | $($x.rg) |" }
} else { $md += 'None.' }
$md += ''
$md += '## Your export by type'
$md += ''
$md += '| Type | Count | Security rule |'
$md += '|---|---|---|'
foreach ($g in $byType) { $md += "| $($g.Name) | $($g.Count) | $(if($script:CoveredArmTypes -contains $g.Name){'checked'}else{'inventory only'}) |" }

$mdPath = Join-Path $out 'inventory-check.md'
$md -join "`n" | Out-File -Encoding utf8 $mdPath

Write-Host ''
Write-Host '==================== INVENTORY CROSS-CHECK ====================' -ForegroundColor Green
Write-Host "Your export: $($mine.Count) resource(s). Seen by the audit app: $($seen.Count)." -ForegroundColor Yellow
Write-Host "  In your export but not seen by the app: $($notSeen.Count)$(if($notSeenOtherSub){" ($notSeenOtherSub in a subscription the app cannot see)"})" -ForegroundColor $(if ($notSeen.Count) { 'Yellow' } else { 'Green' })
Write-Host "  Seen by the app but not in your export: $($notMine.Count)" -ForegroundColor Yellow
$unchecked = @($byType | Where-Object { $script:CoveredArmTypes -notcontains $_.Name } | ForEach-Object { "$(($_.Name -split '/')[-1]) ($($_.Count))" })
if ($unchecked.Count) { Write-Host "  Types in your export with no security rule yet: $($unchecked -join ', ')" -ForegroundColor DarkGray }
Write-Host "Report: $mdPath" -ForegroundColor Green
