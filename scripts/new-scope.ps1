# new-scope.ps1 - writes scope.json: which Azure subscriptions, resource groups, resource readers
# and Dataverse environments a run of run-audit.ps1 covers.
#
# Two ways in:
#   -FromInventory a.csv,b.csv   Portal inventory exports (columns NAME, TYPE, ..., RESOURCE LINK).
#                                No sign-in. The RESOURCE LINK column carries the ARM resource id,
#                                which gives the subscription, the resource group, the exact ARM
#                                type and the name. Child resources (Spark pools, databases)
#                                collapse onto their parent, types the audit reads map to reader
#                                names, everything else lands on an "ignored" list with counts.
#   (no -FromInventory)          Lists what the app can see (subscriptions, resource groups,
#                                environments) with read-only GETs and offers numbered pickers.
#                                Signs in as the .env app registration. -DeviceCode signs in as a
#                                person instead: the only interactive sign-in in this repo, and it
#                                lives here, in a helper that writes one local file. The audit
#                                itself never prompts.
#
# Read-only against the tenant. Writes exactly one local file, scope.json (or -Out). Empty lists
# in that file mean "everything the app can read"; delete the file to go back to a full run.
# PowerShell 5.1 and 7. No modules.

param(
    [string[]]$FromInventory,          # one or more CSV exports; a comma-separated string is fine too
    [string]$Out,                      # default: <repo>/scope.json
    [switch]$Force,                    # overwrite an existing file
    [string[]]$Environments,           # environment selectors to include (URL, environment id or display name)
    [switch]$NoResources,              # inventory mode: do not pin resource names, audit whole groups
    [switch]$DeviceCode,               # picker mode: sign in as a person for this helper only
    [string]$Tenant = 'organizations'  # device-code only: tenant id or domain
)

. (Join-Path $PSScriptRoot '_common.ps1')

$repo = Split-Path $PSScriptRoot -Parent
if (-not $Out) { $Out = Join-Path $repo 'scope.json' }
if ((Test-Path $Out) -and -not $Force) { Write-Warning "$Out exists. Add -Force to overwrite it."; return }

# ARM type -> reader name the audit knows; everything else is reported, never fatal.
$ReaderByType = @{
    'microsoft.sql/servers'                    = 'sql'
    'microsoft.synapse/workspaces'             = 'synapse'
    'microsoft.keyvault/vaults'                = 'keyvault'
    'microsoft.network/networksecuritygroups'  = 'nsg'
    'microsoft.logic/workflows'                = 'logicapps'
    'microsoft.operationalinsights/workspaces' = 'loganalytics'
}
$PlannedByType = @{
    'microsoft.compute/virtualmachines' = 'no reader yet (planned: VM exposure - public IPs, NSG source breadth)'
    'microsoft.storage/storageaccounts' = 'no reader yet (planned: storage network rules)'
    'microsoft.web/sites'               = 'no reader yet (planned: Function App access restrictions)'
    'microsoft.web/connections'         = 'no reader yet (planned: API connections)'
}
$Notes = @(
    'Empty lists (or a missing key) mean everything the app can read.',
    'types limits the per-resource readers; rbac, defender and diagnostics always run per selected subscription.',
    'resources pins names per reader; delete that block to audit whole resource groups.',
    'A run with any selection is labelled PARTIAL in output/assessment-report.md.'
)

function Get-Column($cols, [string]$want) { return @($cols | Where-Object { $_.Trim().TrimStart([char]0xFEFF) -eq $want })[0] }

function Write-ScopeFile($obj, [string]$path) {
    ConvertTo-Json -Depth 8 -InputObject $obj | Out-File -Encoding utf8 $path
    Write-Host "Written: $path" -ForegroundColor Green
    Write-Host 'Next: ./run-audit.ps1 (a scope.json next to .env is picked up automatically; elsewhere: -Scope <path>)' -ForegroundColor Green
}

# ---------------------------------------------------------------------------------------------
# Inventory mode
# ---------------------------------------------------------------------------------------------
if ($FromInventory) {
    $paths = @()
    foreach ($x in $FromInventory) { if (Test-Path $x -PathType Leaf) { $paths += $x } else { $paths += @(ConvertTo-ScopeList $x) } }
    $linkRx = '/subscriptions/(?<sub>[0-9a-fA-F-]{36})(?:/resourceGroups/(?<rg>[^/?#]+))?(?:/providers/(?<ns>[^/?#]+)/(?<type>[^/?#]+)/(?<name>[^/?#]+))?'
    $subIds = @{}; $subNames = @{}; $rgs = @{}; $readers = @{}; $resources = @{}; $seenRes = @{}; $ignored = @{}; $sources = @()
    $rowsTotal = 0; $rowsRes = 0; $rowsChild = 0
    foreach ($p in $paths) {
        if (-not (Test-Path $p -PathType Leaf)) { throw "inventory not found: $p" }
        $csv = @(Import-Csv -Path $p -Encoding UTF8)
        $sources += (Split-Path $p -Leaf)
        if ($csv.Count -eq 0) { Write-Warning "$p has no data rows"; continue }
        $cols = @($csv[0].PSObject.Properties.Name)
        $linkCol = Get-Column $cols 'RESOURCE LINK'; $nameCol = Get-Column $cols 'NAME'; $typeCol = Get-Column $cols 'TYPE'
        if (-not $linkCol) { throw "$p has no RESOURCE LINK column (columns: $($cols -join ', '))" }
        foreach ($r in $csv) {
            $rowsTotal++
            $link = "$($r.$linkCol)"; $friendly = ''; $rowName = ''
            if ($typeCol) { $friendly = ("$($r.$typeCol)" -replace '\s+', ' ').Trim() }
            if ($nameCol) { $rowName = "$($r.$nameCol)".Trim() }
            if ($link -match $linkRx) {
                $sub = $Matches['sub'].ToLower(); $rg = $Matches['rg']; $ns = $Matches['ns']; $type = $Matches['type']; $name = $Matches['name']
                $subIds[$sub] = 1
                if ($rg) { if (-not $rgs.ContainsKey($rg.ToLower())) { $rgs[$rg.ToLower()] = $rg } }
                if ($ns -and $type -and $name) {
                    $key = "$ns/$type"; $keyL = $key.ToLower()
                    $resKey = "$sub|$($rg.ToLower())|$keyL|$($name.ToLower())"
                    if ($seenRes.ContainsKey($resKey)) { $rowsChild++; continue }   # a child row (pool, database) or a duplicate: the parent is already counted
                    $seenRes[$resKey] = 1; $rowsRes++
                    if ($ReaderByType.ContainsKey($keyL)) {
                        $reader = $ReaderByType[$keyL]; $readers[$reader] = 1
                        if (-not $resources.ContainsKey($reader)) { $resources[$reader] = @() }
                        if ($resources[$reader] -notcontains $name) { $resources[$reader] += $name }
                    } else {
                        $reason = 'not read by the audit'; if ($PlannedByType.ContainsKey($keyL)) { $reason = $PlannedByType[$keyL] }
                        if (-not $ignored.ContainsKey($key)) { $ignored[$key] = @{ count = 0; reason = $reason } }
                        $ignored[$key].count++
                    }
                }
                continue
            }
            # No ARM id in the link: only the portal's own rows for groups and subscriptions are usable.
            if ($friendly -eq 'Resource group' -and $rowName) { if (-not $rgs.ContainsKey($rowName.ToLower())) { $rgs[$rowName.ToLower()] = $rowName }; continue }
            if ($friendly -eq 'Subscription' -and $rowName) { $subNames[$rowName] = 1; continue }
            $key = "(no resource link) $friendly"
            if (-not $ignored.ContainsKey($key)) { $ignored[$key] = @{ count = 0; reason = 'row has no ARM resource id in RESOURCE LINK' } }
            $ignored[$key].count++
        }
    }
    $subList = @($subIds.Keys | Sort-Object) + @($subNames.Keys | Sort-Object)
    $typeList = @($script:ScopeReaders | Where-Object { $readers.ContainsKey($_) })
    $resOut = [ordered]@{}
    foreach ($t in $typeList) { $resOut[$t] = @($resources[$t] | Sort-Object) }
    $ignoredOut = @()
    foreach ($k in ($ignored.Keys | Sort-Object { -$ignored[$_].count })) { $ignoredOut += [ordered]@{ type = $k; count = $ignored[$k].count; reason = $ignored[$k].reason } }
    $scopeOut = [ordered]@{
        version = 1
        generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        generatedBy = 'scripts/new-scope.ps1 -FromInventory'
        sources = $sources
        notes = $Notes + @('Environments are not part of Azure inventories: add instance URLs, environment ids or display names under powerPlatform.environments, or run new-scope.ps1 without -FromInventory to pick them.')
        azure = [ordered]@{ subscriptions = $subList; resourceGroups = @($rgs.Values | Sort-Object); types = $typeList }
        powerPlatform = [ordered]@{ environments = @(ConvertTo-ScopeList $Environments) }
        ignored = $ignoredOut
    }
    if (-not $NoResources) { $scopeOut.azure.resources = $resOut }

    Write-Host ''
    Write-Host "Inventory: $rowsTotal row(s) from $($sources.Count) file(s); $rowsRes distinct resource(s), $rowsChild child or duplicate row(s) collapsed onto their parent" -ForegroundColor Cyan
    Write-Host "  subscriptions   $($subList.Count) ($($subIds.Count) by id, $($subNames.Count) by name)" -ForegroundColor Yellow
    Write-Host "  resource groups $($rgs.Count)" -ForegroundColor Yellow
    Write-Host "  readers         $(if($typeList.Count){$typeList -join ', '}else{'none (no type the audit reads)'})" -ForegroundColor Yellow
    if (-not $NoResources) { Write-Host "  pinned names    $(($typeList | ForEach-Object { "$_=$(@($resOut[$_]).Count)" }) -join ', ')" -ForegroundColor Yellow }
    Write-Host "  environments    $(@(ConvertTo-ScopeList $Environments).Count) (add with -Environments or edit the file)" -ForegroundColor Yellow
    if ($ignoredOut.Count -gt 0) {
        Write-Host '  ignored (not created in the scope):' -ForegroundColor DarkGray
        foreach ($i in $ignoredOut) { Write-Host ("    {0,4} x {1}: {2}" -f $i.count, $i.type, $i.reason) -ForegroundColor DarkGray }
    }
    Write-ScopeFile $scopeOut $Out
    return
}

# ---------------------------------------------------------------------------------------------
# Picker mode: what the app (or, with -DeviceCode, you) can see, then numbered multi-selects.
# ---------------------------------------------------------------------------------------------
# "1,3-5" -> 1-based indices; blank or "all" -> @() which means no selection (everything).
function ConvertTo-Selection([string]$text, [int]$max) {
    $t = "$text".Trim().ToLower()
    if (-not $t -or $t -eq 'all') { return @() }
    $idx = @()
    foreach ($part in ($t -split '[,\s]+')) {
        if (-not $part) { continue }
        if ($part -match '^(\d+)-(\d+)$') { $a = [int]$Matches[1]; $b = [int]$Matches[2]; if ($a -gt $b) { $x = $a; $a = $b; $b = $x }; for ($i = $a; $i -le $b; $i++) { $idx += $i } }
        elseif ($part -match '^\d+$') { $idx += [int]$part }
        else { throw "not a number or a range: $part" }
    }
    return @($idx | Where-Object { $_ -ge 1 -and $_ -le $max } | Select-Object -Unique)
}
function Read-Selection([string]$prompt, [int]$max) {
    while ($true) {
        $answer = Read-Host $prompt
        try { return @(ConvertTo-Selection $answer $max) } catch { Write-Host "  $($_.Exception.Message); try again (numbers, ranges like 1,3-5, or blank for all)" -ForegroundColor Yellow }
    }
}
# Device-code sign-in in pure REST through Microsoft's first-party Azure PowerShell public client.
function Get-DeviceCodeToken {
    param([Parameter(Mandatory)][string]$Scope, [string]$Label = 'sign-in')
    $clientId = '1950a258-227b-4e31-a9cf-717495945fc2'
    $dc = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/devicecode" -Body @{ client_id = $clientId; scope = $Scope }
    Write-Host ''
    Write-Host "  [$Label] $($dc.message)" -ForegroundColor Yellow
    Write-Host ''
    $interval = 5; if ($dc.interval) { $interval = [int]$dc.interval }
    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            return (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -Body @{
                grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $clientId; device_code = $dc.device_code
            }).access_token
        } catch {
            $text = Get-ErrorText $_
            $code = ''; if ($text -match '"error"\s*:\s*"([a-z_]+)"') { $code = $Matches[1] }
            if ($code -eq 'authorization_pending') { continue }
            if ($code -eq 'slow_down') { $interval += 5; continue }
            throw "Device-code sign-in failed ($code): $text"
        }
    }
    throw 'Device-code sign-in timed out: the code expired before the sign-in completed.'
}

Write-Host 'new-scope: listing what can be seen (read-only GETs), then pick.' -ForegroundColor Cyan
$armTok = $null; $bapTok = $null
if ($DeviceCode) {
    Write-Host 'Interactive sign-in for this helper only (the audit itself never prompts).' -ForegroundColor Yellow
    $armTok = Get-DeviceCodeToken -Scope 'https://management.azure.com/user_impersonation offline_access' -Label 'Azure Resource Manager'
    try { $bapTok = Get-DeviceCodeToken -Scope 'https://api.bap.microsoft.com/user_impersonation offline_access' -Label 'Power Platform admin' } catch { Write-Warning "Power Platform sign-in skipped: $($_.Exception.Message)" }
} else {
    $armTok = Get-Token 'https://management.azure.com'
    $bapTok = Get-Token 'https://api.bap.microsoft.com'
    if (-not $armTok -and -not $bapTok) { throw 'No app token. Fill in .env (docs/permissions.md), or use -DeviceCode to sign in as yourself for this helper only.' }
}

$subs = @(); $groups = @(); $envs = @()
if ($armTok) {
    $HA = @{ Authorization = "Bearer $armTok" }
    try { $r = Invoke-Paged 'https://management.azure.com/subscriptions?api-version=2020-01-01' $HA 'nextLink'; $subs = @($r | Where-Object { $_.state -eq 'Enabled' }) }
    catch { Write-Warning "Subscriptions could not be listed: $(Get-ErrorText $_)" }
}
$pickedSubs = @()
if ($subs.Count -gt 0) {
    Write-Host ''
    Write-Host "Subscriptions visible ($($subs.Count)):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $subs.Count; $i++) { Write-Host ("  [{0,2}] {1}  {2}" -f ($i + 1), $subs[$i].displayName, $subs[$i].subscriptionId) }
    $sel = @(Read-Selection 'Subscriptions to audit (numbers or ranges; blank = all)' $subs.Count)
    $pickedSubs = @($sel | ForEach-Object { $subs[$_ - 1] })
    $listFrom = $subs; if ($pickedSubs.Count -gt 0) { $listFrom = $pickedSubs }
    foreach ($s in $listFrom) {
        try {
            $r = Invoke-Paged "https://management.azure.com/subscriptions/$($s.subscriptionId)/resourcegroups?api-version=2021-04-01" $HA 'nextLink'
            foreach ($g in @($r)) { $groups += [pscustomobject]@{ name = "$($g.name)"; sub = "$($s.displayName)" } }
        } catch { Write-Warning "Resource groups in $($s.displayName) could not be listed: $(Get-ErrorText $_)" }
    }
} else { Write-Host '  no subscription visible (no Reader role, or no ARM token); Azure lists left empty' -ForegroundColor DarkGray }
$pickedGroups = @()
if ($groups.Count -gt 0) {
    Write-Host ''
    Write-Host "Resource groups ($($groups.Count)):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $groups.Count; $i++) { Write-Host ("  [{0,3}] {1}  ({2})" -f ($i + 1), $groups[$i].name, $groups[$i].sub) }
    $sel = @(Read-Selection 'Resource groups to audit (blank = all groups in the subscriptions above)' $groups.Count)
    $pickedGroups = @($sel | ForEach-Object { $groups[$_ - 1].name } | Select-Object -Unique)
}
if ($bapTok) {
    try { $r = Invoke-Paged 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01' @{ Authorization = "Bearer $bapTok" } 'nextLink'; $envs = @($r | Where-Object { $_.properties }) }
    catch { Write-Warning "Environments could not be listed (is the app registered as a Power Platform management app?): $(Get-ErrorText $_)" }
}
$pickedEnvs = @()
if ($envs.Count -gt 0) {
    Write-Host ''
    Write-Host "Power Platform environments ($($envs.Count)):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $envs.Count; $i++) {
        $e = $envs[$i]; $dv = 'no Dataverse'; if ($e.properties.linkedEnvironmentMetadata.instanceUrl) { $dv = $e.properties.linkedEnvironmentMetadata.instanceUrl }
        Write-Host ("  [{0,2}] {1} [{2}]  {3}" -f ($i + 1), $e.properties.displayName, $e.properties.environmentSku, $dv)
    }
    $sel = @(Read-Selection 'Environments to audit (blank = all with a Dataverse URL)' $envs.Count)
    foreach ($n in $sel) {
        $e = $envs[$n - 1]
        $u = "$($e.properties.linkedEnvironmentMetadata.instanceUrl)".TrimEnd('/')
        if ($u) { $pickedEnvs += $u } else { Write-Host "  skipped '$($e.properties.displayName)': no Dataverse database" -ForegroundColor Yellow }
    }
} else { Write-Host '  no environment list (no Power Platform token); environments left empty' -ForegroundColor DarkGray }
Write-Host ''
Write-Host "Resource readers ($($script:ScopeReaders.Count)):" -ForegroundColor Cyan
for ($i = 0; $i -lt $script:ScopeReaders.Count; $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $script:ScopeReaders[$i]) }
$sel = @(Read-Selection 'Readers to run (blank = all; rbac, defender and diagnostics always run)' $script:ScopeReaders.Count)
$pickedTypes = @($sel | ForEach-Object { $script:ScopeReaders[$_ - 1] })

$scopeOut = [ordered]@{
    version = 1
    generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    generatedBy = "scripts/new-scope.ps1 (picker$(if($DeviceCode){', device-code sign-in'}else{', app token'}))"
    notes = $Notes
    azure = [ordered]@{ subscriptions = @($pickedSubs | ForEach-Object { $_.subscriptionId }); resourceGroups = $pickedGroups; types = $pickedTypes }
    powerPlatform = [ordered]@{ environments = @($pickedEnvs + @(ConvertTo-ScopeList $Environments) | Select-Object -Unique) }
}
Write-Host ''
Write-Host "Selection: $($scopeOut.azure.subscriptions.Count) subscription(s), $($pickedGroups.Count) resource group(s), $(if($pickedTypes.Count){$pickedTypes -join ', '}else{'all readers'}), $($scopeOut.powerPlatform.environments.Count) environment(s). Empty = everything." -ForegroundColor Yellow
Write-ScopeFile $scopeOut $Out
