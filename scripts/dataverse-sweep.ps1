# dataverse-sweep.ps1 - read-only pull of Dataverse security config, per environment.
# Covers: org-level auditing, per-table audit flags, security roles (managed vs custom), solutions.
#
# Environments: the same resolved list as dataverse-plus.ps1 (run-audit.ps1 -Environments >
# scope.json > DATAVERSE_ENVIRONMENTS in .env, as URLs, environment ids or display names).
# With no selection, every environment the Power Platform sweep discovered with a Dataverse
# URL (output/pp-environment-urls.json). The app must be an Application User with a read-only
# role in each; environments where it is not simply leave a dv-<env>-*-ERROR.json marker.

. (Join-Path $PSScriptRoot '_common.ps1')

$scope = Read-ScopeEffective
$res = Resolve-ScopeEnvironments $scope
$envs = @(@($res.environments) | ForEach-Object { $_.url })
if (@($res.unresolved).Count -gt 0) {
    Write-Warning "Dataverse: $(@($res.unresolved).Count) selected environment(s) could not be resolved to a URL: $(@($res.unresolved) -join ', '). Use the instance URL, or run the Power Platform sweep first so ids and display names resolve."
}
if ($envs.Count -eq 0) { Write-Warning 'No Dataverse environments selected or discovered (DATAVERSE_ENVIRONMENTS, scope.json, -Environments, or the Power Platform sweep) - skipping Dataverse sweep.'; return }
Write-Host "Dataverse: $($envs.Count) environment(s)$(if($res.selected -gt 0){' selected by scope'}else{' discovered'})" -ForegroundColor Cyan
Update-ScopeEffective {
    param($x)
    Set-ScopeField $x.powerPlatform 'discoveredEnvironments' $res.discovered
    Set-ScopeField $x.powerPlatform 'resolved' @($res.environments)
    Set-ScopeField $x.powerPlatform 'unresolved' @($res.unresolved)
} | Out-Null

function Get-DvAll($base, $H, $path) {
    $items = @(); $next = "$base/api/data/v9.2/$path"
    while ($next) { $r = Invoke-RestMethod -Uri $next -Headers $H; if ($r.value) { $items += $r.value }; $next = $r.'@odata.nextLink' }
    return ,$items
}

# One area = one isolated try/catch: a failure in one query neither hides the others nor
# disappears from output/ (it leaves a dv-<env>-<area>-ERROR.json marker like the other sweeps).
function Save-DvArea($base, $H, $safe, $path, $file, $label) {
    try { Save-Json (Get-DvAll $base $H $path) "dv-$safe-$file.json" | Out-Null }
    catch { $why = Get-ErrorText $_; Write-Warning "  [$safe] $label failed: $why"; Save-Json @{ error = $why } "dv-$safe-$file-ERROR.json" | Out-Null }
}

foreach ($url in $envs) {
    $safe = ($url -replace 'https?://','' -replace '\..*','')
    Write-Host "Dataverse: $safe" -ForegroundColor Cyan
    $tok = Get-Token $url
    if (-not $tok) { Write-Warning "  no token for $url"; continue }
    $H = @{ Authorization = "Bearer $tok"; Accept = 'application/json'; 'OData-Version' = '4.0' }
    Save-DvArea $url $H $safe 'organizations?$select=name,isauditenabled,isuseraccessauditenabled,auditretentionperiodv2' 'org' 'org settings'
    Save-DvArea $url $H $safe 'EntityDefinitions?$select=LogicalName,IsAuditEnabled,IsCustomEntity' 'entities' 'entity audit flags'
    Save-DvArea $url $H $safe 'roles?$select=name,ismanaged,iscustomizable,roleid' 'roles' 'security roles'
    Save-DvArea $url $H $safe 'solutions?$select=uniquename,friendlyname,version,ismanaged,isvisible&$expand=publisherid($select=friendlyname)' 'solutions' 'solutions'
    Save-DvArea $url $H $safe 'fieldsecurityprofiles?$select=name' 'fieldsec' 'field security profiles'
    Save-DvArea $url $H $safe 'systemusers?$select=fullname,domainname,isdisabled,accessmode,applicationid,azureactivedirectoryobjectid&$filter=isdisabled eq false&$expand=systemuserroles_association($select=name,roleid)' 'users' 'users and their roles'
    Write-Host "  [$safe] done" -ForegroundColor Green
}
