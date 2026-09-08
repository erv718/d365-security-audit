# dataverse-sweep.ps1 - read-only pull of Dataverse security config, per environment.
# Covers: org-level auditing, per-table audit flags, security roles (managed vs custom), solutions.
#
# Set DATAVERSE_ENVIRONMENTS in .env to a comma-separated list of environment URLs, e.g.
#   DATAVERSE_ENVIRONMENTS=https://yourorg.crm.dynamics.com,https://yourorg-test.crm.dynamics.com
# The app must be added as an Application User with a read-only role in each.

. (Join-Path $PSScriptRoot '_common.ps1')

$envs = (Get-Conf DATAVERSE_ENVIRONMENTS) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $envs) { Write-Warning 'No DATAVERSE_ENVIRONMENTS set in .env - skipping Dataverse sweep.'; return }

function Get-DvAll($base, $H, $path) {
    $items = @(); $next = "$base/api/data/v9.2/$path"
    while ($next) { $r = Invoke-RestMethod -Uri $next -Headers $H; if ($r.value) { $items += $r.value }; $next = $r.'@odata.nextLink' }
    return ,$items
}

# One area = one isolated try/catch: a failure in one query neither hides the others nor
# disappears from output/ (it leaves a dv-<env>-<area>-ERROR.json marker like the other sweeps).
function Save-DvArea($base, $H, $safe, $path, $file, $label) {
    try { Save-Json (Get-DvAll $base $H $path) "dv-$safe-$file.json" | Out-Null }
    catch { Write-Warning "  [$safe] $label failed: $($_.Exception.Message)"; Save-Json @{ error = $_.Exception.Message } "dv-$safe-$file-ERROR.json" | Out-Null }
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
    Write-Host "  [$safe] done" -ForegroundColor Green
}
