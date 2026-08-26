# dataverse-sweep.ps1 - read-only pull of Dataverse security config, per environment.
# Covers: org-level auditing, per-table audit flags, security roles (managed vs custom), solutions.
#
# Set DATAVERSE_ENVIRONMENTS in .env to a comma-separated list of environment URLs, e.g.
#   DATAVERSE_ENVIRONMENTS=https://yourorg.crm.dynamics.com,https://yourorg-test.crm.dynamics.com
# The app (or your az login identity) must be an Application User / have a read role in each.

. (Join-Path $PSScriptRoot '_common.ps1')

$envs = (Get-Conf DATAVERSE_ENVIRONMENTS) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $envs) { Write-Warning 'No DATAVERSE_ENVIRONMENTS set in .env - skipping Dataverse sweep.'; return }

function Get-DvAll($base, $H, $path) {
    $items = @(); $next = "$base/api/data/v9.2/$path"
    while ($next) { $r = Invoke-RestMethod -Uri $next -Headers $H; if ($r.value) { $items += $r.value }; $next = $r.'@odata.nextLink' }
    return $items
}

foreach ($url in $envs) {
    $safe = ($url -replace 'https?://','' -replace '\..*','')
    Write-Host "Dataverse: $safe" -ForegroundColor Cyan
    $tok = Get-Token $url
    if (-not $tok) { Write-Warning "  no token for $url"; continue }
    $H = @{ Authorization = "Bearer $tok"; Accept = 'application/json'; 'OData-Version' = '4.0' }
    try {
        Save-Json (Get-DvAll $url $H 'organizations?$select=name,isauditenabled,isuseraccessauditenabled,auditretentionperiodv2') "dv-$safe-org.json" | Out-Null
        Save-Json (Get-DvAll $url $H 'EntityDefinitions?$select=LogicalName,IsAuditEnabled,IsCustomEntity') "dv-$safe-entities.json" | Out-Null
        Save-Json (Get-DvAll $url $H 'roles?$select=name,ismanaged,iscustomizable,roleid') "dv-$safe-roles.json" | Out-Null
        Save-Json (Get-DvAll $url $H 'solutions?$select=uniquename,friendlyname,version,ismanaged,isvisible&$expand=publisherid($select=friendlyname)') "dv-$safe-solutions.json" | Out-Null
        Save-Json (Get-DvAll $url $H 'fieldsecurityprofiles?$select=name') "dv-$safe-fieldsec.json" | Out-Null
        Write-Host "  saved org/entities/roles/solutions/fieldsec" -ForegroundColor Green
    } catch { Write-Warning "  $safe failed: $($_.Exception.Message)" }
}
