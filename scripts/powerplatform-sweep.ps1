# powerplatform-sweep.ps1 - read-only pull of the Power Platform admin (BAP) plane.
# Covers: environments (+ residency/region, security group, Managed Environment flag and
# Dataverse URL auto-discovery), DLP (connector data) policies, tenant settings.
#
# ASSUMPTION: the app registration (CLIENT_ID) must be registered as a Power Platform
# management application. That is a one-time setup step an admin runs elsewhere - this
# tool itself never signs in interactively:
#     Add-PowerAppsAccount ; New-PowerAppManagementApp -ApplicationId <CLIENT_ID>
# Without that registration the BAP admin endpoints return 401/403 - each area is
# wrapped in its own try/catch and simply records the error, so a missing registration
# or license degrades gracefully instead of stopping the sweep.
#
# Everything here is GET (or a read-only listTenantSettings POST). No tenant writes.

. (Join-Path $PSScriptRoot '_common.ps1')

$tok = Get-Token 'https://api.bap.microsoft.com'
if (-not $tok) { Write-Warning 'No Power Platform (BAP) token - skipping powerplatform sweep.'; return }
$H = @{ Authorization = "Bearer $tok" }

# BAP APIs paginate on 'nextLink' (not the OData '@odata.nextLink').
$Next = 'nextLink'

# --- Environments (residency + Dataverse URL auto-discovery) -----------------
# The payload already carries what the report needs: properties.isDefault, environmentSku,
# linkedEnvironmentMetadata.securityGroupId (absent when no group is set) and
# governanceConfiguration.protectionLevel ('Standard' = Managed Environment).
Write-Host 'Power Platform: environments...' -ForegroundColor Cyan
try {
    $envs = Invoke-Paged 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01' $H $Next
    Save-Json $envs 'pp-environments.json' | Out-Null

    # Plain list of Dataverse instance URLs so the Dataverse sweep can auto-discover them.
    $urls = @($envs | ForEach-Object { $_.properties.linkedEnvironmentMetadata.instanceUrl } | Where-Object { $_ })
    Save-Json $urls 'pp-environment-urls.json' | Out-Null

    Write-Host "  found $($envs.Count) environment(s); $($urls.Count) with a Dataverse URL" -ForegroundColor Yellow
    $envs | Group-Object { $_.properties.azureRegion } | Sort-Object Count -Descending | ForEach-Object {
        $region = if ($_.Name) { $_.Name } else { '(unknown)' }
        Write-Host "    region $region : $($_.Count)" -ForegroundColor Yellow
    }
    $skus = @($envs | Group-Object { $_.properties.environmentSku } | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
    if ($skus) { Write-Host "    SKUs: $skus" -ForegroundColor Yellow }
    $managed = @($envs | Where-Object { "$($_.properties.governanceConfiguration.protectionLevel)" -eq 'Standard' }).Count
    $withSg  = @($envs | Where-Object { $_.properties.linkedEnvironmentMetadata.securityGroupId }).Count
    Write-Host "    Managed Environments: $managed; with a security group: $withSg" -ForegroundColor Yellow
} catch {
    $e = Get-ErrorText $_
    Write-Warning "  environments failed: $e"
    Save-Json @{ error = $e; note = 'Register the app as a Power Platform management app: New-PowerAppManagementApp -ApplicationId <CLIENT_ID>.' } 'pp-environments-ERROR.json' | Out-Null
}

# --- DLP (connector data) policies --------------------------------------------
# Same route Microsoft's own admin module calls for Get-DlpPolicy:
# PowerPlatform.Governance/v1/policies with api-version 2016-11-01 (the v2 path this
# script used before is not what the module or the docs use). Zero policies is a real,
# reportable result, so an empty list is saved as [] rather than treated as a failure.
Write-Host 'Power Platform: DLP policies...' -ForegroundColor Cyan
try {
    $dlp = @()
    $next = 'https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v1/policies?api-version=2016-11-01&$top=50'
    while ($next) {
        $r = Invoke-RestMethod -Uri $next -Headers $H
        if ($null -eq $r) { $next = $null }
        elseif ($r.PSObject.Properties.Name -contains 'value') {
            $dlp += @($r.value)
            $next = if ($r.nextLink) { $r.nextLink } elseif ($r.'@odata.nextLink') { $r.'@odata.nextLink' } else { $null }
        } else {
            # shape guard: a bare array/object is still saved as-is instead of being dropped
            $dlp += @($r); $next = $null
        }
    }
    Save-Json $dlp 'pp-dlp-policies.json' | Out-Null
    if ($dlp.Count -eq 0) { Write-Host '  0 DLP policies - no connector data policy exists in this tenant.' -ForegroundColor Yellow }
    else { Write-Host "  DLP: $($dlp.Count) policies" -ForegroundColor Yellow }
} catch {
    $e = Get-ErrorText $_
    Write-Warning "  DLP policies failed: $e"
    Save-Json @{ error = $e; note = 'Needs the app registered as a Power Platform management app (New-PowerAppManagementApp).' } 'pp-dlp-policies-ERROR.json' | Out-Null
}

# --- Tenant settings (read-only listTenantSettings POST) ---------------------
Write-Host 'Power Platform: tenant settings...' -ForegroundColor Cyan
try {
    $ts = Invoke-RestMethod -Method Post -Uri 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version=2020-10-01' -Headers $H -Body '{}' -ContentType 'application/json'
    Save-Json $ts 'pp-tenant-settings.json' | Out-Null
    Write-Host '  saved tenant settings' -ForegroundColor Green
} catch {
    $e = Get-ErrorText $_
    Write-Warning "  tenant settings failed: $e"
    Save-Json @{ error = $e } 'pp-tenant-settings-ERROR.json' | Out-Null
}

Write-Host 'Power Platform sweep done.' -ForegroundColor Green
