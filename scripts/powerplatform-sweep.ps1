# powerplatform-sweep.ps1 - read-only pull of the Power Platform admin (BAP) plane.
# Covers: environments (+ residency/region + Dataverse URL auto-discovery), DLP policies,
# tenant settings.
#
# ASSUMPTION: the app registration (CLIENT_ID) must be registered as a Power Platform
# management application, e.g. via PowerShell:
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
} catch {
    Write-Warning "  environments failed: $($_.Exception.Message)"
    Save-Json @{ error = $_.Exception.Message } 'pp-environments-ERROR.json' | Out-Null
}

# --- DLP policies (v2 first, fall back to v1) --------------------------------
Write-Host 'Power Platform: DLP policies...' -ForegroundColor Cyan
try {
    $dlp = Invoke-Paged 'https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v2/policies?api-version=2019-05-01' $H $Next
    Save-Json $dlp 'pp-dlp-policies.json' | Out-Null
    Write-Host "  DLP (v2): $($dlp.Count) policies" -ForegroundColor Yellow
} catch {
    Write-Warning "  DLP v2 failed: $($_.Exception.Message) - trying v1"
    try {
        $dlp = Invoke-Paged 'https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v1/policies?api-version=2016-11-01' $H $Next
        Save-Json $dlp 'pp-dlp-policies.json' | Out-Null
        Write-Host "  DLP (v1): $($dlp.Count) policies" -ForegroundColor Yellow
    } catch {
        Write-Warning "  DLP v1 failed: $($_.Exception.Message)"
        Save-Json @{ error = $_.Exception.Message } 'pp-dlp-policies-ERROR.json' | Out-Null
    }
}

# --- Tenant settings (read-only listTenantSettings POST) ---------------------
Write-Host 'Power Platform: tenant settings...' -ForegroundColor Cyan
try {
    $ts = Invoke-RestMethod -Method Post -Uri 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version=2020-10-01' -Headers $H -Body '{}' -ContentType 'application/json'
    Save-Json $ts 'pp-tenant-settings.json' | Out-Null
    Write-Host '  saved tenant settings' -ForegroundColor Green
} catch {
    Write-Warning "  tenant settings failed: $($_.Exception.Message)"
    Save-Json @{ error = $_.Exception.Message } 'pp-tenant-settings-ERROR.json' | Out-Null
}

Write-Host 'Power Platform sweep done.' -ForegroundColor Green
