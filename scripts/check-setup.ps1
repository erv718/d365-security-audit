# check-setup.ps1 - preflight doctor. Verifies the read-only app registration is fully
# set up, and for anything that is not, prints exactly where to click to fix it.
#
# Read-only: each probe is a single tiny GET ($top=1 or a singleton). Nothing is changed.
# Outputs $true when the audit can proceed (even partially - sweeps fail soft), or
# $false when it cannot start at all (no .env values or the app cannot sign in).
# Can also be run on its own:  pwsh ./scripts/check-setup.ps1

. (Join-Path $PSScriptRoot '_common.ps1')

$script:fails = 0
function Show {
    param([bool]$Ok, [string]$Label, [string[]]$Fix = @())
    if ($Ok) { Write-Host "  [OK] $Label" -ForegroundColor Green }
    else {
        Write-Host "  [ X] $Label" -ForegroundColor Red
        foreach ($line in $Fix) { Write-Host "       $line" -ForegroundColor Yellow }
        $script:fails++
    }
}

Write-Host 'Checking your app registration setup...' -ForegroundColor Cyan
Write-Host ''

# --- 1. .env has the three values ------------------------------------------------
$tenant = Get-Conf TENANT_ID; $cid = Get-Conf CLIENT_ID; $sec = Get-Conf CLIENT_SECRET
if (-not ($tenant -and $cid -and $sec)) {
    Show $false '.env has TENANT_ID, CLIENT_ID and CLIENT_SECRET' @(
        'This tool signs in ONLY as a read-only app registration. It never signs in',
        'as a person and never shows a login prompt.',
        '1. Copy .env.example to .env',
        '2. Create the app: Entra portal > App registrations > New registration',
        '3. Put its Directory (tenant) ID, Application (client) ID, and a client',
        '   secret value into .env. Permissions: docs/permissions.md'
    )
    Write-Host ''
    Write-Host 'Cannot start until .env is filled in.' -ForegroundColor Yellow
    return $false
}
Show $true '.env has TENANT_ID, CLIENT_ID and CLIENT_SECRET'

# --- 2. The app can sign in at all -----------------------------------------------
$graphTok = Get-Token 'https://graph.microsoft.com'
if (-not $graphTok) {
    Show $false 'App can sign in (client credentials)' @(
        'The sign-in itself failed. Usual causes, in order:',
        '- CLIENT_SECRET is wrong, or expired (Entra > App registrations > your app >',
        '  Certificates & secrets > make a new secret and update .env)',
        '- TENANT_ID or CLIENT_ID has a typo (compare with the app Overview page)'
    )
    Write-Host ''
    Write-Host 'Cannot start until the app can sign in.' -ForegroundColor Yellow
    return $false
}
Show $true 'App can sign in (client credentials)'
$H = @{ Authorization = "Bearer $graphTok" }

# --- 3. Graph application permissions, one probe each -----------------------------
$consentFix = 'then click "Grant admin consent" on the API permissions page.'
$probes = @(
    @{ perm = 'Application.Read.All';                    url = 'https://graph.microsoft.com/v1.0/applications?$top=1' },
    @{ perm = 'RoleManagement.Read.Directory';           url = 'https://graph.microsoft.com/v1.0/directoryRoles' },
    @{ perm = 'User.Read.All';                           url = 'https://graph.microsoft.com/v1.0/users?$top=1' },
    @{ perm = 'Policy.Read.All';                         url = 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' },
    @{ perm = 'AuditLog.Read.All';                       url = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1' },
    @{ perm = 'DeviceManagementConfiguration.Read.All';  url = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?$top=1' },
    @{ perm = 'DeviceManagementManagedDevices.Read.All'; url = 'https://graph.microsoft.com/beta/deviceManagement/managedDeviceOverview' }
)
foreach ($p in $probes) {
    $ok = $true
    try { Invoke-RestMethod -Uri $p.url -Headers $H | Out-Null } catch { $ok = $false }
    $fix = @(
        "Entra portal > App registrations > your app > API permissions > Add a permission >",
        "Microsoft Graph > Application permissions > add '$($p.perm)',",
        $consentFix
    )
    if ($p.perm -eq 'AuditLog.Read.All') {
        $fix += "Note: sign-in logs also need an Entra ID P1 license. If the permission is already"
        $fix += "granted and consented, an [X] here is a licensing gap, not a permission gap."
    }
    Show $ok "Graph permission: $($p.perm)" $fix
}

# --- 4. Azure: can the app see any subscriptions? ---------------------------------
$armTok = Get-Token 'https://management.azure.com'
$subCount = 0
if ($armTok) {
    try {
        $subs = Invoke-RestMethod -Uri 'https://management.azure.com/subscriptions?api-version=2020-01-01' -Headers @{ Authorization = "Bearer $armTok" }
        $subCount = @($subs.value).Count
    } catch { $subCount = 0 }
}
Show ($subCount -gt 0) "Azure: $subCount subscription(s) visible to the app" @(
    'The app has no Reader role on any subscription.',
    'Azure portal > Subscriptions > (pick one) > Access control (IAM) >',
    'Add > Add role assignment > Reader > select your app > Review + assign.'
)

# --- 5. Dataverse: is the app an Application User in each environment? ------------
$envs = (Get-Conf DATAVERSE_ENVIRONMENTS) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $envs) {
    Write-Host '  [--] Dataverse: DATAVERSE_ENVIRONMENTS not set in .env (those checks will be skipped)' -ForegroundColor DarkGray
} else {
    foreach ($envUrl in $envs) {
        $ok = $false
        $t = Get-Token $envUrl
        if ($t) {
            try { Invoke-RestMethod -Uri "$($envUrl.TrimEnd('/'))/api/data/v9.2/WhoAmI" -Headers @{ Authorization = "Bearer $t" } | Out-Null; $ok = $true } catch { $ok = $false }
        }
        Show $ok "Dataverse: $envUrl" @(
            'The app is not an Application User in this environment (or has no role).',
            'Power Platform admin center > Environments > (this environment) > Settings >',
            'Users + permissions > Application users > New app user > add your app,',
            'then give it a read-only security role.'
        )
    }
}

# --- 6. Power Platform admin API (BAP) --------------------------------------------
$bapOk = $false
$bapTok = Get-Token 'https://api.bap.microsoft.com'
if ($bapTok) {
    try {
        Invoke-RestMethod -Uri 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01' -Headers @{ Authorization = "Bearer $bapTok" } | Out-Null
        $bapOk = $true
    } catch { $bapOk = $false }
}
Show $bapOk 'Power Platform admin API (environments, DLP, tenant settings)' @(
    'The app is not registered as a Power Platform management application.',
    'Run this once as an admin (any machine with PowerShell):',
    '  Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser',
    '  Add-PowerAppsAccount',
    "  New-PowerAppManagementApp -ApplicationId $cid"
)

# --- Summary ----------------------------------------------------------------------
Write-Host ''
if ($script:fails -eq 0) {
    Write-Host 'Setup looks complete. Starting the audit...' -ForegroundColor Green
} else {
    Write-Host "Setup incomplete: $($script:fails) item(s) need attention (fixes above)." -ForegroundColor Yellow
    Write-Host 'The audit will still run and will skip whatever it cannot read.' -ForegroundColor Yellow
}
Write-Host ''
return $true
