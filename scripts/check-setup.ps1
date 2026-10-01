# check-setup.ps1 - preflight doctor. Verifies the read-only app registration is fully
# set up, and for anything that is not, prints exactly where to click to fix it. It also
# resolves the scope of the run (parameters > scope.json > .env; blank = everything the app
# can read), checks every selection against what the app can actually see, prints the
# effective scope and writes it to output/scope-effective.json for the sweeps and the report.
#
# Read-only: each probe is a single tiny GET ($top=1, a singleton, or a list the sweeps read
# anyway). Nothing is changed. Outputs $true when the audit can proceed (even partially -
# sweeps fail soft), or $false when it cannot start at all (no .env values, the app cannot
# sign in, an unreadable scope file, or -StrictScope with an invisible selection).
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

# --- 3. The scope selection is readable (parameters > scope.json > .env) -----------
$scope = $null
try { $scope = Get-ScopeObject } catch {
    Show $false "Scope: $($_.Exception.Message)" @(
        'Fix the scope file (or the -Scope path) and re-run, or remove it to audit everything',
        'the app can read. Format: scope.example.json in the repo root.'
    )
    Write-Host ''
    Write-Host 'Cannot start with an unreadable scope: auditing the whole tenant when part of it was asked for is never done silently.' -ForegroundColor Yellow
    return $false
}
Show $true "Scope selection readable (source: $(Get-ScopeSourceText $scope))"

# --- 4. Graph application permissions, one probe each -----------------------------
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

# --- 5. Azure: which subscriptions can the app see, and which were selected? --------
$armTok = Get-Token 'https://management.azure.com'
$allSubs = @()
if ($armTok) {
    try {
        $r = Invoke-RestMethod -Uri 'https://management.azure.com/subscriptions?api-version=2020-01-01' -Headers @{ Authorization = "Bearer $armTok" }
        $allSubs = @($r.value)
    } catch { $allSubs = @() }
}
Show ($allSubs.Count -gt 0) "Azure: $($allSubs.Count) subscription(s) visible to the app" @(
    'The app has no Reader role on any subscription.',
    'Azure portal > Subscriptions > (pick one) > Access control (IAM) >',
    'Add > Add role assignment > Reader > select your app > Review + assign.'
)
$visSubs = @(Select-ScopedSubscriptions $scope $allSubs)
$invSubs = @(Get-ScopeInvisibleSubscriptions $scope $allSubs)
Set-ScopeField $scope.azure 'discoveredSubscriptions' $allSubs.Count
Set-ScopeField $scope.azure 'selectedVisible' @($visSubs | ForEach-Object { "$($_.subscriptionId)" })
Set-ScopeField $scope.azure 'selectedInvisible' $invSubs
foreach ($s in $invSubs) {
    Show $false "Azure: selected subscription '$s' is not visible to the app" @(
        'Give the app the Reader role on that subscription (Access control (IAM) > Add role assignment),',
        'or fix the id / display name in the scope. Its checks will read Not checked, never silently dropped.'
    )
}
# Resource groups only when some were selected: one list GET per visible selected subscription.
$rgSel = @(Get-ScopeItems $scope.azure.resourceGroups); $rgSeen = @{}; $rgTotal = 0; $rgInv = @()
if ($rgSel.Count -gt 0) {
    if ($armTok) {
        foreach ($sub in $visSubs) {
            try {
                $r = Invoke-Paged "https://management.azure.com/subscriptions/$($sub.subscriptionId)/resourcegroups?api-version=2021-04-01" @{ Authorization = "Bearer $armTok" } 'nextLink'
                $names = @(@($r) | ForEach-Object { "$($_.name)" })
                $rgTotal += $names.Count
                $hits = Select-ScopedResourceGroups $scope $names
                foreach ($g in @($hits)) { $rgSeen[$g.ToLower()] = $g }
            } catch { Write-Warning "  resource groups in $($sub.displayName) could not be listed: $($_.Exception.Message)" }
        }
    }
    $rgInv = @($rgSel | Where-Object { -not $rgSeen.ContainsKey($_.ToLower()) })
    Set-ScopeField $scope.azure 'discoveredResourceGroups' $rgTotal
    Set-ScopeField $scope.azure 'resourceGroupsVisible' @($rgSeen.Values)
    Set-ScopeField $scope.azure 'resourceGroupsInvisible' $rgInv
    Show ($rgInv.Count -eq 0) "Azure: $($rgSeen.Count) of $($rgSel.Count) selected resource group(s) found in the selected subscription(s)" @(
        "Not found: $($rgInv -join ', '). Check the names, or which subscription they live in;",
        'Reader on the group alone is enough for the SQL, Synapse, Key Vault, NSG, Log Analytics and Logic Apps readers.'
    )
}

# --- 6. Power Platform admin API (BAP): also the environment catalog for the scope --------
$bapOk = $false; $bapEnvs = @()
$bapTok = Get-Token 'https://api.bap.microsoft.com'
if ($bapTok) {
    try {
        $r = Invoke-Paged 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01' @{ Authorization = "Bearer $bapTok" } 'nextLink'
        $bapEnvs = @($r)
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

# --- 7. Dataverse: is the app an Application User in each environment in scope? -------
# With a selection, ids and display names resolve through the catalog just read; without one,
# both Dataverse sweeps cover every environment that has a Dataverse URL.
if ($bapOk) { $envRes = Resolve-ScopeEnvironments $scope -Catalog $bapEnvs } else { $envRes = Resolve-ScopeEnvironments $scope }
Set-ScopeField $scope.powerPlatform 'discoveredEnvironments' $envRes.discovered
Set-ScopeField $scope.powerPlatform 'resolved' @($envRes.environments)
Set-ScopeField $scope.powerPlatform 'unresolved' @($envRes.unresolved)
$envUrls = @(@($envRes.environments) | ForEach-Object { $_.url })
if ($envUrls.Count -eq 0) {
    Write-Host '  [--] Dataverse: no environment selected or discovered (both Dataverse sweeps will be skipped). Select with scope.json / -Environments / DATAVERSE_ENVIRONMENTS, or fix the Power Platform admin API item above.' -ForegroundColor DarkGray
} else {
    foreach ($envUrl in $envUrls) {
        $ok = $false
        $t = Get-Token $envUrl
        if ($t) {
            try { Invoke-RestMethod -Uri "$($envUrl.TrimEnd('/'))/api/data/v9.2/WhoAmI" -Headers @{ Authorization = "Bearer $t" } | Out-Null; $ok = $true } catch { $ok = $false }
        }
        Show $ok "Dataverse: $envUrl" @(
            'The app is not an Application User in this environment (or has no role).',
            'Power Platform admin center > Environments > (this environment) > Settings >',
            'Users + permissions > Application users > New app user > add your app,',
            'then give it a read-only security role (or run testdata/add-dataverse-app-user.ps1).',
            'Environments you do not audit can be left out with a scope (scope.json or -Environments).'
        )
    }
}
foreach ($u in @($envRes.unresolved)) {
    Show $false "Dataverse: selected environment '$u' was not found" @(
        'Use the environment instance URL (https://<org>.crm.dynamics.com), its environment id, or its exact',
        'display name; ids and display names resolve through the Power Platform admin API listing above.'
    )
}

# --- 8. Effective scope: what this run covers, written for the sweeps and the report ---
Write-Host ''
Write-Host "Effective scope (source: $(Get-ScopeSourceText $scope))" -ForegroundColor Cyan
if (-not $scope.partial) {
    Write-Host "  FULL: no selection configured. Everything the app can read: $($allSubs.Count) subscription(s), $($envRes.discovered) Dataverse environment(s); identity evidence tenant-wide." -ForegroundColor Green
} else {
    Write-Host "  Azure       $(Get-ScopeAzureText $scope)" -ForegroundColor Yellow
    Write-Host "  Dataverse   $(Get-ScopeDataverseText $scope)" -ForegroundColor Yellow
    Write-Host '  Identity    tenant-wide by nature, not scopeable' -ForegroundColor Yellow
    Write-Host '  The report is labelled PARTIAL; selections the app cannot see read Not checked, never dropped silently.' -ForegroundColor Yellow
}
$scopePath = Save-ScopeEffective $scope
Write-Host "  written to $scopePath" -ForegroundColor DarkGray
$blind = ($invSubs.Count -gt 0 -or $rgInv.Count -gt 0 -or @($envRes.unresolved).Count -gt 0)
if ($scope.strict -and $blind) {
    Write-Host ''
    Write-Host '-StrictScope: a selection is not visible to the app. Stopping before any sweep.' -ForegroundColor Red
    return $false
}

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
