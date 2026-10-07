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
# [OK] = ready, [ X] = needs a fix (the audit still runs and skips what it cannot read),
# [ !] = optional or least-privilege note (never counted as a failure).
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
$script:notes = 0
function Note {
    param([string]$Label, [string[]]$Fix = @())
    Write-Host "  [ !] $Label" -ForegroundColor Yellow
    foreach ($line in $Fix) { Write-Host "       $line" -ForegroundColor DarkYellow }
    $script:notes++
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
    $ok = $true; $why = ''
    try { Invoke-RestMethod -Uri $p.url -Headers $H | Out-Null } catch { $ok = $false; $why = Get-ErrorText $_ }
    if (-not $ok -and $why -match 'not applicable to target tenant') {
        # The permission is fine; the tenant has no Intune. Checks 1.5 and 1.6 read Gap from that.
        Note "Graph permission $($p.perm) is held, but Intune is not provisioned in this tenant (checks 1.5 and 1.6 read Gap)"
        continue
    }
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

# --- 4b. Least privilege for the audit app itself ---------------------------------------
# Lists the application permissions the app holds (Application.Read.All covers this read) and
# names any the audit never uses. Delegated permissions are ignored: the app signs in as itself.
$needed = @($probes | ForEach-Object { $_.perm })
try {
    $self = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$cid')?`$select=id" -Headers $H
    $held = Invoke-Paged "https://graph.microsoft.com/v1.0/servicePrincipals/$($self.id)/appRoleAssignments" $H
    $resCache = @{}; $extra = @()
    foreach ($a in @($held)) {
        $rid = "$($a.resourceId)"
        if (-not $resCache.ContainsKey($rid)) {
            $res = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($rid)?`$select=appId,displayName,appRoles" -Headers $H
            $byId = @{}; foreach ($ar in @($res.appRoles)) { $byId["$($ar.id)"] = "$($ar.value)" }
            $resCache[$rid] = @{ appId = "$($res.appId)"; name = "$($res.displayName)"; roles = $byId }
        }
        $rc = $resCache[$rid]
        $value = $rc.roles["$($a.appRoleId)"]
        if (-not $value) { $value = "$($a.appRoleId)" }
        if ($rc.appId -eq '00000003-0000-0000-c000-000000000000' -and $needed -contains $value) { continue }
        $extra += "$value ($($rc.name))"
    }
    if ($extra.Count) {
        Note "The app also holds permission(s) the audit never uses: $($extra -join ', ')" @(
            'Least privilege: take them away. Entra portal > App registrations > your app > API permissions >',
            'on each of those rows: ... > Revoke admin consent, then ... > Remove permission.'
        )
    }
} catch {}

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

# --- 6. Power Platform admin API (BAP): environments, DLP, tenant settings ----------------
# Microsoft's only route for an app to read these is registering it as a Power Platform
# management application, which gives it the rights of a Power Platform Administrator (granular
# roles "can't be assigned to limit their capabilities"; the read-only Power Platform reader role
# does not cover the environment list). The audit itself still only reads. With environments
# selected, the Dataverse checks run without it, so it is optional; with none selected, it is how
# the audit finds them.
$bapOk = $false; $bapEnvs = @()
$bapTok = Get-Token 'https://api.bap.microsoft.com'
if ($bapTok) {
    try {
        $r = Invoke-Paged 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01' @{ Authorization = "Bearer $bapTok" } 'nextLink'
        $bapEnvs = @($r)
        $bapOk = $true
    } catch { $bapOk = $false }
}
$bapHow = @(
    'Microsoft offers one way: register the app as a Power Platform management app. That gives the app',
    'the rights of a Power Platform Administrator (not read-only; the audit still only reads), so',
    'register right before the run and remove it right after. In Windows PowerShell 5.1, as an admin:',
    '  Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser',
    '  Add-PowerAppsAccount',
    "  New-PowerAppManagementApp -ApplicationId $cid",
    "  (after the run)  Remove-PowerAppManagementApp -ApplicationId $cid"
)
if ($bapOk) { Show $true 'Power Platform admin API (environments, DLP, tenant settings)' }
elseif (@(Get-ScopeItems $scope.powerPlatform.environments).Count -gt 0) {
    Note 'Power Platform admin API not readable (optional): DLP policies, tenant settings and the environment list are skipped' (@(
        'Checks 1.3, 2.4 and 5.3 read Not checked; confirm them in the Power Platform admin center, or:') + $bapHow)
} else {
    Show $false 'Power Platform admin API (environments, DLP, tenant settings)' (@(
        'No Dataverse environment is selected, so this is how the audit finds them. Either select them:',
        '  ./run-audit.ps1 -Environments https://<org>.crm.dynamics.com   (several: comma-separated)',
        'or let the audit read the environment list, DLP policies and tenant settings:') + $bapHow)
}

# --- 7. Dataverse: is the app an Application User in each environment in scope? -------
# With a selection, ids and display names resolve through the catalog just read; without one,
# both Dataverse sweeps cover every environment that has a Dataverse URL.
# Without the admin API there is no discovery this run; an earlier run's URL list is not used.
if ($bapOk) { $envRes = Resolve-ScopeEnvironments $scope -Catalog $bapEnvs } else { $envRes = Resolve-ScopeEnvironments $scope -Catalog @() }
Set-ScopeField $scope.powerPlatform 'discoveredEnvironments' $envRes.discovered
Set-ScopeField $scope.powerPlatform 'resolved' @($envRes.environments)
Set-ScopeField $scope.powerPlatform 'unresolved' @($envRes.unresolved)
$envUrls = @(@($envRes.environments) | ForEach-Object { $_.url })
if ($envUrls.Count -eq 0) {
    Write-Host '  [--] Dataverse: no environment selected or discovered (both Dataverse sweeps will be skipped). Select with scope.json / -Environments / DATAVERSE_ENVIRONMENTS, or fix the Power Platform admin API item above.' -ForegroundColor DarkGray
} else {
    foreach ($envUrl in $envUrls) {
        $base = "$($envUrl.TrimEnd('/'))/api/data/v9.2/"
        $who = $null; $Hd = $null; $whoWhy = ''
        $t = Get-Token $envUrl
        if ($t) {
            $Hd = @{ Authorization = "Bearer $t"; Accept = 'application/json'; 'OData-Version' = '4.0' }
            try { $who = Invoke-RestMethod -Uri "${base}WhoAmI" -Headers $Hd } catch { $who = $null; $whoWhy = Get-ErrorText $_ }
        }
        foreach ($re in @($scope.powerPlatform.resolved)) { if ($re -and "$($re.url)".TrimEnd('/') -eq $envUrl.TrimEnd('/')) { Set-ScopeField $re 'reachable' ($null -ne $who); if ($null -eq $who) { Set-ScopeField $re 'reason' $(if ($t) { "WhoAmI failed: $whoWhy" } else { 'no token for this environment' }) } } }
        Show ($null -ne $who) "Dataverse: $envUrl" @(
            'The app is not an Application User in this environment (or has no role).',
            'Power Platform admin center > Environments > (this environment) > Settings >',
            'Users + permissions > Application users > New app user > add your app,',
            'then give it a read-only security role (docs/permissions.md, section 4).',
            'Environments you do not audit can be left out with a scope (scope.json or -Environments).'
        )
        if ($null -eq $who) { continue }

        # The app user's own roles (needs Read on User and Security Role; left out quietly if not).
        $roleNames = @()
        try {
            $me = Invoke-RestMethod -Uri "${base}systemusers($($who.UserId))?`$select=fullname&`$expand=systemuserroles_association(`$select=name)" -Headers $Hd
            $roleNames = @($me.systemuserroles_association | ForEach-Object { "$($_.name)" } | Where-Object { $_ })
        } catch {}

        # One row of every read the two Dataverse sweeps make, so a missing privilege shows up
        # here by table name instead of as a Not checked row after the run.
        $missing = @(); $other = @(); $envType = $null
        foreach ($k in @($script:DvReads.Keys)) {
            $rd = $script:DvReads[$k]
            try {
                $resp = Invoke-RestMethod -Uri "$base$(Get-DvProbePath $rd)" -Headers $Hd
                if ($k -eq 'orginfo' -and $resp.Detail) { $envType = ConvertTo-EnvSku $resp.Detail.OrganizationType }
            } catch {
                $why = Get-ErrorText $_
                $tbl = Get-DvMissingTable $why
                if ($tbl) { $missing += $tbl }
                elseif ($why -match '\b403\b' -and $rd.Tables) { $missing += @($rd.Tables -split ',\s*') }
                elseif ($why -match '\b403\b') { $missing += "whatever the $($rd.Label) read needs (Dataverse did not name it)" }
                else { if ($why.Length -gt 300) { $why = $why.Substring(0, 300) + '...' }; $other += "$($rd.Label): $why" }
            }
        }
        $missing = @($missing | Select-Object -Unique)
        $roleText = if ($roleNames.Count) { "role ($($roleNames -join ', '))" } else { 'security role' }
        Show ($missing.Count -eq 0) "Dataverse: the app user's $roleText can read everything the audit reads$(if($envType){" (environment type: $envType)"})" @(
            "Add Read at Organization level on: $($missing -join ', ')",
            'Power Platform admin center > Environments > (this environment) > Settings > Users + permissions >',
            "Security roles > (the app user's role) > find each table > Read = Organization > Save.",
            'Until then only the checks that need those tables read Not checked; the rest of the audit runs.'
        )
        foreach ($o in $other) { Note "Dataverse read failed (not a permission gap): $o" @('Only that check reads Not checked; the rest of the audit runs.') }
        $broad = @($roleNames | Where-Object { $_ -in 'System Administrator', 'System Customizer' })
        if ($broad.Count) { Note "The app user also holds $($broad -join ', '): far more than a read-only audit needs" @('Least privilege: keep only the custom read-only role (docs/permissions.md, section 4).') }
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
    Write-Host "Setup looks complete$(if($script:notes){" ($($script:notes) optional note(s) marked [ !] above)"}). Starting the audit..." -ForegroundColor Green
} else {
    Write-Host "Setup incomplete: $($script:fails) item(s) need attention (fixes above)." -ForegroundColor Yellow
    Write-Host 'The audit will still run and will skip whatever it cannot read.' -ForegroundColor Yellow
    Write-Host 'Stuck? docs/troubleshooting.md shows how to get help without sharing tenant data.' -ForegroundColor DarkGray
}
Write-Host ''
return $true
