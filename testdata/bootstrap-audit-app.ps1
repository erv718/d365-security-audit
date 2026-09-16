# bootstrap-audit-app.ps1 - creates the read-only audit app registration in a DEV/TEST tenant.
#
# ==========================================================================================
#   DEV/TEST TENANTS YOU OWN ONLY.
#   This script WRITES to a tenant: it creates an app registration, its service principal,
#   admin-consented Graph application permissions, a client secret, and Azure role
#   assignments. It is NOT part of the audit tool. The audit tool (run-audit.ps1 and
#   everything under scripts/) stays strictly read-only. Never run this against any tenant
#   you do not own. docs/dev-tenant-setup.md describes the clean-room tenant it is for.
# ==========================================================================================
#
# What it does, so a new user goes from an empty dev tenant to a filled .env in one step:
#   1. Device-code sign-in to Microsoft Graph as the dev tenant's Global Administrator.
#   2. App registration SecAudit-ReadOnly (reused if it exists) declaring the seven Microsoft
#      Graph APPLICATION permissions from docs/permissions.md. The app role ids are looked up
#      on the Microsoft Graph service principal, never hardcoded.
#   3. Its service principal, then admin consent = one appRoleAssignment per permission
#      (principal = the new service principal, resource = the Microsoft Graph service principal).
#   4. A client secret (90 days by default), printed ONCE.
#   5. Device-code sign-in to Azure Resource Manager, pick subscriptions, assign Reader at
#      subscription scope, retrying through the replication lag a brand-new principal causes.
#   6. The .env block to paste, and the one step that cannot be automated from here.
#
# Authentication: interactive device-code flow in pure REST (POST /oauth2/v2.0/devicecode,
# then poll /oauth2/v2.0/token) using Microsoft's well-known first-party public client ids,
# which exist in every tenant:
#   14d82eec-204b-4c2f-b7e8-296a70dab67e  Microsoft Graph PowerShell  (Graph delegated scopes)
#   1950a258-227b-4e31-a9cf-717495945fc2  Azure PowerShell            (ARM user_impersonation)
# Why those: a brand-new tenant has no app of ours to sign in with, and registering one is
# itself an admin write, so the only way to bootstrap is a person signing in through a client
# that already exists everywhere. The admin consents to the delegated scopes in the browser.
#
# Requirements: Windows PowerShell 5.1 or PowerShell 7. No modules, no az CLI.
# Behaviour: fails soft per resource with a warning, reuses objects that already exist by
# name, and ends with a summary of what was created, reused, failed, or still needs a hand.

param(
    [string]$AppName = 'SecAudit-ReadOnly',
    [string]$Tenant = 'organizations',       # tenant id or verified domain; 'organizations' = pick at sign-in
    [string[]]$SubscriptionIds = @(),          # skip the prompt and assign Reader on exactly these
    [int]$SecretDays = 90,
    [switch]$SkipAzure,
    [switch]$Yes                               # skip the "type yes" confirmation
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GraphClientId      = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph PowerShell (first-party public client)
$ArmClientId        = '1950a258-227b-4e31-a9cf-717495945fc2'   # Azure PowerShell (first-party public client)
$GraphScopes        = 'https://graph.microsoft.com/Application.ReadWrite.All https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All https://graph.microsoft.com/Directory.Read.All offline_access'
$ArmScopes          = 'https://management.azure.com/user_impersonation offline_access'
$GraphResourceAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph, the API the permissions belong to
$ReaderRoleDefId    = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'   # Azure built-in role: Reader
$RequiredAppRoles   = @('Application.Read.All', 'RoleManagement.Read.Directory', 'User.Read.All', 'Policy.Read.All',
                        'AuditLog.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All')

$script:Created = @(); $script:Reused = @(); $script:Failed = @(); $script:Manual = @()
function Add-Created($text) { $script:Created += $text; Write-Host "  created: $text" -ForegroundColor Green }
function Add-Reused($text)  { $script:Reused  += $text; Write-Host "  reused:  $text" -ForegroundColor Yellow }
function Add-Failed($text)  { $script:Failed  += $text; Write-Warning $text }
function Add-Manual($text)  { $script:Manual  += $text }

# HTTP status text plus the response body: Graph and ARM put the real reason there.
function Get-ErrorText($ErrorRecord) {
    $msg = "$($ErrorRecord.Exception.Message)"
    $body = $null
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $body = $ErrorRecord.ErrorDetails.Message }
    elseif ($ErrorRecord.Exception.Response) {
        try { $stream = $ErrorRecord.Exception.Response.GetResponseStream(); if ($stream) { $body = (New-Object IO.StreamReader($stream)).ReadToEnd() } } catch {}
    }
    if ($body) {
        $body = ($body -replace '\s+', ' ').Trim()
        if ($body.Length -gt 600) { $body = $body.Substring(0, 600) + '...' }
        return "$msg $body"
    }
    return $msg
}

# Device-code sign-in: POST /devicecode, show the code, poll /token until the user finishes.
# authorization_pending = keep polling; slow_down = poll slower; anything else = stop.
function Get-DeviceCodeToken {
    param([Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$Scope, [string]$TenantOrAlias = 'organizations', [string]$Label = 'sign-in')
    $dc = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantOrAlias/oauth2/v2.0/devicecode" -Body @{ client_id = $ClientId; scope = $Scope }
    Write-Host ''
    Write-Host "  [$Label] $($dc.message)" -ForegroundColor Yellow
    Write-Host ''
    $interval = 5; if ($dc.interval) { $interval = [int]$dc.interval }
    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            return Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantOrAlias/oauth2/v2.0/token" -Body @{
                grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $ClientId; device_code = $dc.device_code
            }
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

# Read one claim (tid, upn, oid) out of the access token without any extra API call.
function Get-JwtClaim([string]$Token, [string]$Claim) {
    try {
        $payload = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
        return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json).$Claim
    } catch { return $null }
}

function Invoke-Graph {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body = $null)
    if ($Uri -notmatch '^https://') { $Uri = "https://graph.microsoft.com/v1.0/$Uri" }
    $headers = @{ Authorization = "Bearer $script:GraphToken" }
    if ($null -eq $Body) { return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers }
    $json = ConvertTo-Json -Depth 12 -InputObject $Body
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ([Text.Encoding]::UTF8.GetBytes($json)) -ContentType 'application/json'
}

function Invoke-Arm {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body = $null)
    $headers = @{ Authorization = "Bearer $script:ArmToken" }
    if ($null -eq $Body) { return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers }
    $json = ConvertTo-Json -Depth 12 -InputObject $Body
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ([Text.Encoding]::UTF8.GetBytes($json)) -ContentType 'application/json'
}

# Eventual consistency: a just-created object can 404 in Graph, and Azure RBAC answers
# 400 PrincipalNotFound until the new service principal has replicated. Retry only on those.
function Invoke-WithRetry {
    param([Parameter(Mandatory)][scriptblock]$Action, [int]$MaxTries = 6, [int]$DelaySeconds = 10,
          [string]$RetryOn = 'Request_ResourceNotFound|PrincipalNotFound|does not exist in the directory', [string]$What = 'call')
    for ($__try = 1; $__try -le $MaxTries; $__try++) {
        try { return (& $Action) }
        catch {
            $__err = Get-ErrorText $_
            if ($__try -lt $MaxTries -and $__err -match $RetryOn) {
                Write-Host "    $What not ready yet (replication), retry $__try of $MaxTries in ${DelaySeconds}s..." -ForegroundColor DarkGray
                Start-Sleep -Seconds $DelaySeconds
                continue
            }
            throw
        }
    }
}

Write-Host 'Bootstrap the read-only audit app in a DEV/TEST tenant (this script WRITES to the tenant)' -ForegroundColor Cyan

# --- 1. Sign in to Microsoft Graph ------------------------------------------------------
Write-Host 'Sign-in 1 of 2: Microsoft Graph, as the Global Administrator of the dev tenant...' -ForegroundColor Cyan
$graphTok = Get-DeviceCodeToken -ClientId $GraphClientId -Scope $GraphScopes -TenantOrAlias $Tenant -Label 'Microsoft Graph'
$script:GraphToken = $graphTok.access_token
$tenantId = Get-JwtClaim $script:GraphToken 'tid'
$signedIn = Get-JwtClaim $script:GraphToken 'upn'
if (-not $signedIn) { $signedIn = Get-JwtClaim $script:GraphToken 'preferred_username' }
$orgName = ''
try { $orgName = "$(@((Invoke-Graph 'organization?$select=id,displayName').value)[0].displayName)" } catch {}
Write-Host "  signed in as $signedIn" -ForegroundColor Yellow
Write-Host "  tenant $tenantId $orgName" -ForegroundColor Yellow
if (-not $Yes) {
    Write-Host ''
    Write-Host 'This will CREATE objects in that tenant. Continue only if it is a dev/test tenant you own.' -ForegroundColor Red
    if ((Read-Host 'Type yes to continue') -ne 'yes') { Write-Host 'Stopped. Nothing was changed.' -ForegroundColor Yellow; return }
}

# --- 2. App registration with the seven Graph application permissions -------------------
Write-Host "Graph: app registration '$AppName'..." -ForegroundColor Cyan
$app = $null
try {
    $existing = @((Invoke-Graph "applications?`$filter=displayName eq '$($AppName.Replace("'", "''"))'").value)
    if ($existing.Count -gt 0) { $app = $existing[0]; Add-Reused "app registration '$AppName' (appId $($app.appId))" }
} catch { Add-Failed "Could not look up existing app registrations: $(Get-ErrorText $_)" }

# The Microsoft Graph service principal carries the catalogue of app roles; resolve each
# permission name to its id there instead of hardcoding GUIDs.
$graphSp = $null; $roleIds = @{}
try {
    $graphSp = @((Invoke-Graph "servicePrincipals?`$filter=appId eq '$GraphResourceAppId'&`$select=id,appId,displayName,appRoles").value)[0]
    if (-not $graphSp) { throw 'Microsoft Graph service principal not found in this tenant' }
    foreach ($roleName in $RequiredAppRoles) {
        $role = @($graphSp.appRoles | Where-Object { $_.value -eq $roleName -and $_.allowedMemberTypes -contains 'Application' })[0]
        if ($role) { $roleIds[$roleName] = "$($role.id)" } else { Add-Failed "Graph application permission '$roleName' not found on the Microsoft Graph service principal" }
    }
    Write-Host "  resolved $($roleIds.Count) of $($RequiredAppRoles.Count) Graph application permission ids" -ForegroundColor Yellow
} catch { Add-Failed "Could not read the Microsoft Graph service principal: $(Get-ErrorText $_)" }

if (-not $app) {
    try {
        $access = @($roleIds.Values | ForEach-Object { @{ id = $_; type = 'Role' } })
        $body = @{
            displayName = $AppName
            signInAudience = 'AzureADMyOrg'
            notes = 'Read-only security audit app (d365-security-audit). Created by testdata/bootstrap-audit-app.ps1.'
            requiredResourceAccess = @(@{ resourceAppId = $GraphResourceAppId; resourceAccess = $access })
        }
        $app = Invoke-Graph -Method POST -Uri 'applications' -Body $body
        Add-Created "app registration '$AppName' (appId $($app.appId)) with $($access.Count) Graph permission(s) declared"
    } catch { Add-Failed "Create app registration failed: $(Get-ErrorText $_)" }
} elseif ($roleIds.Count -gt 0) {
    # Reused app: keep whatever it already declares and add only the Graph roles it is missing.
    try {
        $current = @($app.requiredResourceAccess)
        $graphEntry = @($current | Where-Object { $_.resourceAppId -eq $GraphResourceAppId })[0]
        $typeOf = @{}
        if ($graphEntry) { foreach ($ra in @($graphEntry.resourceAccess)) { $typeOf["$($ra.id)"] = "$($ra.type)" } }
        $missing = @($roleIds.Values | Where-Object { -not $typeOf.ContainsKey("$_") })
        if ($missing.Count -eq 0) { Write-Host '  app manifest already declares all seven Graph permissions' -ForegroundColor Yellow }
        else {
            $allIds = @($typeOf.Keys) + $missing
            $access = @($allIds | ForEach-Object { $t = 'Role'; if ($typeOf.ContainsKey("$_")) { $t = $typeOf["$_"] }; @{ id = "$_"; type = $t } })
            $others = @($current | Where-Object { $_.resourceAppId -ne $GraphResourceAppId } | ForEach-Object {
                @{ resourceAppId = $_.resourceAppId; resourceAccess = @($_.resourceAccess | ForEach-Object { @{ id = "$($_.id)"; type = "$($_.type)" } }) } })
            Invoke-Graph -Method PATCH -Uri "applications/$($app.id)" -Body @{ requiredResourceAccess = @($others + @(@{ resourceAppId = $GraphResourceAppId; resourceAccess = $access })) } | Out-Null
            Add-Created "$($missing.Count) missing Graph permission(s) declared on the reused app"
        }
    } catch { Add-Failed "Update app permissions failed: $(Get-ErrorText $_)" }
}

# --- 3. Service principal + admin consent -------------------------------------------------
$sp = $null
if ($app) {
    Write-Host 'Graph: service principal (the Enterprise Application)...' -ForegroundColor Cyan
    try {
        $sp = @((Invoke-Graph "servicePrincipals?`$filter=appId eq '$($app.appId)'").value)[0]
        if ($sp) { Add-Reused "service principal $($sp.id)" }
        else {
            $sp = Invoke-WithRetry -What 'service principal create' -Action { Invoke-Graph -Method POST -Uri 'servicePrincipals' -Body @{ appId = $app.appId } }
            Add-Created "service principal $($sp.id)"
        }
    } catch { Add-Failed "Service principal failed: $(Get-ErrorText $_)" }
}

if ($sp -and $graphSp -and $roleIds.Count -gt 0) {
    # Admin consent for application permissions IS an appRoleAssignment: the client service
    # principal is granted the app role defined on the Microsoft Graph service principal.
    Write-Host 'Graph: admin consent (app role assignments on the Microsoft Graph service principal)...' -ForegroundColor Cyan
    $existingAsn = @()
    try { $existingAsn = @((Invoke-Graph "servicePrincipals/$($sp.id)/appRoleAssignments").value) } catch { Write-Warning "  could not list existing assignments: $(Get-ErrorText $_)" }
    $granted = 0
    foreach ($roleName in $RequiredAppRoles) {
        if (-not $roleIds.ContainsKey($roleName)) { continue }
        $rid = $roleIds[$roleName]
        if (@($existingAsn | Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -eq $rid }).Count -gt 0) { Write-Host "  already consented: $roleName" -ForegroundColor Yellow; continue }
        try {
            Invoke-WithRetry -What "consent $roleName" -Action { Invoke-Graph -Method POST -Uri "servicePrincipals/$($sp.id)/appRoleAssignments" -Body @{ principalId = $sp.id; resourceId = $graphSp.id; appRoleId = $rid } } | Out-Null
            Write-Host "  consented: $roleName" -ForegroundColor Green
            $granted++
        } catch { Add-Failed "Admin consent for $roleName failed: $(Get-ErrorText $_)" }
    }
    if ($granted -gt 0) { Add-Created "$granted admin-consented Graph application permission(s)" }
}

# --- 4. Client secret --------------------------------------------------------------------
$secret = $null
if ($app) {
    Write-Host "Graph: client secret ($SecretDays days)..." -ForegroundColor Cyan
    $existingSecrets = @($app.passwordCredentials).Count
    if ($existingSecrets -gt 0) { Write-Host "  $existingSecrets existing secret(s) left in place; a new one is added because their values cannot be read back" -ForegroundColor Yellow }
    try {
        $end = (Get-Date).ToUniversalTime().AddDays($SecretDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $pw = Invoke-WithRetry -What 'addPassword' -Action { Invoke-Graph -Method POST -Uri "applications/$($app.id)/addPassword" -Body @{ passwordCredential = @{ displayName = "audit $(Get-Date -Format yyyy-MM-dd)"; endDateTime = $end } } }
        $secret = $pw.secretText
        Add-Created "client secret '$($pw.displayName)' expiring $($pw.endDateTime)"
    } catch { Add-Failed "Client secret failed: $(Get-ErrorText $_)" }
}

# --- 5. Azure: Reader on the chosen subscriptions -----------------------------------------
$chosenSubs = @()
function Grant-ReaderOnSubscription($sub) {
    $sid = $sub.subscriptionId; $scope = "/subscriptions/$sid"
    $roleDef = "$scope/providers/Microsoft.Authorization/roleDefinitions/$ReaderRoleDefId"
    try {
        $have = @((Invoke-Arm "https://management.azure.com$scope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$($sp.id)'").value)
        if (@($have | Where-Object { "$($_.properties.roleDefinitionId)" -like "*$ReaderRoleDefId" -and "$($_.properties.scope)" -eq $scope }).Count -gt 0) { Add-Reused "Reader on subscription $($sub.displayName)"; return }
        $assignmentName = [guid]::NewGuid().ToString()
        # A brand-new service principal takes a moment to replicate into Azure RBAC; the first
        # PUT can fail with 400 PrincipalNotFound. principalType shortens that window. Retry
        # for up to about 2 minutes (12 x 10s).
        Invoke-WithRetry -What 'role assignment' -MaxTries 12 -DelaySeconds 10 -RetryOn 'PrincipalNotFound' -Action {
            Invoke-Arm -Method PUT -Uri "https://management.azure.com$scope/providers/Microsoft.Authorization/roleAssignments/${assignmentName}?api-version=2022-04-01" -Body @{
                properties = @{ roleDefinitionId = $roleDef; principalId = $sp.id; principalType = 'ServicePrincipal' }
            }
        } | Out-Null
        Add-Created "Reader on subscription $($sub.displayName) ($sid)"
    } catch { Add-Failed "Reader on subscription $($sub.displayName) failed: $(Get-ErrorText $_)" }
}

if ($SkipAzure) { Write-Host 'Azure: skipped (-SkipAzure)' -ForegroundColor Yellow }
elseif (-not $sp) { Add-Manual 'Azure Reader not assigned because the service principal does not exist. Fix the Graph steps above, then re-run, or assign Reader by hand (docs/permissions.md section 3).' }
else {
    Write-Host 'Sign-in 2 of 2: Azure Resource Manager (same admin; needs Owner or User Access Administrator on the subscriptions)...' -ForegroundColor Cyan
    $script:ArmToken = $null
    try { $script:ArmToken = (Get-DeviceCodeToken -ClientId $ArmClientId -Scope $ArmScopes -TenantOrAlias $tenantId -Label 'Azure Resource Manager').access_token }
    catch { Add-Failed "Azure sign-in failed: $($_.Exception.Message)" }
    if ($script:ArmToken) {
        $subs = @()
        try { $subs = @((Invoke-Arm 'https://management.azure.com/subscriptions?api-version=2020-01-01').value) } catch { Add-Failed "Could not list subscriptions: $(Get-ErrorText $_)" }
        if ($subs.Count -eq 0) { Add-Manual 'No Azure subscription is visible to this admin. Create the free account first (docs/dev-tenant-setup.md step 4), then assign Reader per docs/permissions.md section 3.' }
        elseif ($SubscriptionIds.Count -gt 0) { $chosenSubs = @($subs | Where-Object { $SubscriptionIds -contains $_.subscriptionId }) }
        else {
            Write-Host '  subscriptions visible to you:' -ForegroundColor Yellow
            for ($i = 0; $i -lt $subs.Count; $i++) { Write-Host ("    [{0}] {1}  {2}  ({3})" -f ($i + 1), $subs[$i].subscriptionId, $subs[$i].displayName, $subs[$i].state) }
            $pick = Read-Host '  Assign Reader on which? Numbers separated by commas, "all", or blank to skip'
            if ($pick -eq 'all') { $chosenSubs = $subs }
            elseif ($pick) {
                foreach ($n in ($pick -split ',')) {
                    $n = $n.Trim()
                    if ($n -match '^\d+$' -and [int]$n -ge 1 -and [int]$n -le $subs.Count) { $chosenSubs += $subs[[int]$n - 1] }
                }
            }
        }
        foreach ($s in $chosenSubs) { Grant-ReaderOnSubscription $s }
        if ($chosenSubs.Count -eq 0 -and $subs.Count -gt 0) { Add-Manual 'No subscription chosen: assign Reader by hand when ready (docs/permissions.md section 3).' }
    }
}

# --- 6. Summary, .env block, manual steps -------------------------------------------------
Write-Host ''
Write-Host '==================== BOOTSTRAP SUMMARY ====================' -ForegroundColor Green
foreach ($c in $script:Created) { Write-Host "  created  $c" -ForegroundColor Green }
foreach ($r in $script:Reused)  { Write-Host "  reused   $r" -ForegroundColor Yellow }
foreach ($f in $script:Failed)  { Write-Host "  FAILED   $f" -ForegroundColor Red }
if ($app) {
    Write-Host ''
    Write-Host 'Paste this into .env. Copy the secret NOW: it is shown once and cannot be read back.' -ForegroundColor Cyan
    Write-Host "TENANT_ID=$tenantId"
    Write-Host "CLIENT_ID=$($app.appId)"
    if ($secret) { Write-Host "CLIENT_SECRET=$secret" } else { Write-Host 'CLIENT_SECRET=<secret creation failed: add one under Certificates & secrets and paste it here>' }
    if ($chosenSubs.Count -gt 0) { Write-Host "AZURE_SUBSCRIPTIONS=$(@($chosenSubs | ForEach-Object { $_.subscriptionId }) -join ',')" }
}
Write-Host ''
Write-Host 'Steps that cannot be automated from here:' -ForegroundColor Cyan
Write-Host '  1. Register the app as a Power Platform management application. This needs Windows'
Write-Host '     PowerShell 5.1 and an interactive sign-in as a Power Platform admin (the module does'
Write-Host '     not load in PowerShell 7):'
Write-Host '       Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser'
Write-Host '       Add-PowerAppsAccount'
$appIdText = '<CLIENT_ID>'; if ($app) { $appIdText = $app.appId }
Write-Host "       New-PowerAppManagementApp -ApplicationId $appIdText"
Write-Host '  2. Add the app as an Application User with a read-only role in each Dataverse environment'
Write-Host '     (docs/permissions.md section 4) and list those environment URLs in DATAVERSE_ENVIRONMENTS.'
foreach ($m in $script:Manual) { Write-Host "  - $m" -ForegroundColor Yellow }
Write-Host ''
Write-Host 'Then verify: pwsh ./scripts/check-setup.ps1  (or powershell.exe -File scripts/check-setup.ps1)' -ForegroundColor Green
Write-Host 'Bootstrap done.' -ForegroundColor Green
