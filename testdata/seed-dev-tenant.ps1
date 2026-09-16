# seed-dev-tenant.ps1 - plants the fixture table from docs/dev-tenant-setup.md in a DEV/TEST tenant.
#
# ==========================================================================================
#   DEV/TEST TENANTS YOU OWN ONLY.
#   This script WRITES to a tenant and to an Azure subscription: it creates users, a guest
#   invitation, an app registration with a short-lived secret, a Conditional Access policy,
#   a PIM eligible assignment, and deliberately misconfigured Azure resources. It is NOT part
#   of the audit tool. The audit tool (run-audit.ps1 and everything under scripts/) stays
#   strictly read-only. Never run this against any tenant you do not own. The point is a
#   throwaway tenant in which every finding the audit can produce fires on demand.
# ==========================================================================================
#
# Each fixture maps to a finding in analyze.ps1 or a verdict in assessment-report.ps1; the
# script prints that mapping as it creates each one, mirroring the table in the docs.
#
#   Graph (device-code sign-in as the dev tenant's Global Administrator):
#     - three test users TestUser1-3 (random passwords, never shown, forced reset at sign-in)
#     - one guest invitation (-GuestEmail), no email sent unless -SendInvitationEmail
#     - app registration SecAudit-ExpiringSecret-Fixture with a 30-day secret (and a 1-day one)
#     - one Conditional Access policy requiring MFA for all users, state enabled, with the
#       signed-in admin excluded so you cannot lock yourself out. Security defaults must be
#       off for CA to be allowed; this script never toggles them, it prints the manual step.
#     - one PIM ELIGIBLE assignment for TestUser1 on a least-privilege role (Global Reader).
#       PIM writes need the delegated scope RoleManagement.ReadWrite.Directory, an Entra ID
#       P2 licence in the tenant, and a Global Administrator or Privileged Role Administrator.
#   ARM (device-code sign-in to Azure Resource Manager, needs Owner or Contributor):
#     - resource group; an Azure SQL logical server with NO database (no cost) with public
#       network access and the allow-all-Azure-IPs firewall rule (0.0.0.0 to 0.0.0.0);
#       an NSG with an inbound allow rule from any source to port 3389; a standard Key Vault
#       on legacy access policies (enableRbacAuthorization false) with public network access.
#
# Authentication: interactive device-code flow in pure REST (POST /oauth2/v2.0/devicecode,
# then poll /oauth2/v2.0/token) using Microsoft's well-known first-party public client ids,
# which exist in every tenant:
#   14d82eec-204b-4c2f-b7e8-296a70dab67e  Microsoft Graph PowerShell  (Graph delegated scopes)
#   1950a258-227b-4e31-a9cf-717495945fc2  Azure PowerShell            (ARM user_impersonation)
# Why those: a fresh tenant has no app of ours to sign in with, and creating one is itself an
# admin write, so a person signs in through a client that already exists everywhere and
# consents to the delegated scopes in the browser.
#
# Requirements: Windows PowerShell 5.1 or PowerShell 7. No modules, no az CLI.
# Behaviour: fails soft per fixture with a warning, reuses objects that already exist by name,
# and ends with a summary of what was created, reused, failed, or still needs a manual step.

param(
    [string]$GuestEmail,                          # required unless -SkipGuest: an address you control
    [switch]$SkipGuest,
    [switch]$SendInvitationEmail,
    [string]$SubscriptionId,                      # default: the only enabled subscription, or a prompt
    [string]$ResourceGroup = 'rg-secaudit-fixtures',
    [string]$Location = 'eastus',
    [string]$Tenant = 'organizations',            # tenant id or verified domain; 'organizations' = pick at sign-in
    [string]$UsageLocation = 'US',
    [string]$FixtureAppName = 'SecAudit-ExpiringSecret-Fixture',
    [int]$FixtureSecretDays = 30,
    [string]$CaPolicyName = 'SecAudit fixture - require MFA for all users',
    [string]$PimRole = 'Global Reader',
    [string]$PimEligibilityDuration = 'PT8H',     # ISO 8601; the eligibility itself expires after this
    [switch]$SkipGraph,
    [switch]$SkipAzure,
    [switch]$Yes                                  # skip the "type yes" confirmation
)

if (-not $SkipGuest -and -not $GuestEmail) { throw 'Pass -GuestEmail <an address you control> for the guest fixture, or -SkipGuest.' }

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GraphClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph PowerShell (first-party public client)
$ArmClientId   = '1950a258-227b-4e31-a9cf-717495945fc2'   # Azure PowerShell (first-party public client)
$GraphScopes   = @(
    'https://graph.microsoft.com/User.ReadWrite.All',                     # test users
    'https://graph.microsoft.com/User.Invite.All',                        # guest invitation
    'https://graph.microsoft.com/Application.ReadWrite.All',              # fixture app + secret
    'https://graph.microsoft.com/Policy.Read.All',                        # security defaults state, CA create
    'https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess',     # CA create
    'https://graph.microsoft.com/RoleManagement.ReadWrite.Directory',     # PIM eligibility request + role definitions
    'https://graph.microsoft.com/Directory.Read.All',                     # verified domains
    'offline_access'
) -join ' '
$ArmScopes = 'https://management.azure.com/user_impersonation offline_access'

$script:Created = @(); $script:Reused = @(); $script:Failed = @(); $script:Manual = @(); $script:Fixtures = @()
function Add-Created($text) { $script:Created += $text; Write-Host "  created: $text" -ForegroundColor Green }
function Add-Reused($text)  { $script:Reused  += $text; Write-Host "  reused:  $text" -ForegroundColor Yellow }
function Add-Failed($text)  { $script:Failed  += $text; Write-Warning $text }
function Add-Manual($text)  { $script:Manual  += $text }
function Add-Fixture($what, $fires) { $script:Fixtures += [pscustomobject]@{ Fixture = $what; Fires = $fires }; Write-Host "  expected in the audit: $fires" -ForegroundColor DarkCyan }

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

# Eventual consistency: a just-created object can 404 in Graph for a while. Retry only on that.
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

# Random password with all four character classes; used for objects nobody signs in to.
function New-RandomPassword([int]$Length = 20) {
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#%^*-_=+')
    $all = $sets -join ''
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] $Length
    $rng.GetBytes($bytes)
    $chars = @()
    for ($i = 0; $i -lt $Length; $i++) {
        $set = $all; if ($i -lt $sets.Count) { $set = $sets[$i] }
        $chars += $set[([int]$bytes[$i]) % $set.Length]
    }
    return -join (Get-Random -InputObject $chars -Count $chars.Count)
}

function New-RandomSuffix { return (-join ((1..6) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })) }

Write-Host 'Seed fixtures into a DEV/TEST tenant (this script WRITES to the tenant and to Azure)' -ForegroundColor Cyan
$tenantId = $null; $signedIn = $null; $me = $null; $testUsers = @{}

# =========================== Graph fixtures ===============================================
if ($SkipGraph) { Write-Host 'Graph fixtures: skipped (-SkipGraph)' -ForegroundColor Yellow }
else {
    Write-Host 'Sign-in 1 of 2: Microsoft Graph, as the Global Administrator of the dev tenant...' -ForegroundColor Cyan
    $graphTok = Get-DeviceCodeToken -ClientId $GraphClientId -Scope $GraphScopes -TenantOrAlias $Tenant -Label 'Microsoft Graph'
    $script:GraphToken = $graphTok.access_token
    $tenantId = Get-JwtClaim $script:GraphToken 'tid'
    $signedIn = Get-JwtClaim $script:GraphToken 'upn'
    if (-not $signedIn) { $signedIn = Get-JwtClaim $script:GraphToken 'preferred_username' }
    try { $me = Invoke-Graph 'me?$select=id,userPrincipalName' } catch { Write-Warning "  could not read the signed-in user: $(Get-ErrorText $_)" }
    $orgName = ''; $domain = $null
    try {
        $org = @((Invoke-Graph 'organization?$select=id,displayName,verifiedDomains').value)[0]
        $orgName = "$($org.displayName)"
        $domain = "$(@($org.verifiedDomains | Where-Object { $_.isDefault -eq $true })[0].name)"
        if (-not $domain) { $domain = "$(@($org.verifiedDomains)[0].name)" }
    } catch { Add-Failed "Could not read the tenant's verified domains: $(Get-ErrorText $_)" }
    Write-Host "  signed in as $signedIn" -ForegroundColor Yellow
    Write-Host "  tenant $tenantId $orgName (default domain: $domain)" -ForegroundColor Yellow
    if (-not $Yes) {
        Write-Host ''
        Write-Host 'This will CREATE users, an app, a CA policy and a PIM assignment in that tenant. Continue only if it is a dev/test tenant you own.' -ForegroundColor Red
        if ((Read-Host 'Type yes to continue') -ne 'yes') { Write-Host 'Stopped. Nothing was changed.' -ForegroundColor Yellow; return }
    }

    # --- A. Test users ------------------------------------------------------------------
    Write-Host 'Graph: test users TestUser1-3...' -ForegroundColor Cyan
    if (-not $domain) { Add-Failed 'Test users skipped: no verified domain to build a UPN with.' }
    else {
        for ($n = 1; $n -le 3; $n++) {
            $nick = "testuser$n"
            try {
                $found = @((Invoke-Graph "users?`$filter=startswith(userPrincipalName,'${nick}@')&`$select=id,userPrincipalName,displayName").value)
                if ($found.Count -gt 0) { $testUsers[$n] = $found[0]; Add-Reused "user $($found[0].userPrincipalName)"; continue }
                $u = Invoke-Graph -Method POST -Uri 'users' -Body @{
                    accountEnabled = $true; displayName = "Test User $n"; mailNickname = $nick; userPrincipalName = "${nick}@$domain"
                    usageLocation = $UsageLocation
                    passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = (New-RandomPassword) }
                }
                $testUsers[$n] = $u
                Add-Created "user $($u.userPrincipalName) (random password, not shown; reset it in the admin center if you ever need it)"
            } catch { Add-Failed "Test user $nick failed: $(Get-ErrorText $_)" }
        }
        Add-Fixture 'test users' 'no finding on their own; TestUser1 is the PIM principal and all three fall under the CA policy'
    }

    # --- B. Guest invitation --------------------------------------------------------------
    if ($SkipGuest) { Write-Host 'Graph: guest invitation skipped (-SkipGuest)' -ForegroundColor Yellow }
    else {
        Write-Host "Graph: guest invitation for $GuestEmail..." -ForegroundColor Cyan
        try {
            $existingGuest = @((Invoke-Graph "users?`$filter=mail eq '$($GuestEmail.Replace("'", "''"))'&`$select=id,userPrincipalName,userType").value)
            if ($existingGuest.Count -gt 0) { Add-Reused "guest $($existingGuest[0].userPrincipalName)" }
            else {
                $inv = Invoke-Graph -Method POST -Uri 'invitations' -Body @{
                    invitedUserEmailAddress = $GuestEmail; inviteRedirectUrl = 'https://myapplications.microsoft.com'
                    sendInvitationMessage = [bool]$SendInvitationEmail; invitedUserDisplayName = 'SecAudit Guest Fixture'
                }
                $mailNote = 'no email sent'; if ($SendInvitationEmail) { $mailNote = 'invitation email sent' }
                Add-Created "guest invitation for $GuestEmail (status $($inv.status), $mailNote)"
            }
            Add-Fixture 'one guest account' 'analyze: guest count (MEDIUM); guest domains in the report'
        } catch { Add-Failed "Guest invitation failed: $(Get-ErrorText $_)" }
    }

    # --- C. App registration with a secret expiring soon (and one expiring tomorrow) -------
    Write-Host "Graph: app registration '$FixtureAppName' with a $FixtureSecretDays-day secret..." -ForegroundColor Cyan
    try {
        $fx = @((Invoke-Graph "applications?`$filter=displayName eq '$($FixtureAppName.Replace("'", "''"))'").value)[0]
        if ($fx) { Add-Reused "app registration '$FixtureAppName'" }
        else {
            $fx = Invoke-Graph -Method POST -Uri 'applications' -Body @{ displayName = $FixtureAppName; signInAudience = 'AzureADMyOrg'; notes = 'SecAudit fixture: secrets expiring soon. Safe to delete.' }
            Add-Created "app registration '$FixtureAppName'"
        }
        $creds = @($fx.passwordCredentials)
        $now = Get-Date
        $soon = @($creds | Where-Object { $_.endDateTime -and [datetime]$_.endDateTime -gt $now.AddDays(2) -and [datetime]$_.endDateTime -lt $now.AddDays(60) }).Count
        $tomorrow = @($creds | Where-Object { $_.endDateTime -and [datetime]$_.endDateTime -gt $now -and [datetime]$_.endDateTime -le $now.AddDays(2) }).Count
        if ($soon -gt 0) { Add-Reused "secret expiring within 60 days already on '$FixtureAppName'" }
        else {
            $end = $now.ToUniversalTime().AddDays($FixtureSecretDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $pw = Invoke-WithRetry -What 'addPassword' -Action { Invoke-Graph -Method POST -Uri "applications/$($fx.id)/addPassword" -Body @{ passwordCredential = @{ displayName = "fixture-expires-in-$FixtureSecretDays-days"; endDateTime = $end } } }
            Add-Created "secret on '$FixtureAppName' expiring $($pw.endDateTime) (value discarded on purpose)"
        }
        # Graph refuses a past endDateTime, so the "already expired" fixture is a 1-day secret
        # that turns into the expired finding the day after you run this.
        if ($tomorrow -gt 0) { Add-Reused "1-day secret already on '$FixtureAppName'" }
        else {
            $end1 = $now.ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $pw1 = Invoke-WithRetry -What 'addPassword' -Action { Invoke-Graph -Method POST -Uri "applications/$($fx.id)/addPassword" -Body @{ passwordCredential = @{ displayName = 'fixture-expires-tomorrow'; endDateTime = $end1 } } }
            Add-Created "secret on '$FixtureAppName' expiring $($pw1.endDateTime) (becomes the expired-credential fixture tomorrow)"
        }
        Add-Fixture "app secrets expiring in $FixtureSecretDays days and in 1 day" 'analyze: credentials expiring within 60 days (LOW) now; expired credentials (MEDIUM) and 6.2 = Gap from tomorrow'
    } catch { Add-Failed "Fixture app failed: $(Get-ErrorText $_)" }

    # --- D. Conditional Access: require MFA for all users --------------------------------
    Write-Host "Graph: Conditional Access policy '$CaPolicyName'..." -ForegroundColor Cyan
    try {
        $sdOn = $null
        try { $sdOn = [bool](Invoke-Graph 'policies/identitySecurityDefaultsEnforcementPolicy').isEnabled } catch { Write-Warning "  could not read security defaults: $(Get-ErrorText $_)" }
        if ($sdOn -eq $true) {
            Write-Host '  skipped: security defaults are ON, and Conditional Access cannot coexist with them' -ForegroundColor Yellow
            Add-Manual 'Turn security defaults off yourself (entra.microsoft.com > Overview > Properties > Manage security defaults > Disabled), then re-run this script for the CA policy. This script never toggles security defaults.'
        } else {
            $policies = @((Invoke-Graph 'identity/conditionalAccess/policies').value)
            $existingCa = @($policies | Where-Object { $_.displayName -eq $CaPolicyName })[0]
            if ($existingCa) { Add-Reused "CA policy '$CaPolicyName' (state $($existingCa.state))" }
            else {
                $exclude = @(); if ($me -and $me.id) { $exclude = @("$($me.id)") }
                $ca = Invoke-Graph -Method POST -Uri 'identity/conditionalAccess/policies' -Body @{
                    displayName = $CaPolicyName
                    state = 'enabled'
                    conditions = @{
                        users = @{ includeUsers = @('All'); excludeUsers = $exclude }
                        applications = @{ includeApplications = @('All') }
                        clientAppTypes = @('all')
                    }
                    grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
                }
                Add-Created "CA policy '$CaPolicyName' (enabled; $signedIn is excluded so you cannot lock yourself out)"
            }
            Add-Fixture 'CA policy requiring MFA for all users' '1.4 = Aligned; analyze CA finding (LOW). Every other user must register MFA at next sign-in.'
        }
    } catch { Add-Failed "CA policy failed (needs Entra ID P1 and security defaults off): $(Get-ErrorText $_)" }

    # --- E. PIM eligible assignment for TestUser1 -----------------------------------------
    # Needs RoleManagement.ReadWrite.Directory (delegated), Entra ID P2 in the tenant, and a
    # Global Administrator or Privileged Role Administrator signing in. Eligible, not active:
    # the user must activate it, which is what "just-in-time" means and what 2.3 looks for.
    Write-Host "Graph: PIM eligible assignment for TestUser1 on '$PimRole' (expires after $PimEligibilityDuration)..." -ForegroundColor Cyan
    if (-not $testUsers.ContainsKey(1)) { Add-Failed 'PIM fixture skipped: TestUser1 does not exist.' }
    else {
        try {
            $roleDef = @((Invoke-Graph "roleManagement/directory/roleDefinitions?`$filter=displayName eq '$($PimRole.Replace("'", "''"))'").value)[0]
            if (-not $roleDef) { throw "role definition '$PimRole' not found" }
            $principal = "$($testUsers[1].id)"
            $existingElig = @((Invoke-Graph "roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$principal' and roleDefinitionId eq '$($roleDef.id)'").value)
            if ($existingElig.Count -gt 0) { Add-Reused "PIM eligibility for TestUser1 on '$PimRole'" }
            else {
                $req = Invoke-WithRetry -What 'PIM request' -Action {
                    Invoke-Graph -Method POST -Uri 'roleManagement/directory/roleEligibilityScheduleRequests' -Body @{
                        action = 'adminAssign'
                        justification = 'SecAudit fixture: eligible (just-in-time) assignment so pim-eligible.json is not empty'
                        roleDefinitionId = "$($roleDef.id)"; directoryScopeId = '/'; principalId = $principal
                        scheduleInfo = @{
                            startDateTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                            expiration = @{ type = 'afterDuration'; duration = $PimEligibilityDuration }
                        }
                    }
                }
                Add-Created "PIM eligibility request $($req.id) (status $($req.status)) for TestUser1 on '$PimRole'"
            }
            Add-Fixture "PIM eligible assignment ($PimEligibilityDuration)" '2.3 = Aligned (eligible > 0); pim-eligible.json has one entry. Run the audit before the eligibility expires, or pass a longer -PimEligibilityDuration such as P30D.'
        } catch { Add-Failed "PIM fixture failed (needs Entra ID P2 and a Global Administrator or Privileged Role Administrator): $(Get-ErrorText $_)" }
    }
}

# =========================== Azure fixtures ===============================================
if ($SkipAzure) { Write-Host 'Azure fixtures: skipped (-SkipAzure)' -ForegroundColor Yellow }
else {
    Write-Host 'Sign-in 2 of 2: Azure Resource Manager (same admin; needs Owner or Contributor on the subscription)...' -ForegroundColor Cyan
    $armTenant = $Tenant; if ($tenantId) { $armTenant = $tenantId }
    $script:ArmToken = $null
    try { $script:ArmToken = (Get-DeviceCodeToken -ClientId $ArmClientId -Scope $ArmScopes -TenantOrAlias $armTenant -Label 'Azure Resource Manager').access_token }
    catch { Add-Failed "Azure sign-in failed: $($_.Exception.Message)" }
    if (-not $tenantId -and $script:ArmToken) { $tenantId = Get-JwtClaim $script:ArmToken 'tid' }

    $sub = $null
    if ($script:ArmToken) {
        $subs = @()
        try { $subs = @((Invoke-Arm 'https://management.azure.com/subscriptions?api-version=2020-01-01').value | Where-Object { $_.state -eq 'Enabled' }) } catch { Add-Failed "Could not list subscriptions: $(Get-ErrorText $_)" }
        if ($SubscriptionId) {
            $sub = @($subs | Where-Object { $_.subscriptionId -eq $SubscriptionId })[0]
            if (-not $sub) { Add-Failed "Subscription $SubscriptionId is not visible to you or not enabled." }
        } elseif ($subs.Count -eq 1) { $sub = $subs[0] }
        elseif ($subs.Count -eq 0) { Add-Failed 'No enabled Azure subscription is visible to this admin. Create the free account first (docs/dev-tenant-setup.md step 4).' }
        else {
            Write-Host '  subscriptions visible to you:' -ForegroundColor Yellow
            for ($i = 0; $i -lt $subs.Count; $i++) { Write-Host ("    [{0}] {1}  {2}" -f ($i + 1), $subs[$i].subscriptionId, $subs[$i].displayName) }
            $pick = Read-Host '  Plant the Azure fixtures in which one? Enter a number, or blank to skip'
            if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $subs.Count) { $sub = $subs[[int]$pick - 1] }
        }
    }

    if ($sub) {
        $sid = $sub.subscriptionId
        $base = "https://management.azure.com/subscriptions/$sid"
        $rgBase = "$base/resourceGroups/$ResourceGroup"
        Write-Host "  using subscription $($sub.displayName) ($sid)" -ForegroundColor Yellow
        if (-not $Yes -and $SkipGraph) {
            Write-Host 'This will CREATE Azure resources in that subscription. Continue only if it is a dev/test subscription you own.' -ForegroundColor Red
            if ((Read-Host 'Type yes to continue') -ne 'yes') { Write-Host 'Stopped. Nothing was changed in Azure.' -ForegroundColor Yellow; $sub = $null }
        }
    }

    if ($sub) {
        # Resource providers must be registered once per subscription before the first PUT
        # of that type; the portal and CLI do this silently, raw REST does not.
        Write-Host 'ARM: resource providers (Microsoft.Sql, Microsoft.Network, Microsoft.KeyVault)...' -ForegroundColor Cyan
        foreach ($ns in @('Microsoft.Sql', 'Microsoft.Network', 'Microsoft.KeyVault')) {
            try {
                $p = Invoke-Arm "$base/providers/${ns}?api-version=2021-04-01"
                if ("$($p.registrationState)" -eq 'Registered') { Write-Host "  $ns already registered" -ForegroundColor Yellow; continue }
                Invoke-Arm -Method POST -Uri "$base/providers/$ns/register?api-version=2021-04-01" | Out-Null
                for ($w = 0; $w -lt 12; $w++) {
                    Start-Sleep -Seconds 10
                    $p = Invoke-Arm "$base/providers/${ns}?api-version=2021-04-01"
                    if ("$($p.registrationState)" -eq 'Registered') { break }
                }
                Write-Host "  $ns registration state: $($p.registrationState)" -ForegroundColor Yellow
            } catch { Add-Failed "Provider $ns registration failed: $(Get-ErrorText $_)" }
        }

        # --- Resource group ------------------------------------------------------------------
        Write-Host "ARM: resource group $ResourceGroup in $Location..." -ForegroundColor Cyan
        $rgOk = $false
        try {
            $rgExists = $false
            try { Invoke-Arm "${rgBase}?api-version=2021-04-01" | Out-Null; $rgExists = $true } catch {}
            if ($rgExists) { Add-Reused "resource group $ResourceGroup" }
            else {
                Invoke-Arm -Method PUT -Uri "${rgBase}?api-version=2021-04-01" -Body @{ location = $Location; tags = @{ purpose = 'secaudit-fixtures'; 'delete-when-done' = 'yes' } } | Out-Null
                Add-Created "resource group $ResourceGroup"
            }
            $rgOk = $true
        } catch { Add-Failed "Resource group failed: $(Get-ErrorText $_)" }

        if ($rgOk) {
            # --- Azure SQL logical server: public access + allow-all-Azure-IPs rule -------------
            # A logical server with no database costs nothing. The portal's "Allow Azure services
            # and resources to access this server" toggle is exactly the 0.0.0.0-0.0.0.0 rule below.
            Write-Host 'ARM: Azure SQL logical server (no database) with public access and the allow-all-Azure-IPs rule...' -ForegroundColor Cyan
            try {
                $servers = @((Invoke-Arm "$rgBase/providers/Microsoft.Sql/servers?api-version=2021-11-01").value)
                $srv = @($servers | Where-Object { $_.name -like 'secaudit-fixture-*' })[0]
                if ($srv) { Add-Reused "SQL server $($srv.name)" }
                else {
                    $srvName = "secaudit-fixture-$(New-RandomSuffix)"
                    Invoke-Arm -Method PUT -Uri "$rgBase/providers/Microsoft.Sql/servers/${srvName}?api-version=2021-11-01" -Body @{
                        location = $Location
                        properties = @{
                            administratorLogin = 'secauditadmin'; administratorLoginPassword = (New-RandomPassword 24)
                            version = '12.0'; publicNetworkAccess = 'Enabled'; minimalTlsVersion = '1.2'
                        }
                    } | Out-Null
                    # The PUT returns 202 while the server provisions; wait for state Ready before
                    # touching firewall rules.
                    $srv = $null
                    for ($w = 0; $w -lt 30; $w++) {
                        Start-Sleep -Seconds 10
                        try { $srv = Invoke-Arm "$rgBase/providers/Microsoft.Sql/servers/${srvName}?api-version=2021-11-01" } catch { $srv = $null }
                        if ($srv -and "$($srv.properties.state)" -eq 'Ready') { break }
                    }
                    if (-not $srv -or "$($srv.properties.state)" -ne 'Ready') { throw "server $srvName did not reach state Ready within 5 minutes" }
                    Add-Created "SQL server $srvName (admin password random and discarded; no database, no cost)"
                }
                $rules = @((Invoke-Arm "$rgBase/providers/Microsoft.Sql/servers/$($srv.name)/firewallRules?api-version=2021-11-01").value)
                if (@($rules | Where-Object { $_.properties.startIpAddress -eq '0.0.0.0' -and $_.properties.endIpAddress -eq '0.0.0.0' }).Count -gt 0) { Add-Reused "firewall rule AllowAllWindowsAzureIps on $($srv.name)" }
                else {
                    Invoke-Arm -Method PUT -Uri "$rgBase/providers/Microsoft.Sql/servers/$($srv.name)/firewallRules/AllowAllWindowsAzureIps?api-version=2021-11-01" -Body @{ properties = @{ startIpAddress = '0.0.0.0'; endIpAddress = '0.0.0.0' } } | Out-Null
                    Add-Created "firewall rule AllowAllWindowsAzureIps (0.0.0.0 to 0.0.0.0) on $($srv.name)"
                }
                Add-Fixture 'SQL server with public network access and the allow-all-Azure-IPs rule' 'analyze: public network access enabled (HIGH) and allows all Azure IPs 0.0.0.0 (HIGH); 3.1 shows minimum TLS 1.2 enforced'
            } catch { Add-Failed "SQL fixture failed: $(Get-ErrorText $_)" }

            # --- NSG with RDP open to the internet ----------------------------------------------
            Write-Host 'ARM: network security group with an inbound allow rule from any source to port 3389...' -ForegroundColor Cyan
            try {
                $nsgName = 'nsg-secaudit-fixture'
                $nsg = $null
                try { $nsg = Invoke-Arm "$rgBase/providers/Microsoft.Network/networkSecurityGroups/${nsgName}?api-version=2023-05-01" } catch { $nsg = $null }
                $hasRule = $false
                if ($nsg) { $hasRule = (@($nsg.properties.securityRules | Where-Object { $_.properties.direction -eq 'Inbound' -and $_.properties.access -eq 'Allow' -and "$($_.properties.destinationPortRange)" -eq '3389' -and "$($_.properties.sourceAddressPrefix)" -eq '*' }).Count -gt 0) }
                if ($nsg -and $hasRule) { Add-Reused "NSG $nsgName with the open RDP rule" }
                else {
                    Invoke-Arm -Method PUT -Uri "$rgBase/providers/Microsoft.Network/networkSecurityGroups/${nsgName}?api-version=2023-05-01" -Body @{
                        location = $Location
                        properties = @{ securityRules = @(@{
                            name = 'secaudit-fixture-allow-rdp-from-internet'
                            properties = @{
                                priority = 100; direction = 'Inbound'; access = 'Allow'; protocol = 'Tcp'
                                sourceAddressPrefix = '*'; sourcePortRange = '*'; destinationAddressPrefix = '*'; destinationPortRange = '3389'
                                description = 'SecAudit fixture. Attached to nothing. Delete with the resource group.'
                            }
                        }) }
                    } | Out-Null
                    Add-Created "NSG $nsgName with inbound allow from any source to port 3389 (attached to nothing, no cost)"
                }
                Add-Fixture 'NSG rule allowing any source to port 3389' 'analyze: NSG opens port 3389 to the internet (HIGH)'
            } catch { Add-Failed "NSG fixture failed: $(Get-ErrorText $_)" }

            # --- Key Vault on legacy access policies with public network access -----------------
            Write-Host 'ARM: Key Vault on legacy access policies with public network access...' -ForegroundColor Cyan
            try {
                $vaults = @((Invoke-Arm "$rgBase/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01").value)
                $kv = @($vaults | Where-Object { $_.name -like 'kv-secaudit-*' })[0]
                if ($kv) { Add-Reused "Key Vault $($kv.name)" }
                else {
                    $kvName = "kv-secaudit-$(New-RandomSuffix)"
                    Invoke-Arm -Method PUT -Uri "$rgBase/providers/Microsoft.KeyVault/vaults/${kvName}?api-version=2022-07-01" -Body @{
                        location = $Location
                        properties = @{
                            tenantId = $tenantId; sku = @{ family = 'A'; name = 'standard' }
                            accessPolicies = @(); enableRbacAuthorization = $false; publicNetworkAccess = 'Enabled'
                            softDeleteRetentionInDays = 7
                        }
                    } | Out-Null
                    Add-Created "Key Vault $kvName (access-policy model, public network access, soft-delete 7 days, no purge protection)"
                }
                Add-Fixture 'Key Vault on access policies (not RBAC) with public network access' 'analyze: legacy access policies (MEDIUM), public network access (MEDIUM)'
            } catch { Add-Failed "Key Vault fixture failed: $(Get-ErrorText $_)" }
        }
    }
}

# =========================== Summary ======================================================
Write-Host ''
Write-Host '==================== SEED SUMMARY ====================' -ForegroundColor Green
foreach ($c in $script:Created) { Write-Host "  created  $c" -ForegroundColor Green }
foreach ($r in $script:Reused)  { Write-Host "  reused   $r" -ForegroundColor Yellow }
foreach ($f in $script:Failed)  { Write-Host "  FAILED   $f" -ForegroundColor Red }
if ($script:Manual.Count -gt 0) {
    Write-Host ''
    Write-Host 'Needs a manual step:' -ForegroundColor Cyan
    foreach ($m in $script:Manual) { Write-Host "  - $m" -ForegroundColor Yellow }
}
if ($script:Fixtures.Count -gt 0) {
    Write-Host ''
    Write-Host 'Fixtures in place and what the audit should say about them:' -ForegroundColor Cyan
    $script:Fixtures | Format-Table Fixture, Fires -AutoSize -Wrap
}
Write-Host 'Fixtures that are "do nothing" in a fresh tenant (already true unless you changed them):' -ForegroundColor Cyan
Write-Host '  - no custom Dataverse security roles:       1.2 and 5.1 Gap; analyze zero custom roles (MEDIUM)'
Write-Host '  - Dataverse auditing off in an environment: 4.1 Gap or Partial; analyze auditing OFF (HIGH)'
Write-Host '  - no environment security group:            1.3 and 2.4 Gap'
Write-Host '  - no DLP policy:                            5.3 Gap; default environment NOT covered'
Write-Host '  - all Defender for Cloud plans on Free:     7.2 MANUAL with "all plans Free"'
Write-Host ''
Write-Host 'Now run ./run-audit.ps1 and compare output/assessment-report.md and output/FINDINGS-summary.json with the table in docs/dev-tenant-setup.md.' -ForegroundColor Green
Write-Host 'Tear down when done: delete the resource group, the fixture app, the test users and the CA policy (docs/dev-tenant-setup.md step 8).' -ForegroundColor Green
Write-Host 'Seed done.' -ForegroundColor Green
