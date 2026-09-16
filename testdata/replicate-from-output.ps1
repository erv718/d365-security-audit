# replicate-from-output.ps1 - recreates the STRUCTURAL SHAPE of a saved audit output folder in a
# DEV/TEST tenant, with 100% dummy identities.
#
# ==========================================================================================
#   DEV/TEST TENANTS YOU OWN ONLY.
#   With -Force this script WRITES to a tenant and to an Azure subscription: users, app
#   registrations with short-lived secrets, service principals holding risky Graph
#   application permissions, security groups, Conditional Access policies, named locations,
#   guest invitations, PIM eligibility, NSGs, SQL logical servers and Key Vaults. It is NOT
#   part of the audit tool. The audit tool (run-audit.ps1 and everything under scripts/)
#   stays strictly read-only. Never run this against any tenant you do not own.
#   Undo everything with testdata/teardown-replica.ps1.
# ==========================================================================================
#
# Privacy contract: the source folder is a real tenant's evidence. Only COUNTS and STATES are
# read from it (how many apps, how many expired secrets, how many NSGs open RDP, ...). No
# name, UPN, GUID, IP, email or domain ever crosses over. Every replica object is named by a
# counter (SecAuditReplica-App-001), guest domains become fake1.example.com, fake2..., named
# locations use the documentation range 203.0.113.0/24. The only source strings echoed are
# Microsoft constants: directory role names and environment SKUs.
#
# Default mode is a plan (-WhatIf): no sign-in, no writes. It reads the source folder,
# computes the shape, prints the plan table (counts only) and stops. Add -Force to build it.
#
# Authentication (with -Force): interactive device-code flow in pure REST using Microsoft's
# first-party public client ids, exactly as testdata/seed-dev-tenant.ps1 does:
#   14d82eec-204b-4c2f-b7e8-296a70dab67e  Microsoft Graph PowerShell  (Graph delegated scopes)
#   1950a258-227b-4e31-a9cf-717495945fc2  Azure PowerShell            (ARM user_impersonation)
#
# What Graph will not let a replica match, and how it is handled:
#   - addPassword refuses a past endDateTime: the "already expired" share becomes 1-day secrets
#     that turn into expired credentials the day after this runs; the "expiring within 60 days"
#     share becomes 30-day secrets.
#   - a SQL logical server cannot be created with publicNetworkAccess Disabled unless it has a
#     private endpoint: replica servers are all public; the allow-all-Azure-IPs share is kept.
#   - Conditional Access policies are created DISABLED (they can lock people out). The one
#     exception mirrors seed-dev-tenant.ps1: a single all-users MFA policy is created enabled
#     when the source had an enabled MFA policy, with the signed-in admin excluded.
#   - PIM needs Entra ID P2 in the dev tenant; without it that class is skipped with a note.
#
# Requirements: Windows PowerShell 5.1 or PowerShell 7. No modules, no az CLI.
# Behaviour: idempotent by name (re-runs reuse what exists), fails soft per object, summary at
# the end plus the list of what a replica cannot reproduce.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$SourceOutputDir,   # a saved audit output folder (the real tenant's run)
    [string]$SubscriptionId,                                   # default: the only enabled subscription, or a prompt
    [string]$ResourceGroup = 'rg-secaudit-replica',
    [string]$Location = 'eastus',
    [switch]$Force,                                            # without it: plan only, no sign-in, no writes
    [int]$MaxUsers = 25,
    [int]$MaxApps = 50,
    [int]$MaxAzurePerType = 10,
    [int]$MaxCaPolicies = 40,
    [int]$MaxNamedLocations = 40,
    [string]$Tenant = 'organizations',                         # tenant id or verified domain; 'organizations' = pick at sign-in
    [string]$UsageLocation = 'US',
    [string]$PimRole = 'Global Reader',
    [string]$PimEligibilityDuration = 'P30D',                  # ISO 8601; long enough to outlive an audit run
    [switch]$SkipGraph,
    [switch]$SkipAzure,
    [switch]$Yes                                               # skip the typed confirmation after sign-in
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$planOnly = (-not $Force) -or $WhatIfPreference

$GraphClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph PowerShell (first-party public client)
$ArmClientId   = '1950a258-227b-4e31-a9cf-717495945fc2'   # Azure PowerShell (first-party public client)
$GraphScopes   = @(
    'https://graph.microsoft.com/User.ReadWrite.All',                     # replica users
    'https://graph.microsoft.com/User.Invite.All',                        # guest invitations
    'https://graph.microsoft.com/Group.ReadWrite.All',                    # security groups
    'https://graph.microsoft.com/Application.ReadWrite.All',              # replica apps, secrets, service principals
    'https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All',        # risky app-role assignments (consent)
    'https://graph.microsoft.com/Policy.Read.All',                        # security defaults state, CA create
    'https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess',     # CA policies + named locations
    'https://graph.microsoft.com/RoleManagement.ReadWrite.Directory',     # PIM eligibility requests + role definitions
    'https://graph.microsoft.com/Directory.Read.All',                     # verified domains
    'offline_access'
) -join ' '
$ArmScopes = 'https://management.azure.com/user_impersonation offline_access'
$GraphResourceAppId = '00000003-0000-0000-c000-000000000000'
# Same list scripts/analyze.ps1 flags as high-privilege tenant-wide permissions.
$RiskyRoles = @('Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Directory.ReadWrite.All', 'Application.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'User.ReadWrite.All', 'Files.ReadWrite.All', 'Sites.FullControl.All', 'full_access_as_app')
$Prefix = 'SecAuditReplica'

$script:Created = @(); $script:Reused = @(); $script:Failed = @(); $script:Manual = @(); $script:Notes = @()
function Add-Created($text) { $script:Created += $text; Write-Host "  created: $text" -ForegroundColor Green }
function Add-Reused($text)  { $script:Reused  += $text; Write-Host "  reused:  $text" -ForegroundColor Yellow }
function Add-Failed($text)  { $script:Failed  += $text; Write-Warning $text }
function Add-Manual($text)  { $script:Manual  += $text }
function Add-Note($text)    { if ($script:Notes -notcontains $text) { $script:Notes += $text } }
function Expect($text)      { Write-Host "  expected in the audit: $text" -ForegroundColor DarkCyan }
function Name3($kind, $i)   { '{0}-{1}-{2:000}' -f $Prefix, $kind, $i }

# ---------------------------------------------------------------------------------------------
# Shared helpers (same as seed-dev-tenant.ps1)
# ---------------------------------------------------------------------------------------------
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

function Get-JwtClaim([string]$Token, [string]$Claim) {
    try {
        $payload = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
        return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json).$Claim
    } catch { return $null }
}

function Invoke-Graph {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body = $null, [switch]$Advanced)
    if ($Uri -notmatch '^https://') { $Uri = "https://graph.microsoft.com/v1.0/$Uri" }
    $headers = @{ Authorization = "Bearer $script:GraphToken" }
    if ($Advanced) { $headers['ConsistencyLevel'] = 'eventual' }
    if ($null -eq $Body) { return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers }
    $json = ConvertTo-Json -Depth 12 -InputObject $Body
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ([Text.Encoding]::UTF8.GetBytes($json)) -ContentType 'application/json'
}
function Invoke-GraphPaged([string]$Uri, [switch]$Advanced) {
    $items = @(); $next = $Uri
    while ($next) { $r = Invoke-Graph -Uri $next -Advanced:$Advanced; if ($r.value) { $items += @($r.value) }; $next = $r.'@odata.nextLink' }
    return ,$items
}
function Invoke-Arm {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body = $null)
    $headers = @{ Authorization = "Bearer $script:ArmToken" }
    if ($null -eq $Body) { return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers }
    $json = ConvertTo-Json -Depth 12 -InputObject $Body
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ([Text.Encoding]::UTF8.GetBytes($json)) -ContentType 'application/json'
}
function Invoke-ArmPaged([string]$Uri) {
    $items = @(); $next = $Uri
    while ($next) { $r = Invoke-Arm -Uri $next; if ($r.value) { $items += @($r.value) }; $next = $r.nextLink }
    return ,$items
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
function New-RandomSuffix([int]$n = 4) { return (-join ((1..$n) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })) }

# ---------------------------------------------------------------------------------------------
# 1. Shape extraction: counts and states only. Never names, UPNs, GUIDs, IPs or domains.
# ---------------------------------------------------------------------------------------------
if (-not (Test-Path $SourceOutputDir -PathType Container)) { throw "SourceOutputDir not found: $SourceOutputDir" }
$SourceOutputDir = (Resolve-Path $SourceOutputDir).Path

# Read one evidence file: missing, empty or unparseable = $null with a note; [] stays an array.
function Read-Source([string]$name) {
    $p = Join-Path $SourceOutputDir $name
    if (-not (Test-Path $p)) { return $null }
    try {
        $raw = Get-Content $p -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { Add-Note "$name is empty in the source"; return $null }
        $r = $raw | ConvertFrom-Json
        if ($null -eq $r) { Write-Output -NoEnumerate @() } else { Write-Output -NoEnumerate $r }
    } catch { Add-Note "$name could not be parsed in the source"; $null }
}
function Get-SourceFiles([string]$pattern) { @(Get-ChildItem $SourceOutputDir -Filter $pattern -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*-ERROR.json' }) }

Write-Host "Replica: reading the shape of $SourceOutputDir (counts and states only)..." -ForegroundColor Cyan
$shape = [ordered]@{}

# apps + credentials (credential-level counts, exactly what analyze.ps1 counts)
$srcApps = Read-Source 'applications.json'
if ($null -ne $srcApps) {
    $shape.apps = @($srcApps | Where-Object { $_ }).Count
    $now = Get-Date; $exp = 0; $soon = 0
    foreach ($a in @($srcApps)) {
        foreach ($c in @($a.passwordCredentials) + @($a.keyCredentials)) {
            if (-not $c.endDateTime) { continue }
            try { $d = [datetime]$c.endDateTime } catch { continue }
            if ($d -lt $now) { $exp++ } elseif ($d -lt $now.AddDays(60)) { $soon++ }
        }
    }
    $shape.expiredCreds = $exp; $shape.expiringCreds = $soon
} else { Add-Note 'applications.json unreadable: app, credential and risky-permission classes skipped' }

$srcSps = Read-Source 'servicePrincipals.json'
if ($null -ne $srcSps) { $shape.sps = @($srcSps | Where-Object { $_ }).Count }

# risky app-role assignments per role value (role values are Microsoft constants)
$srcDefs = Read-Source 'appRoleDefinitions-graph.json'; $srcAsn = Read-Source 'appRoleAssignments-graph.json'
$shape.risky = [ordered]@{}
if ($null -ne $srcDefs -and $null -ne $srcAsn) {
    $map = @{}; foreach ($d in @($srcDefs)) { if ($d.id) { $map["$($d.id)"] = "$($d.value)" } }
    foreach ($m in @($srcAsn)) {
        if (-not $m.appRoleId) { continue }
        $rn = $map["$($m.appRoleId)"]
        if ($rn -and $RiskyRoles -contains $rn) { if (-not $shape.risky.Contains($rn)) { $shape.risky[$rn] = 0 }; $shape.risky[$rn]++ }
    }
} else { Add-Note 'appRoleAssignments-graph.json or appRoleDefinitions-graph.json unreadable: risky-permission class skipped' }

# directory roles: role NAME -> member count (names are Microsoft constants; members never read)
$srcRoles = Read-Source 'directoryRoles.json'
$shape.roles = [ordered]@{}; $shape.roleMemberSum = 0
if ($null -ne $srcRoles) {
    foreach ($r in @($srcRoles | Where-Object { $_ -and $_.role })) { $n = 0; try { $n = [int]$r.memberCount } catch {}; $shape.roles["$($r.role)"] = $n; $shape.roleMemberSum += $n }
} else { Add-Note 'directoryRoles.json unreadable: user scale falls back to the minimum' }

# Conditional Access + named locations
$srcCa = Read-Source 'ca-policies.json'
if ($null -ne $srcCa) {
    $shape.caTotal   = @($srcCa | Where-Object { $_ }).Count
    $shape.caEnabled = @($srcCa | Where-Object { $_.state -eq 'enabled' }).Count
    $shape.caMfa     = @($srcCa | Where-Object { $_.state -eq 'enabled' -and $_.grantControls.builtInControls -contains 'mfa' }).Count
} else { Add-Note 'ca-policies.json unreadable: Conditional Access class skipped' }
$srcLoc = Read-Source 'ca-named-locations.json'
if ($null -ne $srcLoc) { $shape.namedLocations = @($srcLoc | Where-Object { $_ }).Count } else { Add-Note 'ca-named-locations.json unreadable: named-location class skipped' }

# guests: total + per-domain distribution as a sorted list of counts (domains are never kept)
$srcGc = Read-Source 'guest-count.json'; $srcGd = Read-Source 'guests-by-domain.json'
if ($null -ne $srcGd -and $null -ne $srcGd.byDomain) {
    $shape.guestDomainCounts = @(@($srcGd.byDomain | Where-Object { $_ }) | ForEach-Object { $n = 0; try { $n = [int]$_.count } catch {}; $n } | Where-Object { $_ -gt 0 } | Sort-Object -Descending)
    $shape.guests = 0; try { $shape.guests = [int]$srcGd.total } catch {}
    if ($shape.guests -eq 0) { $sum = ($shape.guestDomainCounts | Measure-Object -Sum).Sum; if ($null -ne $sum) { $shape.guests = [int]$sum } }
} elseif ($null -ne $srcGc -and $null -ne $srcGc.guestCount) {
    $shape.guests = 0; try { $shape.guests = [int]$srcGc.guestCount } catch {}
    $shape.guestDomainCounts = @(); if ($shape.guests -gt 0) { $shape.guestDomainCounts = @($shape.guests) }
    Add-Note 'guests-by-domain.json unreadable: all guests go to one fake domain'
} else { Add-Note 'guest-count.json and guests-by-domain.json unreadable: guest class skipped' }

# PIM
$srcPim = Read-Source 'pim-eligible.json'
if ($null -ne $srcPim) { $shape.pimEligible = @($srcPim | Where-Object { $_ }).Count }
elseif (Test-Path (Join-Path $SourceOutputDir 'pim-eligible-ERROR.json')) { Add-Note 'pim-eligible.json not readable in the source (licence or permission); PIM class skipped' }
else { Add-Note 'pim-eligible.json unreadable: PIM class skipped' }

# Azure, summed over every subscription file
$shape.subscriptions = @(Get-SourceFiles 'arm-*-rbac.json').Count
$shape.nsgs = $null; $shape.nsgOpen = 0
foreach ($f in (Get-SourceFiles 'arm-*-nsgs.json')) {
    $items = Read-Source $f.Name; if ($null -eq $items) { continue }
    if ($null -eq $shape.nsgs) { $shape.nsgs = 0 }
    foreach ($nsg in @($items | Where-Object { $_ })) {
        $shape.nsgs++
        $open = @($nsg.properties.securityRules | Where-Object { $p = $_.properties; $p.access -eq 'Allow' -and $p.direction -eq 'Inbound' -and $p.destinationPortRange -in '3389','22','*' -and $p.sourceAddressPrefix -in '*','0.0.0.0/0','Internet' }).Count
        if ($open -gt 0) { $shape.nsgOpen++ }
    }
}
$shape.sql = $null; $shape.sqlPublic = 0; $shape.sqlAllowAll = 0
foreach ($f in (Get-SourceFiles 'arm-*-sql.json')) {
    $items = Read-Source $f.Name; if ($null -eq $items) { continue }
    if ($null -eq $shape.sql) { $shape.sql = 0 }
    foreach ($srv in @($items | Where-Object { $_ })) {
        $shape.sql++
        if ($srv.properties.publicNetworkAccess -eq 'Enabled') { $shape.sqlPublic++ }
        if (@($srv._firewallRules | Where-Object { $_.properties.startIpAddress -eq '0.0.0.0' -and $_.properties.endIpAddress -eq '0.0.0.0' }).Count -gt 0) { $shape.sqlAllowAll++ }
    }
}
$shape.kv = $null; $shape.kvLegacy = 0; $shape.kvPublic = 0
foreach ($f in (Get-SourceFiles 'arm-*-keyvaults.json')) {
    $items = Read-Source $f.Name; if ($null -eq $items) { continue }
    if ($null -eq $shape.kv) { $shape.kv = 0 }
    foreach ($v in @($items | Where-Object { $_ })) {
        $shape.kv++
        if (-not $v.properties.enableRbacAuthorization) { $shape.kvLegacy++ }
        if ($v.properties.publicNetworkAccess -eq 'Enabled') { $shape.kvPublic++ }
    }
}
if ($null -eq $shape.nsgs -and $null -eq $shape.sql -and $null -eq $shape.kv) { Add-Note 'no arm-*.json in the source: Azure classes skipped' }

# Boundary information (what the source had that a replica cannot rebuild)
$shape.errorFiles = @(Get-ChildItem $SourceOutputDir -Filter '*-ERROR.json' -ErrorAction SilentlyContinue).Count
$srcSignins = Read-Source 'signins-sample.json'; if ($null -ne $srcSignins) { $shape.signins = @($srcSignins | Where-Object { $_ }).Count }
$srcEnv = Read-Source 'pp-environments.json'
if ($null -ne $srcEnv) {
    $shape.ppEnvironments = @($srcEnv | Where-Object { $_ }).Count
    $shape.ppSkus = (@($srcEnv | Where-Object { $_ } | Group-Object { "$($_.properties.environmentSku)" } | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" })) -join ', '
}
$shape.dataverseFiles = @(Get-SourceFiles 'dv-*.json').Count + @(Get-SourceFiles 'dvplus-*.json').Count
$shape.defenderStandard = 0
foreach ($f in (Get-SourceFiles 'arm-*-defender-pricings.json')) { $items = Read-Source $f.Name; if ($null -eq $items) { continue }; $shape.defenderStandard += @($items | Where-Object { "$($_.properties.pricingTier)" -eq 'Standard' }).Count }

# ---------------------------------------------------------------------------------------------
# 2. Plan: scale the shape into the caps
# ---------------------------------------------------------------------------------------------
function ScaleCount([int]$value, [int]$sourceTotal, [int]$planTotal) {
    if ($sourceTotal -le 0 -or $value -le 0) { return 0 }
    $n = [int][Math]::Round($value * ($planTotal / [double]$sourceTotal))
    if ($n -lt 1) { $n = 1 }
    if ($n -gt $planTotal) { $n = $planTotal }
    return $n
}
$plan = [ordered]@{}
$plan.apps = 0; $plan.expiring = 0; $plan.tomorrow = 0
if ($null -ne $shape.apps) {
    $plan.apps = [Math]::Min($shape.apps, $MaxApps)
    $plan.tomorrow = ScaleCount $shape.expiredCreds $shape.apps $plan.apps
    $plan.expiring = ScaleCount $shape.expiringCreds $shape.apps $plan.apps
}
$plan.risky = [ordered]@{}
foreach ($k in $shape.risky.Keys) { if ($k -eq 'full_access_as_app') { Add-Note 'full_access_as_app is an Exchange Online role; a replica can only grant Microsoft Graph roles, so that count is not reproduced'; continue }; $plan.risky[$k] = [Math]::Min([int]$shape.risky[$k], $plan.apps) }
$plan.groups = $plan.apps
$plan.pim = 0; if ($null -ne $shape.pimEligible) { $plan.pim = [Math]::Min($shape.pimEligible, $MaxUsers) }
$plan.users = [Math]::Min($MaxUsers, [Math]::Max(3, [Math]::Max($shape.roleMemberSum, $plan.pim)))
$plan.pim = [Math]::Min($plan.pim, $plan.users)
$plan.caTotal = 0; $plan.caEnabled = 0; $plan.caMfa = 0
if ($null -ne $shape.caTotal) {
    $plan.caTotal = [Math]::Min($shape.caTotal, $MaxCaPolicies)
    $plan.caEnabled = [Math]::Min($shape.caEnabled, $plan.caTotal)
    $plan.caMfa = [Math]::Min($shape.caMfa, $plan.caEnabled)
}
$plan.namedLocations = 0; if ($null -ne $shape.namedLocations) { $plan.namedLocations = [Math]::Min($shape.namedLocations, [Math]::Min($MaxNamedLocations, 250)) }
$plan.guestDomainCounts = @(); $plan.guests = 0
if ($null -ne $shape.guests) {
    $left = $MaxUsers
    foreach ($c in @($shape.guestDomainCounts)) { if ($left -le 0) { break }; $take = [Math]::Min($c, $left); $plan.guestDomainCounts += $take; $left -= $take }
    $plan.guests = ($plan.guestDomainCounts | Measure-Object -Sum).Sum; if ($null -eq $plan.guests) { $plan.guests = 0 }
}
$plan.nsgs = 0; $plan.nsgOpen = 0
if ($null -ne $shape.nsgs) { $plan.nsgs = [Math]::Min($shape.nsgs, $MaxAzurePerType); $plan.nsgOpen = ScaleCount $shape.nsgOpen $shape.nsgs $plan.nsgs }
$plan.sql = 0; $plan.sqlAllowAll = 0
if ($null -ne $shape.sql) { $plan.sql = [Math]::Min($shape.sql, $MaxAzurePerType); $plan.sqlAllowAll = ScaleCount $shape.sqlAllowAll $shape.sql $plan.sql }
$plan.kv = 0; $plan.kvLegacy = 0; $plan.kvPublic = 0
if ($null -ne $shape.kv) { $plan.kv = [Math]::Min($shape.kv, $MaxAzurePerType); $plan.kvLegacy = ScaleCount $shape.kvLegacy $shape.kv $plan.kv; $plan.kvPublic = ScaleCount $shape.kvPublic $shape.kv $plan.kv }

function Row($class, $source, $replica, $feeds) { [pscustomobject]@{ Class = $class; Source = $source; Replica = $replica; Feeds = $feeds } }
function NoneIf0([int]$n, [string]$text) { if ($n -gt 0) { return $text }; return 'none' }
$rows = @()
$rows += Row 'Users (dummy)' "role members sum $($shape.roleMemberSum)" "$($plan.users) (cap $MaxUsers)" 'PIM principals, CA'
if ($null -ne $shape.apps) {
    $rows += Row 'App registrations' "$($shape.apps)" (NoneIf0 $plan.apps "$($plan.apps) (cap $MaxApps)") '2.1, 2.2 inventory'
    $rows += Row 'Expired credentials' "$($shape.expiredCreds)" (NoneIf0 $plan.tomorrow "$($plan.tomorrow) x 1-day secret (expired tomorrow)") 'analyze MEDIUM; 6.2'
    $rows += Row 'Credentials expiring <60d' "$($shape.expiringCreds)" (NoneIf0 $plan.expiring "$($plan.expiring) x 30-day secret") 'analyze LOW'
} else { $rows += Row 'App registrations' 'not in source' 'skipped' '' }
if ($null -ne $shape.sps) { $rows += Row 'Service principals' "$($shape.sps) (incl. first-party)" (NoneIf0 $plan.apps "$($plan.apps) (one per replica app)") '2.2 count' }
if ($shape.risky.Count -gt 0) { foreach ($k in $shape.risky.Keys) { $r = 'not reproducible'; if ($plan.risky.Contains($k)) { $r = "$($plan.risky[$k]) app(s)" }; $rows += Row "Risky: $k" "$($shape.risky[$k]) app(s)" $r 'analyze HIGH; 2.1' } }
elseif ($null -ne $srcAsn -and $null -ne $srcDefs) { $rows += Row 'Risky permissions' '0' 'none' 'analyze App access' }
foreach ($k in $shape.roles.Keys) { $rows += Row "Role: $k" "$($shape.roles[$k]) member(s)" 'user scale only, not assigned' 'analyze Admin roles' }
if ($null -ne $shape.caTotal) {
    $caText = "$($plan.caTotal) ($(if($plan.caMfa -ge 1){'1 enabled MFA, admin excluded; '})rest disabled)"
    $rows += Row 'CA policies' "$($shape.caTotal) total, $($shape.caEnabled) enabled, $($shape.caMfa) MFA" (NoneIf0 $plan.caTotal $caText) '1.4; analyze CA'
}
if ($null -ne $shape.namedLocations) { $rows += Row 'Named locations' "$($shape.namedLocations)" (NoneIf0 $plan.namedLocations "$($plan.namedLocations) (203.0.113.x, cap $MaxNamedLocations)") 'identity-plus count' }
if ($null -ne $shape.guests) { $rows += Row 'Guests' "$($shape.guests) across $(@($shape.guestDomainCounts).Count) domain(s)" (NoneIf0 $plan.guests "$($plan.guests) across $(@($plan.guestDomainCounts).Count) fake domain(s) (cap $MaxUsers)") 'analyze Guests; top domains' }
if ($null -ne $shape.pimEligible) { $rows += Row 'PIM eligible' "$($shape.pimEligible)" (NoneIf0 $plan.pim "$($plan.pim) on $PimRole (needs P2)") '2.3' }
if ($shape.subscriptions -gt 0) { $rows += Row 'Azure subscriptions' "$($shape.subscriptions) with evidence" '1 (-SubscriptionId)' '' }
if ($null -ne $shape.nsgs) { $rows += Row 'NSGs' "$($shape.nsgs), $($shape.nsgOpen) open RDP/SSH" (NoneIf0 $plan.nsgs "$($plan.nsgs), $($plan.nsgOpen) open 3389 (cap $MaxAzurePerType)") 'analyze HIGH NSG' }
if ($null -ne $shape.sql) { $rows += Row 'SQL logical servers' "$($shape.sql), $($shape.sqlPublic) public, $($shape.sqlAllowAll) allow-all" (NoneIf0 $plan.sql "$($plan.sql) all public, $($plan.sqlAllowAll) allow-all (cap $MaxAzurePerType)") 'analyze HIGH SQL; 3.1' }
if ($null -ne $shape.kv) { $rows += Row 'Key Vaults' "$($shape.kv), $($shape.kvLegacy) access-policy, $($shape.kvPublic) public" (NoneIf0 $plan.kv "$($plan.kv), $($plan.kvLegacy) access-policy, $($plan.kvPublic) public (cap $MaxAzurePerType)") 'analyze MEDIUM KV' }

Write-Host ''
Write-Host "==================== REPLICA PLAN (source run had $($shape.errorFiles) *-ERROR.json) ====================" -ForegroundColor Green
$fmt = '  {0,-30} {1,-28} {2,-40} {3}'
Write-Host ($fmt -f 'Class', 'Source', 'Replica', 'Feeds') -ForegroundColor Cyan
Write-Host ($fmt -f '-----', '------', '-------', '-----') -ForegroundColor Cyan
foreach ($r in $rows) { Write-Host ($fmt -f $r.Class, $r.Source, $r.Replica, $r.Feeds) }
Write-Host ''
Write-Host 'Cannot be replicated (source had):' -ForegroundColor Cyan
Write-Host "  - sign-in logs: $(if($null -ne $shape.signins){"$($shape.signins) sampled sign-ins"}else{'not readable'}); a read-only system, no legacy-auth fixture possible from here"
Write-Host "  - Power Platform: $(if($null -ne $shape.ppEnvironments){"$($shape.ppEnvironments) environment(s) [$($shape.ppSkus)]"}else{'inventory not readable'}); creating environments is out of scope for a one-off"
Write-Host "  - Dataverse internals: $($shape.dataverseFiles) dv-*/dvplus-* file(s) (auditing, roles, solutions, mailboxes, queues) - not replicated"
Write-Host "  - Defender for Cloud: $($shape.defenderStandard) plan(s) on Standard in the source; a billing decision, the replica stays Free"
foreach ($n in $script:Notes) { Write-Host "  - $n" -ForegroundColor DarkGray }
Write-Host ''
if ($planOnly) {
    Write-Host 'Plan only: nothing was signed in to and nothing was written. Re-run with -Force to build it in a DEV/TEST tenant you own.' -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------------------------------------------
# 3. Build (-Force): Graph
# ---------------------------------------------------------------------------------------------
$tenantId = $null; $signedIn = $null; $me = $null; $domain = $null
$users = @{}; $apps = @{}
if ($SkipGraph) { Write-Host 'Graph replica: skipped (-SkipGraph)' -ForegroundColor Yellow }
else {
    Write-Host 'Sign-in 1 of 2: Microsoft Graph, as the Global Administrator of the DEV tenant...' -ForegroundColor Cyan
    $graphTok = Get-DeviceCodeToken -ClientId $GraphClientId -Scope $GraphScopes -TenantOrAlias $Tenant -Label 'Microsoft Graph'
    $script:GraphToken = $graphTok.access_token
    $tenantId = Get-JwtClaim $script:GraphToken 'tid'
    $signedIn = Get-JwtClaim $script:GraphToken 'upn'
    if (-not $signedIn) { $signedIn = Get-JwtClaim $script:GraphToken 'preferred_username' }
    try { $me = Invoke-Graph 'me?$select=id,userPrincipalName' } catch { Write-Warning "  could not read the signed-in user: $(Get-ErrorText $_)" }
    $orgName = ''
    try {
        $org = @((Invoke-Graph 'organization?$select=id,displayName,verifiedDomains').value)[0]
        $orgName = "$($org.displayName)"
        $domain = "$(@($org.verifiedDomains | Where-Object { $_.isDefault -eq $true })[0].name)"
        if (-not $domain) { $domain = "$(@($org.verifiedDomains)[0].name)" }
    } catch { Add-Failed "Could not read the tenant's verified domains: $(Get-ErrorText $_)" }
    Write-Host "  signed in as $signedIn" -ForegroundColor Yellow
    Write-Host "  TARGET TENANT: $orgName ($tenantId), default domain $domain" -ForegroundColor Yellow
    if (-not $Yes) {
        Write-Host ''
        Write-Host "This will CREATE $($plan.users) users, $($plan.apps) apps, groups, CA policies, guests and PIM eligibility in that tenant. Continue only if it is a dev/test tenant you own." -ForegroundColor Red
        if ((Read-Host 'Type replicate to continue') -ne 'replicate') { Write-Host 'Stopped. Nothing was changed.' -ForegroundColor Yellow; return }
    }

    # --- users -----------------------------------------------------------------------------
    Write-Host "Graph: $($plan.users) replica users..." -ForegroundColor Cyan
    $userPrefix = 'secauditreplica-user-'
    if (-not $domain) { Add-Failed 'Users skipped: no verified domain to build UPNs with.' }
    else {
        try {
            foreach ($u in (Invoke-GraphPaged "users?`$filter=startswith(userPrincipalName,'$userPrefix')&`$select=id,userPrincipalName&`$top=999")) {
                if ($u.userPrincipalName -match "^$userPrefix(\d{3})@") { $users[[int]$Matches[1]] = $u }
            }
        } catch { Add-Failed "Could not list existing replica users: $(Get-ErrorText $_)" }
        $made = 0
        for ($i = 1; $i -le $plan.users; $i++) {
            if ($users.ContainsKey($i)) { continue }
            $nick = '{0}{1:000}' -f $userPrefix, $i
            try {
                $u = Invoke-Graph -Method POST -Uri 'users' -Body @{
                    accountEnabled = $true; displayName = ('{0} User {1:000}' -f $Prefix, $i); mailNickname = $nick; userPrincipalName = "$nick@$domain"
                    usageLocation = $UsageLocation
                    passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = (New-RandomPassword) }
                }
                $users[$i] = $u; $made++
            } catch { Add-Failed "User $nick failed: $(Get-ErrorText $_)" }
        }
        if ($made -gt 0) { Add-Created "$made replica user(s)" }
        if ($users.Count - $made -gt 0) { Add-Reused "$($users.Count - $made) replica user(s)" }
        Expect 'no finding by themselves; PIM principals and CA subjects'
    }

    # --- app registrations + credentials -------------------------------------------------------
    Write-Host "Graph: $($plan.apps) replica app registrations..." -ForegroundColor Cyan
    $appPrefix = "$Prefix-App-"
    try {
        foreach ($a in (Invoke-GraphPaged "applications?`$filter=startswith(displayName,'$appPrefix')&`$select=id,appId,displayName,passwordCredentials&`$top=999")) {
            if ($a.displayName -match "^$appPrefix(\d{3})$") { $apps[[int]$Matches[1]] = $a }
        }
    } catch { Add-Failed "Could not list existing replica apps: $(Get-ErrorText $_)" }
    $made = 0
    for ($i = 1; $i -le $plan.apps; $i++) {
        if ($apps.ContainsKey($i)) { continue }
        $nm = Name3 'App' $i
        try {
            $a = Invoke-Graph -Method POST -Uri 'applications' -Body @{ displayName = $nm; signInAudience = 'AzureADMyOrg'; notes = 'SecAudit replica fixture (dummy). Safe to delete: testdata/teardown-replica.ps1.' }
            $apps[$i] = $a; $made++
        } catch { Add-Failed "App $nm failed: $(Get-ErrorText $_)" }
    }
    if ($made -gt 0) { Add-Created "$made replica app registration(s)" }
    if ($apps.Count - $made -gt 0) { Add-Reused "$($apps.Count - $made) replica app registration(s)" }

    if ($plan.apps -gt 0 -and ($plan.tomorrow -gt 0 -or $plan.expiring -gt 0)) {
        Write-Host "Graph: secrets ($($plan.tomorrow) expiring tomorrow, $($plan.expiring) expiring in 30 days)..." -ForegroundColor Cyan
        # Round-robin over the apps: app 1 gets the first secret of each kind, and so on.
        $needTomorrow = @{}; $needSoon = @{}
        for ($k = 1; $k -le $plan.tomorrow; $k++) { $idx = (($k - 1) % $plan.apps) + 1; $needTomorrow[$idx] = 1 + $(if ($needTomorrow.ContainsKey($idx)) { $needTomorrow[$idx] } else { 0 }) }
        for ($k = 1; $k -le $plan.expiring; $k++) { $idx = (($k - 1) % $plan.apps) + 1; $needSoon[$idx] = 1 + $(if ($needSoon.ContainsKey($idx)) { $needSoon[$idx] } else { 0 }) }
        $addedT = 0; $addedS = 0; $skipped = 0
        foreach ($idx in @($needTomorrow.Keys) + @($needSoon.Keys) | Select-Object -Unique) {
            if (-not $apps.ContainsKey($idx)) { continue }
            $a = $apps[$idx]
            $haveT = @($a.passwordCredentials | Where-Object { $_.displayName -eq 'replica-expires-tomorrow' }).Count
            $haveS = @($a.passwordCredentials | Where-Object { $_.displayName -eq 'replica-expires-in-30-days' }).Count
            $wantT = 0; if ($needTomorrow.ContainsKey($idx)) { $wantT = $needTomorrow[$idx] }
            $wantS = 0; if ($needSoon.ContainsKey($idx)) { $wantS = $needSoon[$idx] }
            for ($k = $haveT; $k -lt $wantT; $k++) {
                try { Invoke-WithRetry -What 'addPassword' -Action { Invoke-Graph -Method POST -Uri "applications/$($a.id)/addPassword" -Body @{ passwordCredential = @{ displayName = 'replica-expires-tomorrow'; endDateTime = (Get-Date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ssZ') } } } | Out-Null; $addedT++ }
                catch { Add-Failed "1-day secret on $($a.displayName) failed: $(Get-ErrorText $_)" }
            }
            for ($k = $haveS; $k -lt $wantS; $k++) {
                try { Invoke-WithRetry -What 'addPassword' -Action { Invoke-Graph -Method POST -Uri "applications/$($a.id)/addPassword" -Body @{ passwordCredential = @{ displayName = 'replica-expires-in-30-days'; endDateTime = (Get-Date).ToUniversalTime().AddDays(30).ToString('yyyy-MM-ddTHH:mm:ssZ') } } } | Out-Null; $addedS++ }
                catch { Add-Failed "30-day secret on $($a.displayName) failed: $(Get-ErrorText $_)" }
            }
            $skipped += [Math]::Min($haveT, $wantT) + [Math]::Min($haveS, $wantS)
        }
        if ($addedT + $addedS -gt 0) { Add-Created "$addedT 1-day and $addedS 30-day secret(s) (values discarded on purpose)" }
        if ($skipped -gt 0) { Add-Reused "$skipped replica secret(s) already present" }
        Expect "analyze LOW '$($plan.tomorrow + $plan.expiring) app credentials expire within 60 days' today; MEDIUM '$($plan.tomorrow) expired app credentials' and 6.2 Gap from tomorrow"
    }

    # --- service principals: one per replica app, as a consented app would have --------------------
    $sps = @{}
    if ($apps.Count -gt 0) {
        Write-Host "Graph: service principals for $($apps.Count) replica app(s)..." -ForegroundColor Cyan
        $byAppId = @{}
        try { foreach ($sp in (Invoke-GraphPaged "servicePrincipals?`$filter=startswith(displayName,'$appPrefix')&`$select=id,appId,displayName&`$top=999")) { $byAppId["$($sp.appId)"] = $sp } }
        catch { Add-Failed "Could not list replica service principals: $(Get-ErrorText $_)" }
        $made = 0; $had = 0
        foreach ($i in @($apps.Keys | Sort-Object)) {
            $app = $apps[$i]
            if ($byAppId.ContainsKey("$($app.appId)")) { $sps[$i] = $byAppId["$($app.appId)"]; $had++; continue }
            try { $sps[$i] = Invoke-WithRetry -What 'service principal create' -Action { Invoke-Graph -Method POST -Uri 'servicePrincipals' -Body @{ appId = $app.appId } }; $made++ }
            catch { Add-Failed "Service principal for $($app.displayName) failed: $(Get-ErrorText $_)" }
        }
        if ($made -gt 0) { Add-Created "$made replica service principal(s)" }
        if ($had -gt 0) { Add-Reused "$had replica service principal(s)" }
        Expect "servicePrincipals.json gains $($apps.Count) replica entries (2.2 inventory)"
    }

    # --- risky app-role assignments (consent) on the replica service principals ---------------------
    if ($plan.risky.Count -gt 0 -and $sps.Count -gt 0) {
        Write-Host 'Graph: risky application permissions on replica service principals (dummy apps in a throwaway tenant)...' -ForegroundColor Cyan
        $graphSp = $null; $roleIds = @{}
        try {
            $graphSp = @((Invoke-Graph "servicePrincipals?`$filter=appId eq '$GraphResourceAppId'&`$select=id,appId,displayName,appRoles").value)[0]
            if (-not $graphSp) { throw 'Microsoft Graph service principal not found in this tenant' }
            foreach ($rv in $plan.risky.Keys) {
                $role = @($graphSp.appRoles | Where-Object { $_.value -eq $rv -and $_.allowedMemberTypes -contains 'Application' })[0]
                if ($role) { $roleIds[$rv] = "$($role.id)" } else { Add-Failed "Graph application permission '$rv' not found on the Microsoft Graph service principal" }
            }
        } catch { Add-Failed "Could not read the Microsoft Graph service principal: $(Get-ErrorText $_)" }
        $asnCache = @{}
        foreach ($rv in $plan.risky.Keys) {
            if (-not $roleIds.ContainsKey($rv)) { continue }
            $rid = $roleIds[$rv]; $granted = 0; $had = 0
            for ($i = 1; $i -le $plan.risky[$rv]; $i++) {
                if (-not $sps.ContainsKey($i)) { continue }
                $sp = $sps[$i]
                try {
                    if (-not $asnCache.ContainsKey($sp.id)) { $asnCache[$sp.id] = @((Invoke-Graph "servicePrincipals/$($sp.id)/appRoleAssignments").value) }
                    if (@($asnCache[$sp.id] | Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -eq $rid }).Count -gt 0) { $had++; continue }
                    $new = Invoke-WithRetry -What "consent $rv" -Action { Invoke-Graph -Method POST -Uri "servicePrincipals/$($sp.id)/appRoleAssignments" -Body @{ principalId = $sp.id; resourceId = $graphSp.id; appRoleId = $rid } }
                    $asnCache[$sp.id] += @($new); $granted++
                } catch { Add-Failed "Assign $rv to replica app $i failed: $(Get-ErrorText $_)" }
            }
            if ($granted -gt 0) { Add-Created "$granted app(s) now hold $rv" }
            if ($had -gt 0) { Add-Reused "$had app(s) already held $rv" }
            Expect "analyze HIGH '$($plan.risky[$rv]) app(s) hold $rv (tenant-wide)'; 2.1 Partial"
        }
    }

    # --- security groups -------------------------------------------------------------------
    if ($plan.groups -gt 0) {
        Write-Host "Graph: $($plan.groups) replica security groups..." -ForegroundColor Cyan
        $groupPrefix = "$Prefix-Group-"; $groups = @{}
        try {
            foreach ($g in (Invoke-GraphPaged "groups?`$filter=startswith(displayName,'$groupPrefix')&`$select=id,displayName&`$top=999")) {
                if ($g.displayName -match "^$groupPrefix(\d{3})$") { $groups[[int]$Matches[1]] = $g }
            }
        } catch { Add-Failed "Could not list existing replica groups: $(Get-ErrorText $_)" }
        $made = 0
        for ($i = 1; $i -le $plan.groups; $i++) {
            if ($groups.ContainsKey($i)) { continue }
            $nm = Name3 'Group' $i
            try {
                $g = Invoke-Graph -Method POST -Uri 'groups' -Body @{ displayName = $nm; mailEnabled = $false; mailNickname = ('secauditreplica-group-{0:000}' -f $i); securityEnabled = $true; description = 'SecAudit replica fixture (dummy).' }
                $groups[$i] = $g; $made++
            } catch { Add-Failed "Group $nm failed: $(Get-ErrorText $_)" }
        }
        if ($made -gt 0) { Add-Created "$made replica security group(s)" }
        if ($groups.Count - $made -gt 0) { Add-Reused "$($groups.Count - $made) replica security group(s)" }
        Expect 'no finding; groups exist at source scale for environment security-group tests'
    }

    # --- Conditional Access ------------------------------------------------------------------
    if ($plan.caTotal -gt 0) {
        Write-Host "Graph: $($plan.caTotal) Conditional Access policies (created disabled, except one all-users MFA policy)..." -ForegroundColor Cyan
        $sdOn = $null
        try { $sdOn = [bool](Invoke-Graph 'policies/identitySecurityDefaultsEnforcementPolicy').isEnabled } catch { Write-Warning "  could not read security defaults: $(Get-ErrorText $_)" }
        if ($sdOn -eq $true) {
            Write-Host '  skipped: security defaults are ON, and Conditional Access cannot coexist with them' -ForegroundColor Yellow
            Add-Manual "Turn security defaults off (entra.microsoft.com > Overview > Properties > Manage security defaults > Disabled), then re-run for the $($plan.caTotal) CA policies. This script never toggles security defaults."
        } else {
            $caPrefix = "$Prefix-CA-"; $existingCa = @{}
            try { foreach ($p in @((Invoke-Graph 'identity/conditionalAccess/policies').value)) { if ($p.displayName -match "^$caPrefix(\d{3})") { $existingCa[[int]$Matches[1]] = $p } } }
            catch { Add-Failed "Could not list Conditional Access policies: $(Get-ErrorText $_)" }
            $made = 0; $enabledMade = 0
            for ($i = 1; $i -le $plan.caTotal; $i++) {
                if ($existingCa.ContainsKey($i)) { continue }
                $isMfa = ($i -le $plan.caMfa); $isEnabledInSource = ($i -le $plan.caEnabled)
                $state = 'disabled'; $suffix = 'disabled'
                if ($i -eq 1 -and $plan.caMfa -ge 1) { $state = 'enabled'; $suffix = 'mfa-all-users' }
                elseif ($isMfa) { $suffix = 'mfa-disabled' }
                elseif ($isEnabledInSource) { $suffix = 'block-legacy-disabled' }
                $nm = (Name3 'CA' $i) + "-$suffix"
                $exclude = @(); if ($me -and $me.id) { $exclude = @("$($me.id)") }
                $body = @{ displayName = $nm; state = $state; conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = $exclude }; applications = @{ includeApplications = @('All') }; clientAppTypes = @('all') }; grantControls = @{ operator = 'OR'; builtInControls = @('mfa') } }
                if ($suffix -eq 'block-legacy-disabled') { $body.conditions.clientAppTypes = @('exchangeActiveSync', 'other'); $body.grantControls = @{ operator = 'OR'; builtInControls = @('block') } }
                try { Invoke-Graph -Method POST -Uri 'identity/conditionalAccess/policies' -Body $body | Out-Null; $made++; if ($state -eq 'enabled') { $enabledMade++ } }
                catch { Add-Failed "CA policy $nm failed (needs Entra ID P1): $(Get-ErrorText $_)" }
            }
            if ($made -gt 0) { Add-Created "$made CA polic$(if($made -eq 1){'y'}else{'ies'}) ($enabledMade enabled: the all-users MFA policy with $signedIn excluded)" }
            if ($existingCa.Count -gt 0) { Add-Reused "$($existingCa.Count) replica CA polic$(if($existingCa.Count -eq 1){'y'}else{'ies'})" }
            if ($plan.caEnabled -gt 1) { Add-Manual "The source had $($plan.caEnabled) enabled CA policies; the replica enables only the all-users MFA one. Review and enable the others in entra.microsoft.com > Conditional Access > Policies (they are named ...-disabled)." }
            Expect "1.4 $(if($plan.caMfa -ge 1){'Aligned'}else{'Gap'}); analyze Conditional Access: $($plan.caTotal) policies, $(if($plan.caMfa -ge 1){1}else{0}) enabled requiring MFA"
        }
    }

    # --- named locations -----------------------------------------------------------------------
    if ($plan.namedLocations -gt 0) {
        Write-Host "Graph: $($plan.namedLocations) named locations (203.0.113.0/24 documentation range)..." -ForegroundColor Cyan
        $locPrefix = "$Prefix-Location-"; $existingLoc = @{}
        try { foreach ($l in @((Invoke-Graph 'identity/conditionalAccess/namedLocations').value)) { if ($l.displayName -match "^$locPrefix(\d{3})$") { $existingLoc[[int]$Matches[1]] = $l } } }
        catch { Add-Failed "Could not list named locations: $(Get-ErrorText $_)" }
        $made = 0
        for ($i = 1; $i -le $plan.namedLocations; $i++) {
            if ($existingLoc.ContainsKey($i)) { continue }
            $nm = Name3 'Location' $i
            try {
                Invoke-Graph -Method POST -Uri 'identity/conditionalAccess/namedLocations' -Body @{
                    '@odata.type' = '#microsoft.graph.ipNamedLocation'; displayName = $nm; isTrusted = $false
                    ipRanges = @(@{ '@odata.type' = '#microsoft.graph.iPv4CidrRange'; cidrAddress = "203.0.113.$i/32" })
                } | Out-Null
                $made++
            } catch { Add-Failed "Named location $nm failed: $(Get-ErrorText $_)" }
        }
        if ($made -gt 0) { Add-Created "$made named location(s)" }
        if ($existingLoc.Count -gt 0) { Add-Reused "$($existingLoc.Count) named location(s)" }
        Expect "graph-identity-plus: $($plan.namedLocations) named locations"
    }

    # --- guests ------------------------------------------------------------------------------
    if ($plan.guests -gt 0) {
        Write-Host "Graph: $($plan.guests) guest invitations across $(@($plan.guestDomainCounts).Count) fake domain(s) (no email sent)..." -ForegroundColor Cyan
        $haveMail = @{}
        try {
            foreach ($g in (Invoke-GraphPaged "users?`$filter=userType eq 'Guest'&`$count=true&`$select=id,mail&`$top=999" -Advanced)) { if ("$($g.mail)" -like 'replica-guest-*') { $haveMail["$($g.mail)".ToLower()] = 1 } }
        } catch { Add-Failed "Could not list existing guests: $(Get-ErrorText $_)" }
        $made = 0; $had = 0; $k = 0; $d = 0
        foreach ($count in @($plan.guestDomainCounts)) {
            $d++
            for ($j = 1; $j -le $count; $j++) {
                $k++
                $mail = ('replica-guest-{0:000}@fake{1}.example.com' -f $k, $d)
                if ($haveMail.ContainsKey($mail.ToLower())) { $had++; continue }
                try {
                    Invoke-Graph -Method POST -Uri 'invitations' -Body @{ invitedUserEmailAddress = $mail; inviteRedirectUrl = 'https://myapplications.microsoft.com'; sendInvitationMessage = $false; invitedUserDisplayName = ('{0} Guest {1:000}' -f $Prefix, $k) } | Out-Null
                    $made++
                } catch { Add-Failed "Guest invitation $mail failed: $(Get-ErrorText $_)" }
            }
        }
        if ($made -gt 0) { Add-Created "$made guest invitation(s)" }
        if ($had -gt 0) { Add-Reused "$had guest(s)" }
        Expect "analyze Guests MEDIUM '$($plan.guests) guest accounts'; guest concentration top domains fake1..fake$d.example.com"
    }

    # --- PIM eligibility ----------------------------------------------------------------------
    if ($plan.pim -gt 0) {
        Write-Host "Graph: $($plan.pim) PIM eligible assignment(s) on '$PimRole' (expire after $PimEligibilityDuration; needs Entra ID P2)..." -ForegroundColor Cyan
        try {
            $roleDef = @((Invoke-Graph "roleManagement/directory/roleDefinitions?`$filter=displayName eq '$($PimRole.Replace("'", "''"))'").value)[0]
            if (-not $roleDef) { throw "role definition '$PimRole' not found" }
            $made = 0; $had = 0
            for ($i = 1; $i -le $plan.pim; $i++) {
                if (-not $users.ContainsKey($i)) { continue }
                $principal = "$($users[$i].id)"
                try {
                    $existing = @((Invoke-Graph "roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$principal' and roleDefinitionId eq '$($roleDef.id)'").value)
                    if ($existing.Count -gt 0) { $had++; continue }
                    Invoke-WithRetry -What 'PIM request' -Action {
                        Invoke-Graph -Method POST -Uri 'roleManagement/directory/roleEligibilityScheduleRequests' -Body @{
                            action = 'adminAssign'; justification = 'SecAudit replica fixture: eligible (just-in-time) assignment'
                            roleDefinitionId = "$($roleDef.id)"; directoryScopeId = '/'; principalId = $principal
                            scheduleInfo = @{ startDateTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); expiration = @{ type = 'afterDuration'; duration = $PimEligibilityDuration } }
                        }
                    } | Out-Null
                    $made++
                } catch {
                    $t = Get-ErrorText $_
                    if ($t -match 'AadPremiumLicenseRequired') { Add-Manual 'PIM skipped: the dev tenant has no Entra ID P2 licence (AadPremiumLicenseRequired). Add the Entra ID P2 trial (docs/dev-tenant-setup.md step 1) and re-run.'; break }
                    Add-Failed "PIM eligibility for replica user $i failed: $t"
                }
            }
            if ($made -gt 0) { Add-Created "$made PIM eligible assignment(s)" }
            if ($had -gt 0) { Add-Reused "$had PIM eligible assignment(s)" }
            Expect "2.3 Aligned ($($plan.pim) eligible); pim-eligible.json non-empty"
        } catch { Add-Failed "PIM class failed: $(Get-ErrorText $_)" }
    }
}

# ---------------------------------------------------------------------------------------------
# 4. Build (-Force): Azure
# ---------------------------------------------------------------------------------------------
if ($SkipAzure) { Write-Host 'Azure replica: skipped (-SkipAzure)' -ForegroundColor Yellow }
elseif ($plan.nsgs + $plan.sql + $plan.kv -eq 0) { Write-Host 'Azure replica: nothing to build (source had no NSG, SQL or Key Vault evidence)' -ForegroundColor Yellow }
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
        if ($SubscriptionId) { $sub = @($subs | Where-Object { $_.subscriptionId -eq $SubscriptionId })[0]; if (-not $sub) { Add-Failed "Subscription $SubscriptionId is not visible to you or not enabled." } }
        elseif ($subs.Count -eq 1) { $sub = $subs[0] }
        elseif ($subs.Count -eq 0) { Add-Failed 'No enabled Azure subscription is visible to this admin.' }
        else {
            Write-Host '  subscriptions visible to you:' -ForegroundColor Yellow
            for ($i = 0; $i -lt $subs.Count; $i++) { Write-Host ("    [{0}] {1}  {2}" -f ($i + 1), $subs[$i].subscriptionId, $subs[$i].displayName) }
            $pick = Read-Host '  Build the Azure replica in which one? Enter a number, or blank to skip'
            if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $subs.Count) { $sub = $subs[[int]$pick - 1] }
        }
    }
    if ($sub -and -not $Yes -and $SkipGraph) {
        Write-Host "This will CREATE Azure resources in $($sub.displayName) ($($sub.subscriptionId)). Continue only if it is a dev/test subscription you own." -ForegroundColor Red
        if ((Read-Host 'Type replicate to continue') -ne 'replicate') { Write-Host 'Stopped. Nothing was changed in Azure.' -ForegroundColor Yellow; $sub = $null }
    }

    if ($sub) {
        $sid = $sub.subscriptionId
        $base = "https://management.azure.com/subscriptions/$sid"
        $rgBase = "$base/resourceGroups/$ResourceGroup"
        Write-Host "  using subscription $($sub.displayName) ($sid)" -ForegroundColor Yellow

        # Resource providers must be registered once per subscription; raw REST does not do it silently.
        foreach ($ns in @('Microsoft.Network', 'Microsoft.Sql', 'Microsoft.KeyVault')) {
            try {
                $p = Invoke-Arm "$base/providers/${ns}?api-version=2021-04-01"
                if ("$($p.registrationState)" -eq 'Registered') { continue }
                Invoke-Arm -Method POST -Uri "$base/providers/$ns/register?api-version=2021-04-01" | Out-Null
                for ($w = 0; $w -lt 12; $w++) { Start-Sleep -Seconds 10; $p = Invoke-Arm "$base/providers/${ns}?api-version=2021-04-01"; if ("$($p.registrationState)" -eq 'Registered') { break } }
                Write-Host "  $ns registration state: $($p.registrationState)" -ForegroundColor Yellow
            } catch { Add-Failed "Provider $ns registration failed: $(Get-ErrorText $_)" }
        }

        Write-Host "ARM: resource group $ResourceGroup in $Location..." -ForegroundColor Cyan
        $rgOk = $false
        try {
            $rgExists = $false
            try { Invoke-Arm "${rgBase}?api-version=2021-04-01" | Out-Null; $rgExists = $true } catch {}
            if ($rgExists) { Add-Reused "resource group $ResourceGroup" }
            else { Invoke-Arm -Method PUT -Uri "${rgBase}?api-version=2021-04-01" -Body @{ location = $Location; tags = @{ purpose = 'secaudit-replica'; 'delete-when-done' = 'yes' } } | Out-Null; Add-Created "resource group $ResourceGroup" }
            $rgOk = $true
        } catch { Add-Failed "Resource group failed: $(Get-ErrorText $_)" }

        if ($rgOk -and $plan.nsgs -gt 0) {
            Write-Host "ARM: $($plan.nsgs) NSG(s), $($plan.nsgOpen) with RDP open to the internet..." -ForegroundColor Cyan
            $made = 0; $had = 0
            for ($i = 1; $i -le $plan.nsgs; $i++) {
                $nm = Name3 'NSG' $i; $open = ($i -le $plan.nsgOpen)
                try {
                    $exists = $false; try { Invoke-Arm "$rgBase/providers/Microsoft.Network/networkSecurityGroups/${nm}?api-version=2023-05-01" | Out-Null; $exists = $true } catch {}
                    if ($exists) { $had++; continue }
                    $rules = @()
                    if ($open) { $rules = @(@{ name = 'replica-allow-rdp-from-internet'; properties = @{ priority = 100; direction = 'Inbound'; access = 'Allow'; protocol = 'Tcp'; sourceAddressPrefix = '*'; sourcePortRange = '*'; destinationAddressPrefix = '*'; destinationPortRange = '3389'; description = 'SecAudit replica fixture. Attached to nothing.' } }) }
                    Invoke-Arm -Method PUT -Uri "$rgBase/providers/Microsoft.Network/networkSecurityGroups/${nm}?api-version=2023-05-01" -Body @{ location = $Location; properties = @{ securityRules = $rules } } | Out-Null
                    $made++
                } catch { Add-Failed "NSG $nm failed: $(Get-ErrorText $_)" }
            }
            if ($made -gt 0) { Add-Created "$made NSG(s)" }
            if ($had -gt 0) { Add-Reused "$had NSG(s)" }
            Expect "analyze HIGH 'NSG ... opens port 3389 to the internet' x $($plan.nsgOpen)"
        }

        if ($rgOk -and $plan.sql -gt 0) {
            Write-Host "ARM: $($plan.sql) SQL logical server(s) (no databases), $($plan.sqlAllowAll) with the allow-all-Azure-IPs rule..." -ForegroundColor Cyan
            $existingSrv = @()
            try { $existingSrv = @((Invoke-Arm "$rgBase/providers/Microsoft.Sql/servers?api-version=2021-11-01").value) } catch { Add-Failed "Could not list SQL servers: $(Get-ErrorText $_)" }
            $servers = @{}
            foreach ($s in $existingSrv) { if ($s.name -match '^secauditrep-sql-(\d{3})-') { $servers[[int]$Matches[1]] = $s } }
            $pending = @{}; $made = 0
            for ($i = 1; $i -le $plan.sql; $i++) {
                if ($servers.ContainsKey($i)) { continue }
                $nm = ('secauditrep-sql-{0:000}-{1}' -f $i, (New-RandomSuffix))
                try {
                    Invoke-Arm -Method PUT -Uri "$rgBase/providers/Microsoft.Sql/servers/${nm}?api-version=2021-11-01" -Body @{
                        location = $Location
                        properties = @{ administratorLogin = 'secauditadmin'; administratorLoginPassword = (New-RandomPassword 24); version = '12.0'; publicNetworkAccess = 'Enabled'; minimalTlsVersion = '1.2' }
                    } | Out-Null
                    $pending[$i] = $nm
                } catch { Add-Failed "SQL server $nm failed: $(Get-ErrorText $_)" }
            }
            # servers provision asynchronously; wait for each to reach Ready before touching firewall rules
            foreach ($i in @($pending.Keys)) {
                $nm = $pending[$i]; $srv = $null
                for ($w = 0; $w -lt 30; $w++) {
                    Start-Sleep -Seconds 10
                    try { $srv = Invoke-Arm "$rgBase/providers/Microsoft.Sql/servers/${nm}?api-version=2021-11-01" } catch { $srv = $null }
                    if ($srv -and "$($srv.properties.state)" -eq 'Ready') { break }
                }
                if ($srv -and "$($srv.properties.state)" -eq 'Ready') { $servers[$i] = $srv; $made++ } else { Add-Failed "SQL server $nm did not reach state Ready within 5 minutes" }
            }
            if ($made -gt 0) { Add-Created "$made SQL logical server(s) (public, no database, admin password discarded)" }
            if ($existingSrv.Count -gt 0) { Add-Reused "$($existingSrv.Count) SQL logical server(s)" }
            $rulesMade = 0
            for ($i = 1; $i -le $plan.sqlAllowAll; $i++) {
                if (-not $servers.ContainsKey($i)) { continue }
                $nm = $servers[$i].name
                try {
                    $rules = @((Invoke-Arm "$rgBase/providers/Microsoft.Sql/servers/$nm/firewallRules?api-version=2021-11-01").value)
                    if (@($rules | Where-Object { $_.properties.startIpAddress -eq '0.0.0.0' -and $_.properties.endIpAddress -eq '0.0.0.0' }).Count -gt 0) { continue }
                    Invoke-Arm -Method PUT -Uri "$rgBase/providers/Microsoft.Sql/servers/$nm/firewallRules/AllowAllWindowsAzureIps?api-version=2021-11-01" -Body @{ properties = @{ startIpAddress = '0.0.0.0'; endIpAddress = '0.0.0.0' } } | Out-Null
                    $rulesMade++
                } catch { Add-Failed "Firewall rule on $nm failed: $(Get-ErrorText $_)" }
            }
            if ($rulesMade -gt 0) { Add-Created "$rulesMade allow-all-Azure-IPs firewall rule(s)" }
            Add-Note "SQL: publicNetworkAccess=Disabled needs a private endpoint, so every replica server is public (source had $($shape.sqlPublic) of $($shape.sql) public)"
            Expect "analyze HIGH 'public network access enabled' x $($plan.sql) and 'allows all Azure IPs' x $($plan.sqlAllowAll); 3.1 TLS 1.2 enforced"
        }

        if ($rgOk -and $plan.kv -gt 0) {
            Write-Host "ARM: $($plan.kv) Key Vault(s), $($plan.kvLegacy) on access policies, $($plan.kvPublic) public..." -ForegroundColor Cyan
            $existingKv = @()
            try { $existingKv = @((Invoke-Arm "$rgBase/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01").value) } catch { Add-Failed "Could not list Key Vaults: $(Get-ErrorText $_)" }
            $vaults = @{}
            foreach ($v in $existingKv) { if ($v.name -match '^secauditrep-kv-(\d{3})-') { $vaults[[int]$Matches[1]] = $v } }
            $made = 0
            for ($i = 1; $i -le $plan.kv; $i++) {
                if ($vaults.ContainsKey($i)) { continue }
                $nm = ('secauditrep-kv-{0:000}-{1}' -f $i, (New-RandomSuffix))
                $legacy = ($i -le $plan.kvLegacy); $public = ($i -le $plan.kvPublic)
                try {
                    Invoke-Arm -Method PUT -Uri "$rgBase/providers/Microsoft.KeyVault/vaults/${nm}?api-version=2022-07-01" -Body @{
                        location = $Location
                        properties = @{
                            tenantId = $tenantId; sku = @{ family = 'A'; name = 'standard' }
                            accessPolicies = @(); enableRbacAuthorization = (-not $legacy)
                            publicNetworkAccess = $(if ($public) { 'Enabled' } else { 'Disabled' })
                            softDeleteRetentionInDays = 7
                        }
                    } | Out-Null
                    $made++
                } catch { Add-Failed "Key Vault $nm failed: $(Get-ErrorText $_)" }
            }
            if ($made -gt 0) { Add-Created "$made Key Vault(s) (soft-delete 7 days, no purge protection)" }
            if ($existingKv.Count -gt 0) { Add-Reused "$($existingKv.Count) Key Vault(s)" }
            Expect "analyze MEDIUM 'legacy access policies' x $($plan.kvLegacy) and 'public network access' x $($plan.kvPublic)"
        }
    }
}

# ---------------------------------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '==================== REPLICA SUMMARY ====================' -ForegroundColor Green
foreach ($c in $script:Created) { Write-Host "  created  $c" -ForegroundColor Green }
foreach ($r in $script:Reused)  { Write-Host "  reused   $r" -ForegroundColor Yellow }
foreach ($f in $script:Failed)  { Write-Host "  FAILED   $f" -ForegroundColor Red }
if ($script:Manual.Count -gt 0) {
    Write-Host ''
    Write-Host 'Needs a manual step:' -ForegroundColor Cyan
    foreach ($m in $script:Manual) { Write-Host "  - $m" -ForegroundColor Yellow }
}
Write-Host ''
Write-Host 'A replica cannot reproduce (by design):' -ForegroundColor Cyan
Write-Host "  - sign-in logs: a read-only system; no legacy-auth sign-ins can be planted (source: $(if($null -ne $shape.signins){"$($shape.signins) sampled"}else{'not readable'}))"
Write-Host "  - Power Platform environments: $(if($null -ne $shape.ppEnvironments){"source had $($shape.ppEnvironments) [$($shape.ppSkus)]"}else{'source inventory not readable'}); creating environments is out of scope"
Write-Host "  - Dataverse internals (auditing, roles, solutions, mailboxes, queues): source had $($shape.dataverseFiles) evidence file(s); not replicated"
Write-Host "  - Defender for Cloud plans: a billing decision; source had $($shape.defenderStandard) on Standard, the replica stays Free"
Write-Host "  - directory role membership: source counts are in the plan table; replica users hold no admin roles"
foreach ($n in $script:Notes) { Write-Host "  - $n" -ForegroundColor DarkGray }
Write-Host ''
Write-Host 'Next: run ./run-audit.ps1 against this tenant and compare output/assessment-report.md with the source tenant report, shape against shape.' -ForegroundColor Green
Write-Host 'Undo: testdata/teardown-replica.ps1 -Force' -ForegroundColor Green
Write-Host 'Replica done.' -ForegroundColor Green
