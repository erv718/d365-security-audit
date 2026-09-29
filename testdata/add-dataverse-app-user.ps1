# add-dataverse-app-user.ps1 - WRITE TOOL (audit setup helper). Adds the read-only audit app
# as an Application User with a security role in every Dataverse environment of a tenant you
# administer. This automates the manual step in docs/permissions.md section 4, after which
# the read-only audit (run-audit.ps1) can read Dataverse instead of getting 403
# "The user is not a member of the organization".
#
# It performs exactly one kind of change: an application-user record, plus a security-role
# binding, for the app id you pass. It never touches business data. The role defaults to
# System Customizer (the quick option from docs/permissions.md); pass a custom read-only
# role for least privilege.
#
# Run it ONLY against tenants you administer. Default is plan mode: no writes, just a table.
#
# Authentication: interactive device-code flow in pure REST using Microsoft's well-known
# first-party Azure PowerShell client id (1950a258-...), the same client Microsoft's own
# Power Platform admin module signs in through. There is no app of ours to sign in with, so
# a person signs in through a client that already exists in every tenant.
#
# Requires: Windows PowerShell 5.1 or PowerShell 7. No modules, no az CLI.

param(
    [Parameter(Mandatory)][string]$ClientId,        # application (client) id of the audit app
    [string]$RoleName = 'System Customizer',        # role bound to the app user in each env
    [string]$Tenant = 'organizations',              # tenant id or domain; organizations = pick at sign-in
    [switch]$Force,                                 # without it: plan only, nothing is written
    [switch]$Yes                                    # skip the typed confirmation with -Force
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$AzPsClient = '1950a258-227b-4e31-a9cf-717495945fc2'
$Bap = 'https://api.bap.microsoft.com'
$BapEnvs = '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments'
$DvApi = 'api/data/v9.2'

$script:Created = @(); $script:Reused = @(); $script:Failed = @(); $script:Manual = @()

function Get-ErrorText($ErrorRecord) {
    $msg = "$($ErrorRecord.Exception.Message)"
    $body = $null
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $body = $ErrorRecord.ErrorDetails.Message }
    elseif ($ErrorRecord.Exception.Response) {
        try { $s = $ErrorRecord.Exception.Response.GetResponseStream(); if ($s) { $body = (New-Object IO.StreamReader($s)).ReadToEnd() } } catch {}
    }
    if ($body) { $body = ($body -replace '\s+', ' ').Trim(); if ($body.Length -gt 600) { $body = $body.Substring(0, 600) + '...' }; return "$msg $body" }
    return $msg
}

# Device-code sign-in: POST /devicecode, show the code, poll /token until the user finishes.
function Get-DeviceCodeToken {
    param([Parameter(Mandatory)][string]$Scope, [string]$Label = 'sign-in')
    $dc = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/devicecode" -Body @{ client_id = $AzPsClient; scope = $Scope }
    Write-Host ''
    Write-Host "  [$Label] $($dc.message)" -ForegroundColor Yellow
    Write-Host ''
    $interval = 5; if ($dc.interval) { $interval = [int]$dc.interval }
    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            return Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -Body @{
                grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $AzPsClient; device_code = $dc.device_code
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

# One Dataverse token per environment URL, cached, so multi-environment tenants ask once each.
$script:DvTokens = @{}
function Get-DvToken([string]$EnvUrl) {
    $key = $EnvUrl.TrimEnd('/')
    if (-not $script:DvTokens.ContainsKey($key)) {
        $script:DvTokens[$key] = Get-DeviceCodeToken -Scope "$key/user_impersonation" -Label "Dataverse ($key)"
    }
    return $script:DvTokens[$key]
}

function Get-AppUserId([string]$EnvUrl, [string]$Token) {
    $H = @{ Authorization = "Bearer $Token" }
    $r = Invoke-RestMethod -Uri "$($EnvUrl.TrimEnd('/'))/$DvApi/systemusers?`$filter=applicationid eq $ClientId&`$select=systemuserid&`$top=1" -Headers $H
    if ($r.value -and @($r.value).Count -gt 0) { return "$($r.value[0].systemuserid)" }
    return $null
}

function Get-RoleId([string]$EnvUrl, [string]$Token) {
    $H = @{ Authorization = "Bearer $Token" }
    $r = Invoke-RestMethod -Uri "$($EnvUrl.TrimEnd('/'))/$DvApi/roles?`$filter=name eq '$RoleName'&`$select=roleid&`$top=1" -Headers $H
    if ($r.value -and @($r.value).Count -gt 0) { return "$($r.value[0].roleid)" }
    return $null
}

function Test-RoleBound([string]$EnvUrl, [string]$Token, [string]$SysId, [string]$RoleId) {
    $H = @{ Authorization = "Bearer $Token" }
    $r = Invoke-RestMethod -Uri "$($EnvUrl.TrimEnd('/'))/$DvApi/systemusers($SysId)?`$expand=systemuserroles_association(`$select=roleid)" -Headers $H
    foreach ($role in @($r.systemuserroles_association)) { if ("$($role.roleid)" -eq $RoleId) { return $true } }
    return $false
}

Write-Host ''
Write-Host 'Add the audit app as a Dataverse Application User (audit setup helper)' -ForegroundColor Cyan
Write-Host 'Writes one thing only: an application-user record + a security-role binding for the app id you passed.' -ForegroundColor DarkGray

# --- discover environments with a Dataverse database ------------------------------------
$bapTok = Get-DeviceCodeToken -Scope "$Bap/user_impersonation" -Label 'Power Platform admin'
$HB = @{ Authorization = "Bearer $bapTok" }
$envs = @()
try {
    $r = Invoke-RestMethod -Method Get -Uri "$Bap$BapEnvs`?api-version=2020-10-01" -Headers $HB
    $envs = @($r.value | Where-Object { $_ -and $_.properties.linkedEnvironmentMetadata -and $_.properties.linkedEnvironmentMetadata.instanceUrl })
} catch { Write-Host "Could not list environments: $(Get-ErrorText $_)" -ForegroundColor Red; return }
if ($envs.Count -eq 0) { Write-Host 'No environments with a Dataverse database found.' -ForegroundColor Yellow; return }

Write-Host ''
Write-Host "  $($envs.Count) Dataverse environment(s). Checking the app user in each (one browser sign-in per environment):" -ForegroundColor Cyan

# --- plan pass: per environment, is the app a user with the role? ------------------------
$plan = @()
foreach ($e in $envs) {
    $url = "$($e.properties.linkedEnvironmentMetadata.instanceUrl)".TrimEnd('/')
    $name = "$($e.properties.displayName)"; if (-not $name) { $name = $url }
    $row = [pscustomobject]@{ Env = $name; Url = $url; EnvName = "$($e.name)"; AppUser = $false; RoleBound = $false; RoleFound = $false; SysId = $null; RoleId = $null; Note = '' }
    try {
        $dtok = Get-DvToken $url
        $sysId = Get-AppUserId $url $dtok
        $roleId = Get-RoleId $url $dtok
        $row.SysId = $sysId; $row.RoleId = $roleId
        $row.AppUser = ($null -ne $sysId)
        $row.RoleFound = ($null -ne $roleId)
        if ($row.AppUser -and $row.RoleFound) { $row.RoleBound = Test-RoleBound $url $dtok $sysId $roleId }
        if (-not $row.RoleFound) { $row.Note = "role '$RoleName' not found here" }
    } catch { $row.Note = "could not check: $(Get-ErrorText $_)" }
    $plan += $row
}

Write-Host ''
$plan | Format-Table Env, AppUser, RoleBound, RoleFound, Note -AutoSize

if (-not $Force) {
    Write-Host 'Plan only: nothing was written. Re-run with -Force to apply.' -ForegroundColor Yellow
    return
}

# --- confirm -----------------------------------------------------------------------------
$todo = @($plan | Where-Object { -not ($_.AppUser -and $_.RoleBound) -and $_.RoleFound })
if ($todo.Count -eq 0) { Write-Host 'Nothing to do: the app already has the user + role everywhere it can be set.' -ForegroundColor Green; return }
if (-not $Yes) {
    Write-Host "This will add the app ($ClientId) as an Application User with role '$RoleName' in $($todo.Count) environment(s) listed above." -ForegroundColor Yellow
    $answer = Read-Host "Type 'yes' to continue"
    if ($answer -ne 'yes') { Write-Host 'Aborted.' -ForegroundColor Yellow; return }
}

# --- apply -------------------------------------------------------------------------------
foreach ($row in $todo) {
    $url = $row.Url
    try {
        $dtok = Get-DvToken $url
        $HD = @{ Authorization = "Bearer $dtok"; 'Content-Type' = 'application/json' }

        # 1. the application user itself. BAP addApplicationUser first (the same action PAC
        #    CLI's create-service-principal wraps); on failure, direct Dataverse systemuser
        #    create with the service principal object id resolved from Graph.
        $sysId = $row.SysId
        if (-not $sysId) {
            $made = $false
            try {
                Invoke-RestMethod -Method Post -Uri "$Bap$BapEnvs/$($row.EnvName)/addApplicationUser?api-version=2020-10-01" -Headers @{ Authorization = "Bearer $bapTok"; 'Content-Type' = 'application/json' } -Body (@{ applicationId = $ClientId } | ConvertTo-Json) | Out-Null
                $made = $true
            } catch {
                Write-Host "  [$($row.Env)] BAP addApplicationUser failed ($(Get-ErrorText $_)); trying direct Dataverse create..." -ForegroundColor DarkYellow
                $gtok = Get-DeviceCodeToken -Scope 'https://graph.microsoft.com/.default' -Label 'Graph (resolve service principal)'
                $sp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$ClientId'&`$select=id" -Headers @{ Authorization = "Bearer $gtok" }
                if (-not $sp.value -or @($sp.value).Count -eq 0) { throw "no service principal found for appId $ClientId" }
                $body = @{ applicationid = $ClientId; azureactivedirectoryobjectid = "$($sp.value[0].id)" } | ConvertTo-Json
                Invoke-RestMethod -Method Post -Uri "$url/$DvApi/systemusers" -Headers $HD -Body $body | Out-Null
                $made = $true
            }
            # replication lag: the user can take a few seconds to appear
            for ($i = 0; $i -lt 5 -and -not $sysId; $i++) { Start-Sleep -Seconds 3; $sysId = Get-AppUserId $url $dtok }
            if (-not $sysId) { throw 'application user still not visible after create (replication)' }
        }

        # 2. the role binding (skip if already bound)
        if ($row.RoleBound -or (Test-RoleBound $url $dtok $sysId $row.RoleId)) {
            $script:Reused += "$($row.Env): role '$RoleName' already bound"
        } else {
            $ref = @{ '@odata.id' = "$url/$DvApi/roles($($row.RoleId))" } | ConvertTo-Json
            Invoke-RestMethod -Method Post -Uri "$url/$DvApi/systemusers($sysId)/systemuserroles_association/`$ref" -Headers $HD -Body $ref | Out-Null
            $script:Created += "$($row.Env): app user + role '$RoleName'"
        }
    } catch { $script:Failed += "$($row.Env): $(Get-ErrorText $_)" }
}

foreach ($t in $script:Created) { Write-Host "  created: $t" -ForegroundColor Green }
foreach ($t in $script:Reused)  { Write-Host "  reused:  $t" -ForegroundColor Yellow }
foreach ($t in $script:Failed)  { Write-Warning $t }

Write-Host ''
Write-Host 'Verify: re-run ./run-audit.ps1 - the dvplus 403s ("not a member of the organization") should become data.' -ForegroundColor Green
Write-Host 'Note: if Azure+ shows "Defender pricings failed: 404", open Microsoft Defender for Cloud in the Azure portal once to register the Microsoft.Security provider for that subscription.' -ForegroundColor DarkGray
