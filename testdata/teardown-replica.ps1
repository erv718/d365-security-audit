# teardown-replica.ps1 - deletes every SecAuditReplica-* object that replicate-from-output.ps1 built.
#
# ==========================================================================================
#   DEV/TEST TENANTS YOU OWN ONLY.
#   With -Force this script DELETES from a tenant and from an Azure subscription: replica
#   users, guests, groups, app registrations (their service principals and app-role
#   assignments go with them), Conditional Access policies, named locations, PIM
#   eligibility, and the replica resource group. It only touches objects whose names carry
#   the replica prefix, but it is still a delete tool: never run it against any tenant you
#   do not own. It is NOT part of the audit tool, which stays strictly read-only.
# ==========================================================================================
#
# Default mode (no -Force): sign in, inventory what would be deleted, print counts, stop.
# Authentication: device-code flow in pure REST, same first-party public client ids as the
# other testdata scripts (Microsoft Graph PowerShell for Graph, Azure PowerShell for ARM).
# Requirements: Windows PowerShell 5.1 or PowerShell 7. No modules, no az CLI.

param(
    [switch]$Force,                                  # without it: inventory only
    [string]$SubscriptionId,
    [string]$ResourceGroup = 'rg-secaudit-replica',
    [string]$Tenant = 'organizations',
    [switch]$PurgeKeyVaults,                         # also purge the soft-deleted replica vaults so their names free up
    [switch]$SkipGraph,
    [switch]$SkipAzure,
    [switch]$Yes                                     # skip the typed confirmation after sign-in
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GraphClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph PowerShell (first-party public client)
$ArmClientId   = '1950a258-227b-4e31-a9cf-717495945fc2'   # Azure PowerShell (first-party public client)
$GraphScopes   = @(
    'https://graph.microsoft.com/User.ReadWrite.All',
    'https://graph.microsoft.com/Group.ReadWrite.All',
    'https://graph.microsoft.com/Application.ReadWrite.All',
    'https://graph.microsoft.com/Policy.Read.All',
    'https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess',
    'https://graph.microsoft.com/RoleManagement.ReadWrite.Directory',
    'https://graph.microsoft.com/Directory.Read.All',
    'offline_access'
) -join ' '
$ArmScopes = 'https://management.azure.com/user_impersonation offline_access'
$Prefix = 'SecAuditReplica'
$UserPrefix = 'secauditreplica-user-'
$GuestPrefix = 'replica-guest-'

$script:Deleted = @(); $script:Failed = @(); $script:Found = @()
function Add-Deleted($text) { $script:Deleted += $text; Write-Host "  deleted: $text" -ForegroundColor Green }
function Add-Failed($text)  { $script:Failed  += $text; Write-Warning $text }
function Add-Found($text)   { $script:Found   += $text; Write-Host "  found:   $text" -ForegroundColor Yellow }

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

# Delete a list of Graph objects one by one; in inventory mode only report them.
function Remove-GraphSet($label, $items, $uriOf) {
    $n = @($items).Count
    if ($n -eq 0) { Write-Host "  $label : none" -ForegroundColor DarkGray; return }
    if (-not $Force) { Add-Found "$n $label"; return }
    $done = 0
    foreach ($o in @($items)) {
        try { Invoke-Graph -Method DELETE -Uri (& $uriOf $o) | Out-Null; $done++ }
        catch { Add-Failed "$label $($o.displayName)$($o.userPrincipalName) failed: $(Get-ErrorText $_)" }
    }
    Add-Deleted "$done of $n $label"
}

Write-Host "Teardown: remove every $Prefix-* replica object $(if($Force){'(DELETING)'}else{'(inventory only, add -Force to delete)'})" -ForegroundColor Cyan
$tenantId = $null

# =========================== Graph ============================================================
if ($SkipGraph) { Write-Host 'Graph: skipped (-SkipGraph)' -ForegroundColor Yellow }
else {
    Write-Host 'Sign-in 1 of 2: Microsoft Graph, as the Global Administrator of the DEV tenant...' -ForegroundColor Cyan
    $graphTok = Get-DeviceCodeToken -ClientId $GraphClientId -Scope $GraphScopes -TenantOrAlias $Tenant -Label 'Microsoft Graph'
    $script:GraphToken = $graphTok.access_token
    $tenantId = Get-JwtClaim $script:GraphToken 'tid'
    $signedIn = Get-JwtClaim $script:GraphToken 'upn'; if (-not $signedIn) { $signedIn = Get-JwtClaim $script:GraphToken 'preferred_username' }
    $orgName = ''; try { $orgName = "$(@((Invoke-Graph 'organization?$select=id,displayName').value)[0].displayName)" } catch {}
    Write-Host "  signed in as $signedIn" -ForegroundColor Yellow
    Write-Host "  TARGET TENANT: $orgName ($tenantId)" -ForegroundColor Yellow
    if ($Force -and -not $Yes) {
        Write-Host ''
        Write-Host "This will DELETE every $Prefix-* object in that tenant. Continue only if it is a dev/test tenant you own." -ForegroundColor Red
        if ((Read-Host 'Type teardown to continue') -ne 'teardown') { Write-Host 'Stopped. Nothing was changed.' -ForegroundColor Yellow; return }
    }

    # users first for PIM cleanup, but delete them last (other objects may reference them)
    $users = @(); $guests = @(); $groups = @(); $apps = @(); $policies = @(); $locations = @()
    try { $users = @(Invoke-GraphPaged "users?`$filter=startswith(userPrincipalName,'$UserPrefix')&`$select=id,userPrincipalName&`$top=999") } catch { Add-Failed "list users: $(Get-ErrorText $_)" }
    try { $guests = @((Invoke-GraphPaged "users?`$filter=userType eq 'Guest'&`$count=true&`$select=id,mail,userPrincipalName&`$top=999" -Advanced) | Where-Object { "$($_.mail)" -like "$GuestPrefix*" }) } catch { Add-Failed "list guests: $(Get-ErrorText $_)" }
    try { $groups = @(Invoke-GraphPaged "groups?`$filter=startswith(displayName,'$Prefix-')&`$select=id,displayName&`$top=999") } catch { Add-Failed "list groups: $(Get-ErrorText $_)" }
    try { $apps = @(Invoke-GraphPaged "applications?`$filter=startswith(displayName,'$Prefix-')&`$select=id,appId,displayName&`$top=999") } catch { Add-Failed "list applications: $(Get-ErrorText $_)" }
    try { $policies = @((Invoke-Graph 'identity/conditionalAccess/policies').value | Where-Object { "$($_.displayName)" -like "$Prefix-*" }) } catch { Add-Failed "list CA policies: $(Get-ErrorText $_)" }
    try { $locations = @((Invoke-Graph 'identity/conditionalAccess/namedLocations').value | Where-Object { "$($_.displayName)" -like "$Prefix-*" }) } catch { Add-Failed "list named locations: $(Get-ErrorText $_)" }

    # PIM eligibility held by replica users: cancel with adminRemove (deleting the user would drop it too,
    # but an explicit removal keeps the PIM audit trail tidy).
    Write-Host 'Graph: PIM eligibility on replica users...' -ForegroundColor Cyan
    $elig = @()
    foreach ($u in $users) {
        try { $elig += @((Invoke-Graph "roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$($u.id)'").value | ForEach-Object { @{ principalId = $u.id; roleDefinitionId = $_.roleDefinitionId; directoryScopeId = $_.directoryScopeId } }) }
        catch { $t = Get-ErrorText $_; if ($t -notmatch 'AadPremiumLicenseRequired') { Add-Failed "list PIM eligibility for $($u.userPrincipalName): $t" }; break }
    }
    if ($elig.Count -eq 0) { Write-Host '  PIM eligibility : none' -ForegroundColor DarkGray }
    elseif (-not $Force) { Add-Found "$($elig.Count) PIM eligible assignment(s)" }
    else {
        $done = 0
        foreach ($e in $elig) {
            try { Invoke-Graph -Method POST -Uri 'roleManagement/directory/roleEligibilityScheduleRequests' -Body @{ action = 'adminRemove'; roleDefinitionId = "$($e.roleDefinitionId)"; directoryScopeId = "$($e.directoryScopeId)"; principalId = "$($e.principalId)"; justification = 'SecAudit replica teardown' } | Out-Null; $done++ }
            catch { Add-Failed "PIM adminRemove failed: $(Get-ErrorText $_)" }
        }
        Add-Deleted "$done of $($elig.Count) PIM eligible assignment(s)"
    }

    Write-Host 'Graph: Conditional Access policies, then named locations (a location referenced by a policy cannot be deleted first)...' -ForegroundColor Cyan
    Remove-GraphSet 'CA policies' $policies { param($o) "identity/conditionalAccess/policies/$($o.id)" }
    Remove-GraphSet 'named locations' $locations { param($o) "identity/conditionalAccess/namedLocations/$($o.id)" }
    Write-Host 'Graph: groups, app registrations (service principals and app-role assignments go with them)...' -ForegroundColor Cyan
    Remove-GraphSet 'security groups' $groups { param($o) "groups/$($o.id)" }
    Remove-GraphSet 'app registrations' $apps { param($o) "applications/$($o.id)" }
    Write-Host 'Graph: guests and users...' -ForegroundColor Cyan
    Remove-GraphSet 'guest accounts' $guests { param($o) "users/$($o.id)" }
    Remove-GraphSet 'replica users' $users { param($o) "users/$($o.id)" }
}

# =========================== Azure ============================================================
if ($SkipAzure) { Write-Host 'Azure: skipped (-SkipAzure)' -ForegroundColor Yellow }
else {
    Write-Host 'Sign-in 2 of 2: Azure Resource Manager (same admin; needs Owner or Contributor)...' -ForegroundColor Cyan
    $armTenant = $Tenant; if ($tenantId) { $armTenant = $tenantId }
    $script:ArmToken = $null
    try { $script:ArmToken = (Get-DeviceCodeToken -ClientId $ArmClientId -Scope $ArmScopes -TenantOrAlias $armTenant -Label 'Azure Resource Manager').access_token }
    catch { Add-Failed "Azure sign-in failed: $($_.Exception.Message)" }
    $sub = $null
    if ($script:ArmToken) {
        $subs = @()
        try { $subs = @((Invoke-Arm 'https://management.azure.com/subscriptions?api-version=2020-01-01').value | Where-Object { $_.state -eq 'Enabled' }) } catch { Add-Failed "Could not list subscriptions: $(Get-ErrorText $_)" }
        if ($SubscriptionId) { $sub = @($subs | Where-Object { $_.subscriptionId -eq $SubscriptionId })[0]; if (-not $sub) { Add-Failed "Subscription $SubscriptionId is not visible to you or not enabled." } }
        elseif ($subs.Count -eq 1) { $sub = $subs[0] }
        elseif ($subs.Count -gt 1) {
            Write-Host '  subscriptions visible to you:' -ForegroundColor Yellow
            for ($i = 0; $i -lt $subs.Count; $i++) { Write-Host ("    [{0}] {1}  {2}" -f ($i + 1), $subs[$i].subscriptionId, $subs[$i].displayName) }
            $pick = Read-Host '  Which one holds the replica resource group? Enter a number, or blank to skip'
            if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $subs.Count) { $sub = $subs[[int]$pick - 1] }
        }
    }
    if ($sub) {
        $sid = $sub.subscriptionId
        $base = "https://management.azure.com/subscriptions/$sid"
        $rgBase = "$base/resourceGroups/$ResourceGroup"
        Write-Host "ARM: resource group $ResourceGroup in $($sub.displayName) ($sid)..." -ForegroundColor Cyan
        $rg = $null; try { $rg = Invoke-Arm "${rgBase}?api-version=2021-04-01" } catch { $rg = $null }
        if (-not $rg) { Write-Host '  resource group : not present' -ForegroundColor DarkGray }
        elseif (-not $Force) {
            $res = @(); try { $res = @((Invoke-Arm "$rgBase/resources?api-version=2021-04-01").value) } catch {}
            Add-Found "resource group $ResourceGroup with $($res.Count) resource(s)"
        } else {
            if (-not $Yes -and $SkipGraph) {
                Write-Host "This will DELETE resource group $ResourceGroup and everything in it. Continue only if it is a dev/test subscription you own." -ForegroundColor Red
                if ((Read-Host 'Type teardown to continue') -ne 'teardown') { Write-Host 'Stopped. Nothing was changed in Azure.' -ForegroundColor Yellow; $rg = $null }
            }
            if ($rg) {
                try {
                    # DELETE returns 202 and finishes in the background; poll until the group is gone (up to ~10 min).
                    Invoke-Arm -Method DELETE -Uri "${rgBase}?api-version=2021-04-01" | Out-Null
                    $gone = $false
                    for ($w = 0; $w -lt 60; $w++) { Start-Sleep -Seconds 10; try { Invoke-Arm "${rgBase}?api-version=2021-04-01" | Out-Null } catch { $gone = $true; break } }
                    if ($gone) { Add-Deleted "resource group $ResourceGroup" } else { Add-Failed "resource group $ResourceGroup deletion still running after 10 minutes; check the portal" }
                } catch { Add-Failed "Resource group delete failed: $(Get-ErrorText $_)" }
            }
        }
        if ($PurgeKeyVaults) {
            # Soft-deleted vaults keep their names for the retention period; purge the replica ones.
            Write-Host 'ARM: purging soft-deleted replica Key Vaults...' -ForegroundColor Cyan
            try {
                $deleted = @((Invoke-Arm "$base/providers/Microsoft.KeyVault/deletedVaults?api-version=2022-07-01").value | Where-Object { "$($_.name)" -like 'secauditrep-kv-*' })
                if ($deleted.Count -eq 0) { Write-Host '  soft-deleted vaults : none' -ForegroundColor DarkGray }
                elseif (-not $Force) { Add-Found "$($deleted.Count) soft-deleted replica vault(s)" }
                else {
                    $done = 0
                    foreach ($v in $deleted) {
                        $loc = "$($v.properties.location)"
                        try { Invoke-Arm -Method POST -Uri "$base/providers/Microsoft.KeyVault/locations/$loc/deletedVaults/$($v.name)/purge?api-version=2022-07-01" | Out-Null; $done++ }
                        catch { Add-Failed "purge $($v.name) failed: $(Get-ErrorText $_)" }
                    }
                    Add-Deleted "$done of $($deleted.Count) soft-deleted vault(s) purged"
                }
            } catch { Add-Failed "Could not list soft-deleted vaults: $(Get-ErrorText $_)" }
        }
    }
}

# =========================== Summary ==========================================================
Write-Host ''
Write-Host '==================== TEARDOWN SUMMARY ====================' -ForegroundColor Green
if (-not $Force) {
    foreach ($f in $script:Found) { Write-Host "  would delete  $f" -ForegroundColor Yellow }
    if ($script:Found.Count -eq 0) { Write-Host '  nothing to delete' -ForegroundColor Yellow }
    Write-Host 'Inventory only. Add -Force to delete.' -ForegroundColor Yellow
} else {
    foreach ($d in $script:Deleted) { Write-Host "  deleted  $d" -ForegroundColor Green }
}
foreach ($f in $script:Failed) { Write-Host "  FAILED   $f" -ForegroundColor Red }
Write-Host 'Teardown done.' -ForegroundColor Green
