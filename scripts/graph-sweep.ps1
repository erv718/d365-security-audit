# graph-sweep.ps1 - read-only pull of the Entra ID identity plane.
# Covers: app registrations + credential expiry, service principals, high-privilege
# app permissions, directory roles + members, Conditional Access, guest count, sign-in sample.
# Read-only. Every area is isolated so one 403 (partial consent) never stops the sweep.

. (Join-Path $PSScriptRoot '_common.ps1')

$tok = Get-Token 'https://graph.microsoft.com'
if (-not $tok) {
    Write-Warning 'No Microsoft Graph token (app registration missing or its token failed). Skipping the Entra ID sweep; other sweeps still run.'
    return
}
$H = @{ Authorization = "Bearer $tok"; ConsistencyLevel = 'eventual' }
$G = 'https://graph.microsoft.com/v1.0'

Write-Host 'Graph: applications...' -ForegroundColor Cyan
$apps = @()
try {
    $apps = Invoke-Paged "$G/applications?`$top=999&`$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials" $H
    Save-Json $apps 'applications.json' | Out-Null
} catch { Write-Warning "applications need Application.Read.All: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } 'applications-ERROR.json' | Out-Null }

Write-Host 'Graph: service principals...' -ForegroundColor Cyan
$sps = @(); $spsOk = $false
try {
    $sps = Invoke-Paged "$G/servicePrincipals?`$top=999&`$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,tags" $H
    Save-Json $sps 'servicePrincipals.json' | Out-Null
    $spsOk = $true
} catch { Write-Warning "service principals need Application.Read.All: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } 'servicePrincipals-ERROR.json' | Out-Null }

Write-Host 'Graph: app-role assignments (Graph + Exchange)...' -ForegroundColor Cyan
$riskyHolders = @{}   # service principal id -> the high-privilege roles it holds ($RiskyAppRoles, _common.ps1)
$appRolesOk = $spsOk
# One try per resource, and a per-resource error file, so a failure replaces that resource's file
# from an earlier run instead of leaving it to be read as this run's.
foreach ($pair in @(@('graph','00000003-0000-0000-c000-000000000000'), @('exo','00000002-0000-0ff1-ce00-000000000000'))) {
    if (-not $spsOk) { Save-Json @{ error = 'not read: the service principal list could not be read' } "appRoleAssignments-$($pair[0])-ERROR.json" | Out-Null; continue }
    $sp = $sps | Where-Object { $_.appId -eq $pair[1] } | Select-Object -First 1
    if (-not $sp) { continue }
    try {
        $full = Invoke-RestMethod -Uri "$G/servicePrincipals/$($sp.id)?`$select=appRoles" -Headers $H
        Save-Json $full.appRoles "appRoleDefinitions-$($pair[0]).json" | Out-Null
        $asn = Invoke-Paged "$G/servicePrincipals/$($sp.id)/appRoleAssignedTo?`$top=999" $H
        Save-Json $asn "appRoleAssignments-$($pair[0]).json" | Out-Null
        $defMap = @{}; foreach ($d in @($full.appRoles)) { if ($d -and $d.id) { $defMap["$($d.id)"] = "$($d.value)" } }
        foreach ($m in @($asn)) {
            $rn = $defMap["$($m.appRoleId)"]
            if ($rn -and $script:RiskyAppRoles -contains $rn) { $k = "$($m.principalId)"; if (-not $riskyHolders.ContainsKey($k)) { $riskyHolders[$k] = @() }; $riskyHolders[$k] += $rn }
        }
    } catch { $appRolesOk = $false; Write-Warning "app-role assignments ($($pair[0])) failed: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } "appRoleAssignments-$($pair[0])-ERROR.json" | Out-Null }
}

# Owners of the apps that hold a high-privilege permission: an owner can add a new secret to the
# app and sign in as it, with no admin role. Read for those apps only (Application.Read.All; the
# owners' names need User.Read.All): both the enterprise app's (service principal's) owners and,
# when the app is registered in this tenant, the app registration's. Written every run, so an
# earlier run's list is never read as this one's.
if (-not $appRolesOk) {
    Save-Json @{ error = 'not read: the service principal list or the app-role assignments could not be read this run' } 'app-owners-ERROR.json' | Out-Null
} elseif (-not $riskyHolders.Count) {
    Save-Json @() 'app-owners.json' | Out-Null
} else {
    Write-Host "Graph: owners of the $($riskyHolders.Count) app(s) that hold a high-privilege permission..." -ForegroundColor Cyan
    try {
        $spById = @{}; foreach ($s in @($sps)) { if ($s -and $s.id) { $spById["$($s.id)"] = $s } }
        $sel = '?$select=id,displayName,userPrincipalName'
        $ownersOut = @(foreach ($spId in @($riskyHolders.Keys)) {
            $s = $spById[$spId]
            if (-not $s) { continue }
            $own = @{}; $errs = @(); $from = @()
            try {
                $ol = Invoke-Paged "$G/servicePrincipals/$spId/owners$sel" $H
                foreach ($o in @($ol | Where-Object { $_ })) { $own["$($o.id)"] = [pscustomobject]@{ id = "$($o.id)"; displayName = "$($o.displayName)"; userPrincipalName = "$($o.userPrincipalName)"; type = "$($o.'@odata.type')" } }
                $from += 'enterprise app'
            } catch { $errs += Get-ErrorText $_ }
            try {
                $ol2 = Invoke-Paged "$G/applications(appId='$($s.appId)')/owners$sel" $H
                foreach ($o in @($ol2 | Where-Object { $_ })) { $own["$($o.id)"] = [pscustomobject]@{ id = "$($o.id)"; displayName = "$($o.displayName)"; userPrincipalName = "$($o.userPrincipalName)"; type = "$($o.'@odata.type')" } }
                $from += 'app registration'
            } catch { $t = Get-ErrorText $_; if ($t -notmatch '404|Request_ResourceNotFound|does not exist') { $errs += $t } }   # 404: registered in another tenant
            [pscustomobject]@{ appId = "$($s.appId)"; spId = "$spId"; displayName = "$($s.displayName)"; object = ($from -join ' + '); roles = @($riskyHolders[$spId] | Select-Object -Unique); owners = @($own.Values); error = $(if ($errs.Count) { $errs -join ' | ' } else { $null }) }
        })
        Save-Json $ownersOut 'app-owners.json' | Out-Null
        Write-Host "  $(@($ownersOut | Where-Object { @($_.owners).Count }).Count) of them have owners." -ForegroundColor Yellow
    } catch { Write-Warning "app owners failed: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } 'app-owners-ERROR.json' | Out-Null }
}

Write-Host 'Graph: directory roles + members...' -ForegroundColor Cyan
try {
    $dirRoles = Invoke-Paged "$G/directoryRoles" $H
    $roleOut = foreach ($r in $dirRoles) {
        $members = Invoke-Paged "$G/directoryRoles/$($r.id)/members?`$select=id,displayName,userPrincipalName" $H
        [pscustomobject]@{ role = $r.displayName; memberCount = $members.Count; members = @($members | ForEach-Object { $_.userPrincipalName }) }
    }
    Save-Json $roleOut 'directoryRoles.json' | Out-Null
} catch { Write-Warning "directory roles need RoleManagement.Read.Directory (+ User.Read.All for names): $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } 'directoryRoles-ERROR.json' | Out-Null }

Write-Host 'Graph: Conditional Access policies...' -ForegroundColor Cyan
try { Save-Json (Invoke-Paged "$G/identity/conditionalAccess/policies" $H) 'ca-policies.json' | Out-Null }
catch { Write-Warning "CA policies need Policy.Read.All: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } 'ca-policies-ERROR.json' | Out-Null }

Write-Host 'Graph: guest count...' -ForegroundColor Cyan
try {
    $gc = Invoke-RestMethod -Uri "$G/users/`$count?`$filter=userType eq 'Guest'" -Headers $H
    Save-Json @{ guestCount = $gc } 'guest-count.json' | Out-Null
    Write-Host "  tenant-wide guests: $gc" -ForegroundColor Yellow
} catch { Write-Warning "Guest count failed: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } 'guest-count-ERROR.json' | Out-Null }

Write-Host 'Graph: user sign-in activity (dormant accounts)...' -ForegroundColor Cyan
# Last interactive, non-interactive and successful sign-in per account. Needs User.Read.All +
# AuditLog.Read.All and an Entra ID P1 licence; the file can be large on a big tenant.
try {
    $ua = Invoke-Paged "$G/users?`$select=id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,signInActivity&`$top=999" $H
    Save-Json $ua 'users-signin-activity.json' | Out-Null
    Write-Host "  $(@($ua).Count) account(s) with sign-in activity" -ForegroundColor Yellow
} catch { $why = Get-ErrorText $_; Write-Warning "User sign-in activity needs AuditLog.Read.All + Entra ID P1: $why"; Save-Json @{ error = $why } 'users-signin-activity-ERROR.json' | Out-Null }

Write-Host 'Graph: sign-in sample...' -ForegroundColor Cyan
try { Save-Json (Invoke-RestMethod -Uri "$G/auditLogs/signIns?`$top=200" -Headers $H).value 'signins-sample.json' | Out-Null }
catch { Write-Warning "Sign-in logs need AuditLog.Read.All + Entra P1: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } 'signins-sample-ERROR.json' | Out-Null }

Write-Host "Graph sweep done. $(@($apps).Count) apps, $(@($sps).Count) service principals." -ForegroundColor Green
