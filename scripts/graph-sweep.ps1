# graph-sweep.ps1 - read-only pull of the Entra ID identity plane.
# Covers: app registrations + credential expiry, service principals, high-privilege
# app permissions, directory roles + members, Conditional Access, guest count, sign-in sample.
# Read-only. Every area is isolated so one 403 (partial consent) never stops the sweep.

. (Join-Path $PSScriptRoot '_common.ps1')

$tok = Get-Token 'https://graph.microsoft.com'
if (-not $tok) {
    Write-Warning 'No Microsoft Graph token (sign-in declined, timed out, or unavailable). Skipping the Entra ID sweep; other sweeps still run.'
    return
}
$H = @{ Authorization = "Bearer $tok"; ConsistencyLevel = 'eventual' }
$G = 'https://graph.microsoft.com/v1.0'

Write-Host 'Graph: applications...' -ForegroundColor Cyan
$apps = @()
try {
    $apps = Invoke-Paged "$G/applications?`$top=999&`$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials" $H
    Save-Json $apps 'applications.json' | Out-Null
} catch { Write-Warning "applications need Application.Read.All: $($_.Exception.Message)"; Save-Json @{ error = $_.Exception.Message } 'applications-ERROR.json' | Out-Null }

Write-Host 'Graph: service principals...' -ForegroundColor Cyan
$sps = @()
try {
    $sps = Invoke-Paged "$G/servicePrincipals?`$top=999&`$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,tags" $H
    Save-Json $sps 'servicePrincipals.json' | Out-Null
} catch { Write-Warning "service principals need Application.Read.All: $($_.Exception.Message)"; Save-Json @{ error = $_.Exception.Message } 'servicePrincipals-ERROR.json' | Out-Null }

Write-Host 'Graph: app-role assignments (Graph + Exchange)...' -ForegroundColor Cyan
try {
    foreach ($pair in @(@('graph','00000003-0000-0000-c000-000000000000'), @('exo','00000002-0000-0ff1-ce00-000000000000'))) {
        $sp = $sps | Where-Object { $_.appId -eq $pair[1] } | Select-Object -First 1
        if (-not $sp) { continue }
        $full = Invoke-RestMethod -Uri "$G/servicePrincipals/$($sp.id)?`$select=appRoles" -Headers $H
        Save-Json $full.appRoles "appRoleDefinitions-$($pair[0]).json" | Out-Null
        $asn = Invoke-Paged "$G/servicePrincipals/$($sp.id)/appRoleAssignedTo?`$top=999" $H
        Save-Json $asn "appRoleAssignments-$($pair[0]).json" | Out-Null
    }
} catch { Write-Warning "app-role assignments failed: $($_.Exception.Message)"; Save-Json @{ error = $_.Exception.Message } 'appRoleAssignments-ERROR.json' | Out-Null }

Write-Host 'Graph: directory roles + members...' -ForegroundColor Cyan
try {
    $dirRoles = Invoke-Paged "$G/directoryRoles" $H
    $roleOut = foreach ($r in $dirRoles) {
        $members = Invoke-Paged "$G/directoryRoles/$($r.id)/members?`$select=id,displayName,userPrincipalName" $H
        [pscustomobject]@{ role = $r.displayName; memberCount = $members.Count; members = @($members | ForEach-Object { $_.userPrincipalName }) }
    }
    Save-Json $roleOut 'directoryRoles.json' | Out-Null
} catch { Write-Warning "directory roles need RoleManagement.Read.Directory (+ User.Read.All for names): $($_.Exception.Message)"; Save-Json @{ error = $_.Exception.Message } 'directoryRoles-ERROR.json' | Out-Null }

Write-Host 'Graph: Conditional Access policies...' -ForegroundColor Cyan
try { Save-Json (Invoke-Paged "$G/identity/conditionalAccess/policies" $H) 'ca-policies.json' | Out-Null }
catch { Write-Warning "CA policies need Policy.Read.All: $($_.Exception.Message)"; Save-Json @{ error = $_.Exception.Message } 'ca-policies-ERROR.json' | Out-Null }

Write-Host 'Graph: guest count...' -ForegroundColor Cyan
try {
    $gc = Invoke-RestMethod -Uri "$G/users/`$count?`$filter=userType eq 'Guest'" -Headers $H
    Save-Json @{ guestCount = $gc } 'guest-count.json' | Out-Null
    Write-Host "  tenant-wide guests: $gc" -ForegroundColor Yellow
} catch { Write-Warning "Guest count failed: $($_.Exception.Message)"; Save-Json @{ error = $_.Exception.Message } 'guest-count-ERROR.json' | Out-Null }

Write-Host 'Graph: sign-in sample...' -ForegroundColor Cyan
try { Save-Json (Invoke-RestMethod -Uri "$G/auditLogs/signIns?`$top=200" -Headers $H).value 'signins-sample.json' | Out-Null }
catch { Write-Warning "Sign-in logs need AuditLog.Read.All + Entra P1: $($_.Exception.Message)"; Save-Json @{ error = $_.Exception.Message } 'signins-sample-ERROR.json' | Out-Null }

Write-Host "Graph sweep done. $(@($apps).Count) apps, $(@($sps).Count) service principals." -ForegroundColor Green
