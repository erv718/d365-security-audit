# graph-identity-plus.ps1 - extra read-only Entra identity checks.
# Covers: authentication methods policy, security defaults, PIM eligible/active role
# assignments, Intune compliance + device overview, named locations, guests by home domain.
# Read-only. GET/paged reads only. Every area is isolated so one failure never stops the sweep.
#
# Endpoint -> application permission it needs (Microsoft Graph v1.0 reference, all read-only):
#   policies/authenticationMethodsPolicy                Policy.Read.All (least-privileged alternative: Policy.Read.AuthenticationMethod)
#   policies/identitySecurityDefaultsEnforcementPolicy  Policy.Read.All
#   roleManagement/directory/role*ScheduleInstances     RoleManagement.Read.Directory
#   deviceManagement/*                                  DeviceManagement*.Read.All, plus an Intune licence in the tenant
# A 403 on any of these is a consent gap, not an endpoint problem; check-setup.ps1 probes each one
# and the *-ERROR.json written here carries the service's own error body for the exact reason.

. (Join-Path $PSScriptRoot '_common.ps1')

$tok = Get-Token 'https://graph.microsoft.com'
if (-not $tok) {
    Write-Warning 'No Microsoft Graph token (app registration missing or its token failed). Skipping the extra identity checks; other sweeps still run.'
    return
}
$H    = @{ Authorization = "Bearer $tok" }
$Hadv = @{ Authorization = "Bearer $tok"; ConsistencyLevel = 'eventual' }
$G    = 'https://graph.microsoft.com/v1.0'

Write-Host 'Graph+: authentication methods policy...' -ForegroundColor Cyan
try {
    $amp = Invoke-RestMethod -Uri "$G/policies/authenticationMethodsPolicy" -Headers $H
    Save-Json $amp 'authentication-methods-policy.json' | Out-Null
    $enabledMethods = @($amp.authenticationMethodConfigurations | Where-Object { $_.state -eq 'enabled' } | ForEach-Object { $_.id })
    if ($enabledMethods.Count) { Write-Host "  enabled methods: $($enabledMethods -join ', ')" -ForegroundColor Yellow }
} catch {
    $e = Get-ErrorText $_
    Write-Warning "Auth methods policy failed: $e"
    Save-Json @{ error = $e; note = 'Needs Policy.Read.All (or Policy.Read.AuthenticationMethod) as an application permission with admin consent.' } 'authentication-methods-policy-ERROR.json' | Out-Null
}

Write-Host 'Graph+: security defaults...' -ForegroundColor Cyan
try {
    $sd = Invoke-RestMethod -Uri "$G/policies/identitySecurityDefaultsEnforcementPolicy" -Headers $H
    Save-Json $sd 'security-defaults.json' | Out-Null
    Write-Host "  security defaults enabled: $($sd.isEnabled)" -ForegroundColor Yellow
} catch {
    $e = Get-ErrorText $_
    Write-Warning "Security defaults failed: $e"
    Save-Json @{ error = $e; note = 'Needs Policy.Read.All as an application permission with admin consent.' } 'security-defaults-ERROR.json' | Out-Null
}

$pimNote = 'Needs RoleManagement.Read.Directory as an application permission with admin consent. If the error body says the tenant is not licensed (AadPremiumLicenseRequired), Entra ID P2 / PIM is not in use and every admin assignment is standing access.'

Write-Host 'Graph+: PIM eligible role assignments...' -ForegroundColor Cyan
try {
    $pimElig = Invoke-Paged "$G/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=roleDefinition(`$select=displayName)" $H
    Save-Json $pimElig 'pim-eligible.json' | Out-Null
    if (@($pimElig).Count -eq 0) { Write-Host '  0 eligible assignments - PIM not in use (all admin access is standing).' -ForegroundColor Yellow }
    else { Write-Host "  $(@($pimElig).Count) eligible assignments." -ForegroundColor Yellow }
} catch {
    $e = Get-ErrorText $_
    Write-Warning "PIM eligible failed: $e"
    Save-Json @{ error = $e; note = $pimNote } 'pim-eligible-ERROR.json' | Out-Null
}

Write-Host 'Graph+: PIM active (permanent + activated) role assignments...' -ForegroundColor Cyan
try {
    $pimActive = Invoke-Paged "$G/roleManagement/directory/roleAssignmentScheduleInstances?`$expand=roleDefinition(`$select=displayName)" $H
    Save-Json $pimActive 'pim-active.json' | Out-Null
    $permanent = @($pimActive | Where-Object { "$($_.assignmentType)" -eq 'Assigned' -and -not $_.endDateTime }).Count
    Write-Host "  $(@($pimActive).Count) active assignments ($permanent permanent)." -ForegroundColor Yellow
} catch {
    $e = Get-ErrorText $_
    Write-Warning "PIM active failed: $e"
    Save-Json @{ error = $e; note = $pimNote } 'pim-active-ERROR.json' | Out-Null
}

Write-Host 'Graph+: Intune device compliance policies...' -ForegroundColor Cyan
try {
    $comp = Invoke-Paged "$G/deviceManagement/deviceCompliancePolicies" $H
    Save-Json $comp 'intune-compliance-policies.json' | Out-Null
    Write-Host "  $(@($comp).Count) compliance policies." -ForegroundColor Yellow
} catch {
    $e = Get-ErrorText $_
    Write-Warning "Intune compliance policies failed: $e"
    Save-Json @{ error = $e; note = 'Needs DeviceManagementConfiguration.Read.All as an application permission with admin consent, and an active Intune licence in the tenant.' } 'intune-compliance-policies-ERROR.json' | Out-Null
}

Write-Host 'Graph+: Intune managed device overview...' -ForegroundColor Cyan
try {
    $devOv = Invoke-RestMethod -Uri "$G/deviceManagement/managedDeviceOverview" -Headers $H
    Save-Json $devOv 'intune-device-overview.json' | Out-Null
} catch {
    $e = Get-ErrorText $_
    Write-Warning "Intune device overview failed: $e"
    Save-Json @{ error = $e; note = 'Needs DeviceManagementManagedDevices.Read.All as an application permission with admin consent, and an active Intune licence in the tenant.' } 'intune-device-overview-ERROR.json' | Out-Null
}

Write-Host 'Graph+: Conditional Access named locations...' -ForegroundColor Cyan
try {
    $named = Invoke-Paged "$G/identity/conditionalAccess/namedLocations" $H
    Save-Json $named 'ca-named-locations.json' | Out-Null
    Write-Host "  $(@($named).Count) named locations." -ForegroundColor Yellow
} catch {
    $e = Get-ErrorText $_
    Write-Warning "Named locations need Policy.Read.All: $e"
    Save-Json @{ error = $e } 'ca-named-locations-ERROR.json' | Out-Null
}

Write-Host 'Graph+: guests by home domain...' -ForegroundColor Cyan
try {
    $guests = Invoke-Paged "$G/users?`$filter=userType eq 'Guest'&`$select=userPrincipalName&`$top=999&`$count=true" $Hadv
    $domains = foreach ($u in $guests) {
        $upn = $u.userPrincipalName
        if (-not $upn) { continue }
        if ($upn -like '*#EXT#*') {
            $left = $upn.Substring(0, $upn.IndexOf('#EXT#'))
            $i = $left.LastIndexOf('_')
            if ($i -ge 0) { $left.Substring($i + 1) } else { $left }
        } elseif ($upn -like '*@*') {
            $upn.Split('@')[-1]
        } else {
            $upn
        }
    }
    $byDomain = $domains | Group-Object | Sort-Object Count -Descending |
        ForEach-Object { [pscustomobject]@{ domain = $_.Name; count = $_.Count } }
    Save-Json @{ total = @($guests).Count; byDomain = @($byDomain) } 'guests-by-domain.json' | Out-Null
    Write-Host "  $(@($guests).Count) guests across $(@($byDomain).Count) home domains." -ForegroundColor Yellow
} catch {
    $e = Get-ErrorText $_
    Write-Warning "Guests by domain failed: $e"
    Save-Json @{ error = $e } 'guests-by-domain-ERROR.json' | Out-Null
}

Write-Host 'Graph+ identity sweep done.' -ForegroundColor Green
