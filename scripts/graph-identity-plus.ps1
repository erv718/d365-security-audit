# graph-identity-plus.ps1 - extra read-only Entra identity checks.
# Covers: authentication methods policy, security defaults, PIM eligible/active role
# assignments, Intune compliance + device overview, named locations, guests by home domain.
# Read-only. GET/paged reads only. Every area is isolated so one failure never stops the sweep.

. (Join-Path $PSScriptRoot '_common.ps1')

$tok = Get-Token 'https://graph.microsoft.com'
if (-not $tok) { throw 'No Microsoft Graph token.' }
$H    = @{ Authorization = "Bearer $tok" }
$Hadv = @{ Authorization = "Bearer $tok"; ConsistencyLevel = 'eventual' }
$G    = 'https://graph.microsoft.com/v1.0'

Write-Host 'Graph+: authentication methods policy...' -ForegroundColor Cyan
try {
    $amp = Invoke-RestMethod -Uri "$G/policies/authenticationMethodsPolicy" -Headers $H
    Save-Json $amp 'authentication-methods-policy.json' | Out-Null
} catch {
    Write-Warning "Auth methods policy failed: $($_.Exception.Message)"
    Save-Json @{ error = $_.Exception.Message } 'authentication-methods-policy-ERROR.json' | Out-Null
}

Write-Host 'Graph+: security defaults...' -ForegroundColor Cyan
try {
    $sd = Invoke-RestMethod -Uri "$G/policies/identitySecurityDefaultsEnforcementPolicy" -Headers $H
    Save-Json $sd 'security-defaults.json' | Out-Null
    Write-Host "  security defaults enabled: $($sd.isEnabled)" -ForegroundColor Yellow
} catch {
    Write-Warning "Security defaults failed: $($_.Exception.Message)"
    Save-Json @{ error = $_.Exception.Message } 'security-defaults-ERROR.json' | Out-Null
}

Write-Host 'Graph+: PIM eligible role assignments...' -ForegroundColor Cyan
try {
    $pimElig = Invoke-Paged "$G/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=roleDefinition(`$select=displayName)" $H
    Save-Json $pimElig 'pim-eligible.json' | Out-Null
    if (@($pimElig).Count -eq 0) { Write-Host '  0 eligible assignments - PIM likely not in use.' -ForegroundColor Yellow }
    else { Write-Host "  $(@($pimElig).Count) eligible assignments." -ForegroundColor Yellow }
} catch {
    Write-Warning "PIM eligible failed (403/empty implies PIM not in use / no P2): $($_.Exception.Message)"
    Save-Json @{ error = $_.Exception.Message; note = 'PIM likely not in use or Entra ID P2 not licensed.' } 'pim-eligible-ERROR.json' | Out-Null
}

Write-Host 'Graph+: PIM active (permanent) role assignments...' -ForegroundColor Cyan
try {
    $pimActive = Invoke-Paged "$G/roleManagement/directory/roleAssignmentScheduleInstances?`$expand=roleDefinition(`$select=displayName)" $H
    Save-Json $pimActive 'pim-active.json' | Out-Null
    Write-Host "  $(@($pimActive).Count) active assignments." -ForegroundColor Yellow
} catch {
    Write-Warning "PIM active failed: $($_.Exception.Message)"
    Save-Json @{ error = $_.Exception.Message } 'pim-active-ERROR.json' | Out-Null
}

Write-Host 'Graph+: Intune device compliance policies...' -ForegroundColor Cyan
try {
    $comp = Invoke-Paged "$G/deviceManagement/deviceCompliancePolicies" $H
    Save-Json $comp 'intune-compliance-policies.json' | Out-Null
    Write-Host "  $(@($comp).Count) compliance policies." -ForegroundColor Yellow
} catch {
    Write-Warning "Intune compliance policies need DeviceManagementConfiguration.Read.All: $($_.Exception.Message)"
    Save-Json @{ error = $_.Exception.Message } 'intune-compliance-policies-ERROR.json' | Out-Null
}

Write-Host 'Graph+: Intune managed device overview...' -ForegroundColor Cyan
try {
    $devOv = Invoke-RestMethod -Uri "$G/deviceManagement/managedDeviceOverview" -Headers $H
    Save-Json $devOv 'intune-device-overview.json' | Out-Null
} catch {
    Write-Warning "Intune device overview failed: $($_.Exception.Message)"
    Save-Json @{ error = $_.Exception.Message } 'intune-device-overview-ERROR.json' | Out-Null
}

Write-Host 'Graph+: Conditional Access named locations...' -ForegroundColor Cyan
try {
    $named = Invoke-Paged "$G/identity/conditionalAccess/namedLocations" $H
    Save-Json $named 'ca-named-locations.json' | Out-Null
    Write-Host "  $(@($named).Count) named locations." -ForegroundColor Yellow
} catch {
    Write-Warning "Named locations need Policy.Read.All: $($_.Exception.Message)"
    Save-Json @{ error = $_.Exception.Message } 'ca-named-locations-ERROR.json' | Out-Null
}

Write-Host 'Graph+: guests by home domain...' -ForegroundColor Cyan
try {
    $guests = Invoke-Paged "$G/users?`$filter=userType eq 'Guest'&`$select=userPrincipalName&`$top=999" $Hadv
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
    Write-Warning "Guests by domain failed: $($_.Exception.Message)"
    Save-Json @{ error = $_.Exception.Message } 'guests-by-domain-ERROR.json' | Out-Null
}

Write-Host 'Graph+ identity sweep done.' -ForegroundColor Green
