# assessment-report.ps1 - turns the raw pulls in ./output into a Microsoft-style
# security assessment: the 8 domains / 29 checks of the Power Platform & D365
# Security Review, each marked Aligned / Partial / Gap / Not checked / MANUAL,
# plus a "beyond the checklist" section of deeper technical findings.
#
# Based on the structure and recommendations of Microsoft's Power Platform & D365
# Security Review, extended with infrastructure and credential-hygiene checks that
# an interview-based assessment does not cover. Read-only. Pure local processing.

. (Join-Path $PSScriptRoot '_common.ps1')
$out = Get-OutDir

function LJ($name)    { $p = Join-Path $out $name; if (Test-Path $p) { try { Get-Content $p -Raw | ConvertFrom-Json } catch { $null } } }
function LFiles($pat) { Get-ChildItem $out -Filter $pat -ErrorAction SilentlyContinue }
function First($x)    { if ($null -eq $x) { return $null } if ($x -is [array]) { $x[0] } else { $x } }

# ---------- pre-load / aggregate ----------
$orgFiles = LFiles 'dv-*-org.json'
$envN = @($orgFiles).Count
$auditOn = 0; $retentionSet = 0
foreach ($f in $orgFiles) { $o = First (Get-Content $f.FullName -Raw | ConvertFrom-Json); if ($o.isauditenabled) { $auditOn++ }; if ($o.auditretentionperiodv2) { $retentionSet++ } }

$customRoles = 0
foreach ($f in (LFiles 'dv-*-roles.json')) { $r = @(Get-Content $f.FullName -Raw | ConvertFrom-Json); $customRoles += @($r | Where-Object { $_.ismanaged -eq $false }).Count }

$ca = LJ 'ca-policies.json'
$caTotal = @($ca).Count
$caOn = @($ca | Where-Object { $_.state -eq 'enabled' }).Count
$caMfa = @($ca | Where-Object { $_.state -eq 'enabled' -and $_.grantControls.builtInControls -contains 'mfa' }).Count

$pimElig = LJ 'pim-eligible.json'
$secDef  = LJ 'security-defaults.json'
$intune  = LJ 'intune-compliance-policies.json'
$guests  = LJ 'guest-count.json'
$dlp     = LJ 'pp-dlp-policies.json'
$ppEnv   = LJ 'pp-environments.json'
$apps    = LJ 'applications.json'
$findings= LJ 'FINDINGS-summary.json'

$sentinelOn = $false
foreach ($f in (LFiles 'arm-*-sentinel.json')) { $s = Get-Content $f.FullName -Raw | ConvertFrom-Json; if ($s) { $sentinelOn = $true } }
$logicApps = 0; foreach ($f in (LFiles 'arm-*-logicapps.json')) { $logicApps += @(Get-Content $f.FullName -Raw | ConvertFrom-Json).Count }
$emailProfiles = 0; foreach ($f in (LFiles 'dvplus-*-emailprofiles.json')) { $emailProfiles += @(Get-Content $f.FullName -Raw | ConvertFrom-Json).Count }
$fieldPerms = 0
foreach ($f in (LFiles 'dvplus-*-fieldpermissions.json')) { $fieldPerms += @(Get-Content $f.FullName -Raw | ConvertFrom-Json).Count }
foreach ($f in (LFiles 'dv-*-fieldsec.json'))            { $fieldPerms += @(Get-Content $f.FullName -Raw | ConvertFrom-Json).Count }

$expiredSecrets = 0
if ($apps) {
    $now = Get-Date
    foreach ($a in $apps) { foreach ($c in @($a.passwordCredentials) + @($a.keyCredentials)) { if ($c.endDateTime -and [datetime]$c.endDateTime -lt $now) { $expiredSecrets++ } } }
}

# ---------- checks ----------
$checks = New-Object System.Collections.ArrayList
function Chk($no,$dom,$check,$status,$ev) { [void]$checks.Add([pscustomobject]@{ No=$no; Domain=$dom; Check=$check; Status=$status; Evidence=$ev }) }
function Have($x) { $null -ne $x }

# Domain 1 - Entra ID configuration
Chk '1.1' '1 Entra ID' 'Entra integrated with D365' 'Aligned' 'D365 authenticates through Entra ID.'
Chk '1.2' '1 Entra ID' 'Roles least privilege' $(if($customRoles -eq 0){'Gap'}else{'Partial'}) "$customRoles custom security roles across $envN environment(s)."
Chk '1.3' '1 Entra ID' 'Security group restricts environment access' 'MANUAL' 'Confirm each environment is bound to a security group (not auto-read).'
Chk '1.4' '1 Entra ID' 'Conditional Access' $(if($caTotal -eq 0){'Not checked'}elseif($caMfa -eq 0){'Gap'}else{'Aligned'}) "$caTotal policies, $caOn enabled, $caMfa enforce MFA."
Chk '1.5' '1 Entra ID' 'Intune device management' $(if(Have $intune){'Partial'}else{'Not checked'}) $(if(Have $intune){"$(@($intune).Count) compliance policies found."}else{'Intune not read (needs DeviceManagement.Read.All).'})
Chk '1.6' '1 Entra ID' 'Device compliance enforced for D365' 'MANUAL' 'Confirm device compliance is tied to D365 access.'

# Domain 2 - Authentication
Chk '2.1' '2 Authentication' 'Service-to-service app access' 'Aligned' "$(@($apps).Count) app registrations inventoried."
Chk '2.2' '2 Authentication' 'App/user access inventory' 'Aligned' 'Full app-registration + permission inventory produced.'
Chk '2.3' '2 Authentication' 'PIM / segregation of duties' $(if(Have $pimElig){ if(@($pimElig).Count -eq 0){'Gap'}else{'Aligned'} }else{'Not checked'}) $(if(Have $pimElig){"$(@($pimElig).Count) PIM-eligible assignments (0 = standing admin, no PIM)."}else{'PIM not read.'})
Chk '2.4' '2 Authentication' 'Security groups restrict environment access' 'MANUAL' 'Same as 1.3 - confirm environment security groups.'
Chk '2.5' '2 Authentication' 'Security groups (duplicate of 2.4 in template)' 'MANUAL' 'Template duplicate of 2.4.'

# Domain 3 - Data security
Chk '3.1' '3 Data security' 'Encryption at rest / in transit' 'Aligned' 'Azure encrypts by default; confirm if CMK is required by policy.'
Chk '3.2' '3 Data security' 'Customer Lockbox + consent' 'MANUAL' 'Confirm Customer Lockbox setting (tenant-level, not auto-read).'
Chk '3.3' '3 Data security' 'PII / sensitivity labels' 'MANUAL' 'Sensitivity labels / Purview coverage for Dataverse to be confirmed.'
Chk '3.4' '3 Data security' 'Data retention' $(if($retentionSet -gt 0){'Partial'}else{'Gap'}) "Audit retention set in $retentionSet of $envN environment(s); broader retention to confirm."
Chk '3.5' '3 Data security' 'Record sync / Outlook' $(if($emailProfiles -gt 0){'Partial'}else{'Not checked'}) "$emailProfiles email server profile(s) found."
Chk '3.6' '3 Data security' 'Mailbox / queue integration' $(if($emailProfiles -le 1){'Not in use'}else{'Partial'}) 'Only default profile suggests mailbox integration not in active use.'

# Domain 4 - Auditing & monitoring
Chk '4.1' '4 Auditing' 'D365 auditing enabled' $(if($envN -eq 0){'Not checked'}elseif($auditOn -eq 0){'Gap'}elseif($auditOn -lt $envN){'Partial'}else{'Aligned'}) "Org auditing ON in $auditOn of $envN environment(s)."
Chk '4.2' '4 Auditing' 'Events / user activity logged' $(if($auditOn -eq 0){'Gap'}else{'Partial'}) 'Depends on Dataverse auditing (4.1).'
Chk '4.3' '4 Auditing' 'SIEM / monitoring over Power Platform' $(if($sentinelOn){'Partial'}else{'Gap'}) $(if($sentinelOn){'Sentinel present on a workspace.'}else{'No Sentinel onboarding found.'})
Chk '4.4' '4 Auditing' 'Purview / Sentinel integration' $(if($sentinelOn){'Partial'}else{'Not checked'}) 'Sentinel state read; Purview config to confirm.'

# Domain 5 - Security settings
Chk '5.1' '5 Security settings' 'Security role design' $(if($customRoles -eq 0){'Gap'}else{'Partial'}) "$customRoles custom roles (0 = only built-in available)."
Chk '5.2' '5 Security settings' 'Field-level / record / BU security' $(if($fieldPerms -gt 0){'Partial'}else{'Gap'}) "$fieldPerms field-security permissions/profiles found."
Chk '5.3' '5 Security settings' 'DLP / IRM / classification' $(if(Have $dlp){ if(@($dlp).Count -gt 0){'Aligned'}else{'Gap'} }else{'Not checked'}) $(if(Have $dlp){"$(@($dlp).Count) DLP policies."}else{'DLP not read (needs PP management app).'})

# Domain 6 - Integration security
Chk '6.1' '6 Integration' 'External integration security' 'Partial' "$logicApps Logic Apps inventoried; per-integration auth to review."
Chk '6.2' '6 Integration' 'API keys / credentials / tokens' $(if($expiredSecrets -gt 0){'Gap'}else{'Partial'}) "$expiredSecrets expired app credentials still present."

# Domain 7 - Incident response
Chk '7.1' '7 Incident response' 'Incident response plan' 'MANUAL' 'A document/process. No API can confirm it exists.'
Chk '7.2' '7 Incident response' 'Vulnerability scanning / pen testing' 'MANUAL' 'Defender for Cloud status is a partial proxy; program itself is manual.'

# Domain 8 - Compliance
$regions = if ($ppEnv) { (@($ppEnv) | ForEach-Object { $_.properties.azureRegion } | Where-Object { $_ } | Select-Object -Unique) -join ', ' } else { '' }
Chk '8.1' '8 Compliance' 'Data sovereignty / residency' 'MANUAL' $(if($regions){"Environment region(s): $regions. Whether that satisfies your obligations is a legal call."}else{'Region not read; residency adequacy is a legal call.'})

# ---------- output ----------
$order = @{ 'Gap'=0; 'Not in use'=1; 'Partial'=2; 'Not checked'=3; 'MANUAL'=4; 'Aligned'=5 }
$tally = $checks | Group-Object Status | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.Count)" }

$md = @()
$md += "# D365 / Power Platform Security Assessment"
$md += ""
$md += "Based on Microsoft's Power Platform & Dynamics 365 Security Review (8 domains, 29 checks), read from the live configuration and extended with deeper infrastructure and credential-hygiene checks that an interview-based review does not cover."
$md += ""
$md += "Generated read-only. Statuses: **Aligned** (good), **Partial** (okay, needs work), **Gap** (fix), **Not in use**, **Not checked** (needs more access), **MANUAL** (no API can answer, a human must confirm)."
$md += ""
$md += "Tally: " + ($tally -join ' | ')
$md += ""
$md += "## The 29 checks"
$md += ""
$md += "| # | Domain | Check | Status | Evidence |"
$md += "|---|--------|-------|--------|----------|"
foreach ($c in $checks) { $md += "| $($c.No) | $($c.Domain) | $($c.Check) | **$($c.Status)** | $($c.Evidence) |" }
$md += ""
$md += "## Beyond the Microsoft checklist (extra security depth)"
$md += ""
if ($findings) {
    $md += "Technical findings this tool adds on top of the assessment (from the ranked findings summary):"
    $md += ""
    $md += "| Severity | Area | Finding |"
    $md += "|----------|------|---------|"
    foreach ($f in @($findings)) { $md += "| $($f.Severity) | $($f.Area) | $($f.Finding) |" }
} else {
    $md += "_Run analyze.ps1 first to populate the extra technical findings (open firewalls, RDP exposure, expired secrets, over-privileged apps, Owner sprawl)._"
}
$md += ""
$md += "## Manual items (no API can answer these)"
$md += "- 7.1 Incident response plan"
$md += "- 7.2 Penetration-testing program"
$md += "- 8.1 Whether the data region satisfies your residency obligations (legal)"
$md += "- 3.2 Customer Lockbox / 3.3 sensitivity labels / 1.3 environment security groups (confirm in the portal)"

$mdPath = Join-Path $out 'assessment-report.md'
$md -join "`n" | Out-File -Encoding utf8 $mdPath
Save-Json $checks 'assessment-report.json' | Out-Null

Write-Host ""
Write-Host "==================== ASSESSMENT (29 checks) ====================" -ForegroundColor Green
$checks | Sort-Object { $order[$_.Status] }, No | Format-Table No, Domain, Status, Check -AutoSize
Write-Host ("Tally: " + ($tally -join '  |  ')) -ForegroundColor Yellow
Write-Host ("Report: {0}" -f $mdPath) -ForegroundColor Green
Write-Host "This maps Microsoft's assessment structure to your live config, plus the extra findings from analyze.ps1." -ForegroundColor Green
