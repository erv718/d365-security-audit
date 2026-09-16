# assessment-report.ps1 - turns the raw pulls in ./output into a Microsoft-style
# security assessment: the 8 domains / 29 checks of the Power Platform & D365
# Security Review (28 unique - 2.5 is an MS-template duplicate of 2.4), each marked
# Aligned / Partial / Gap / Not in use / Not checked / MANUAL, plus a "beyond the
# checklist" section of deeper technical findings.
#
# Every verdict is tied to a file in ./output. When the evidence file is missing, empty or
# unparseable, the check is "Not checked" (with the access that unlocks it), never a guessed Gap or
# Aligned; the two platform facts (1.1, 3.1) say so in their evidence. MANUAL checks
# carry the exact portal click-path. Read-only. Pure local processing.

. (Join-Path $PSScriptRoot '_common.ps1')
$out = Get-OutDir

# LJ: load one evidence file. Missing, empty or unparseable = $null (the check reads "Not
# checked"); a JSON [] stays an empty array (the check reads its zero verdict). -NoEnumerate
# keeps arrays intact on return; callers assign first and only then wrap in @( ), because
# @( ) around the call itself would nest the array (PowerShell 5.1 and 7).
function LJ($name) {
    $p = Join-Path $out $name
    if (-not (Test-Path $p)) { return $null }
    try {
        $raw = Get-Content $p -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { Write-Warning "assessment: $name is empty; treated as not read"; return $null }
        $r = $raw | ConvertFrom-Json
        if ($null -eq $r) { Write-Output -NoEnumerate @() } else { Write-Output -NoEnumerate $r }
    } catch { Write-Warning "assessment: $name could not be parsed; treated as not read ($($_.Exception.Message))"; $null }
}
function LFiles($pat) { Get-ChildItem $out -Filter $pat -ErrorAction SilentlyContinue }
function First($x)    { if ($null -eq $x) { return $null } if ($x -is [array]) { $x[0] } else { $x } }
function Have($x)     { $null -ne $x }
function Cnt($x)      { @($x | Where-Object { $null -ne $_ }).Count }
function Names($list, $max = 8) {
    $l = @($list | Where-Object { $_ })
    if ($l.Count -le $max) { return ($l -join ', ') }
    return (($l[0..($max - 1)] -join ', ') + " (+$($l.Count - $max) more)")
}
function EnvSku($e)   { "$($e.properties.environmentSku)" }
function EnvHasSg($e) {
    $sg = "$($e.properties.linkedEnvironmentMetadata.securityGroupId)"
    if (-not $sg) { $sg = "$($e.properties.securityGroupId)" }
    return ($sg -and $sg -ne '00000000-0000-0000-0000-000000000000')
}
# Does any DLP policy apply to the environment named $envName? $null = cannot tell.
# Policy objects are flat (environmentType / environments) but a properties wrapper is tolerated.
function DlpCovers($policies, $envName) {
    if (-not (Have $policies) -or -not $envName) { return $null }
    if ((Cnt $policies) -eq 0) { return $false }
    $known = $false
    foreach ($p in @($policies)) {
        $props = $p
        if ($p.properties -and $p.properties.environmentType) { $props = $p.properties }
        $type = "$($props.environmentType)"
        if (-not $type) { continue }
        $known = $true
        $listed = @($props.environments | ForEach-Object { if ($_.name) { "$($_.name)" } elseif ($_.id) { "$($_.id)".Split('/')[-1] } }) -contains $envName
        if ($type -eq 'AllEnvironments') { return $true }
        if (($type -eq 'OnlyEnvironments' -or $type -eq 'SingleEnvironment') -and $listed) { return $true }
        if ($type -eq 'ExceptEnvironments' -and -not $listed) { return $true }
    }
    if ($known) { return $false } else { return $null }
}

# ---------- pre-load / aggregate ----------
# Dataverse org settings come from two sweeps: dv-*-org.json (DATAVERSE_ENVIRONMENTS list)
# and dvplus-*-org-settings.json (auto-discovered environments); one environment can be in both.
$orgs = @{}
foreach ($f in @(LFiles 'dv-*-org.json') + @(LFiles 'dvplus-*-org-settings.json')) {
    $o = First (LJ $f.Name)
    if ($null -eq $o -or -not ($o.PSObject.Properties.Name -contains 'isauditenabled')) { continue }
    $key = if ($o.organizationid) { "$($o.organizationid)" } elseif ($o.name) { "$($o.name)" } else { $f.Name }
    if (-not $orgs.ContainsKey($key)) { $orgs[$key] = $o }
}
$orgList        = @($orgs.Values)
$envN           = $orgList.Count
$auditOn        = Cnt ($orgList | Where-Object { $_.isauditenabled -eq $true })
$retentionSet   = Cnt ($orgList | Where-Object { $_.auditretentionperiodv2 })
$userAccessOn   = Cnt ($orgList | Where-Object { $_.isuseraccessauditenabled -eq $true })
$readAuditKnown = Cnt ($orgList | Where-Object { $_.PSObject.Properties.Name -contains 'isreadauditenabled' })
$readAuditOn    = Cnt ($orgList | Where-Object { $_.isreadauditenabled -eq $true })

# Per-file loops count only files that parsed, so an unreadable file is "not read", never "zero".
$rolesFiles = @(LFiles 'dv-*-roles.json'); $rolesEnvN = 0; $customRoles = 0
foreach ($f in $rolesFiles) { $roles = LJ $f.Name; if ($null -eq $roles) { continue }; $rolesEnvN++; $customRoles += Cnt ($roles | Where-Object { $_.ismanaged -eq $false }) }

$ca = LJ 'ca-policies.json'
$caTotal     = Cnt $ca
$caOn        = Cnt ($ca | Where-Object { $_.state -eq 'enabled' })
$caMfa       = Cnt ($ca | Where-Object { $_.state -eq 'enabled' -and $_.grantControls.builtInControls -contains 'mfa' })
$caCompliant = Cnt ($ca | Where-Object { $_.state -eq 'enabled' -and $_.grantControls.builtInControls -contains 'compliantDevice' })

$pimElig   = LJ 'pim-eligible.json'
$pimActive = LJ 'pim-active.json'
$secDef    = LJ 'security-defaults.json'
$intune    = LJ 'intune-compliance-policies.json'
$devOv     = LJ 'intune-device-overview.json'
$guests    = LJ 'guest-count.json'
$guestDom  = LJ 'guests-by-domain.json'
$dlp       = LJ 'pp-dlp-policies.json'
$ppEnv     = LJ 'pp-environments.json'
$ppTenant  = LJ 'pp-tenant-settings.json'
$apps      = LJ 'applications.json'
$sps       = LJ 'servicePrincipals.json'
$asnGraph  = LJ 'appRoleAssignments-graph.json'
$asnExo    = LJ 'appRoleAssignments-exo.json'
$dirRoles  = LJ 'directoryRoles.json'
$signins   = LJ 'signins-sample.json'
$findings  = LJ 'FINDINGS-summary.json'

$pimEligN     = Cnt $pimElig
$pimActiveN   = Cnt $pimActive
$pimPermanent = Cnt ($pimActive | Where-Object { "$($_.assignmentType)" -eq 'Assigned' -and -not $_.endDateTime })
$sdOn         = ((Have $secDef) -and $secDef.isEnabled -eq $true)
$intuneN      = Cnt $intune
$devOverview  = $null
if (Have $devOv) { if ($devOv.value) { $devOverview = $devOv.value } else { $devOverview = $devOv } }
$riskyN       = Cnt ($findings | Where-Object { $_.Area -eq 'App access' })
$signinN      = Cnt $signins
$d365SignIns  = Cnt ($signins | Where-Object { "$($_.resourceDisplayName)" -match 'Dynamics|Dataverse|Common Data Service|Power ?Apps|Power Platform|Power Automate|Flow' })
$guestTotal   = $null
if ((Have $guestDom) -and $null -ne $guestDom.total) { $guestTotal = [int]$guestDom.total }
elseif ((Have $guests) -and $null -ne $guests.guestCount) { $guestTotal = [int]$guests.guestCount }
$domainN = 0; $topDomains = @()
if (Have $guestDom) {
    $byDom = @($guestDom.byDomain | Where-Object { $_ -and $_.domain })
    $domainN = $byDom.Count
    $topDomains = @($byDom | Sort-Object { [int]$_.count } -Descending | Select-Object -First 3 | ForEach-Object { "$($_.domain) ($($_.count))" })
}
$routing = $null
if ((Have $ppTenant) -and $ppTenant.powerPlatform -and $ppTenant.powerPlatform.governance) {
    $gov = $ppTenant.powerPlatform.governance
    if ($gov.PSObject.Properties.Name -contains 'enableDefaultEnvironmentRouting') { $routing = [bool]$gov.enableDefaultEnvironmentRouting }
}

$sentinelFiles = @(LFiles 'arm-*-sentinel.json'); $sentinelReadN = 0; $sentinelOn = $false; $wsN = 0
foreach ($f in $sentinelFiles) { $s = LJ $f.Name; if ($null -eq $s) { continue }; $sentinelReadN++; $wsN += Cnt $s; if ((Cnt ($s | Where-Object { $_.sentinelEnabled })) -gt 0) { $sentinelOn = $true } }
$logicFiles = @(LFiles 'arm-*-logicapps.json'); $logicReadN = 0; $logicApps = 0
foreach ($f in $logicFiles) { $x = LJ $f.Name; if ($null -eq $x) { continue }; $logicReadN++; $logicApps += Cnt $x }
$emailFiles = @(LFiles 'dvplus-*-emailprofiles.json'); $emailReadN = 0; $emailProfiles = 0
foreach ($f in $emailFiles) { $x = LJ $f.Name; if ($null -eq $x) { continue }; $emailReadN++; $emailProfiles += Cnt $x }
$mailboxFiles = @(LFiles 'dvplus-*-mailboxes.json'); $mailboxN = 0
foreach ($f in $mailboxFiles) { $m = First (LJ $f.Name); if ($m -and $null -ne $m.'@odata.count') { $mailboxN += [int]$m.'@odata.count' } elseif ($m) { $mailboxN += Cnt $m.sample } }
$queueFiles = @(LFiles 'dvplus-*-queues.json'); $queueN = 0
foreach ($f in $queueFiles) { $q = First (LJ $f.Name); if ($q -and $null -ne $q.'@odata.count') { $queueN += [int]$q.'@odata.count' } elseif ($q) { $queueN += Cnt $q.sample } }
$fpFiles = @(LFiles 'dvplus-*-fieldpermissions.json') + @(LFiles 'dv-*-fieldsec.json'); $fpReadN = 0; $fieldPerms = 0
foreach ($f in $fpFiles) { $x = LJ $f.Name; if ($null -eq $x) { continue }; $fpReadN++; $fieldPerms += Cnt $x }

$expiredSecrets = 0
if (Have $apps) {
    $now = Get-Date
    foreach ($a in @($apps)) { foreach ($c in @($a.passwordCredentials) + @($a.keyCredentials)) { if ($c.endDateTime -and [datetime]$c.endDateTime -lt $now) { $expiredSecrets++ } } }
}

# Defender for Cloud plans. Only plan names documented in the Pricings API are judged; other
# names on Standard tier (e.g. FoundationalCspm, which is always on and free) are listed, not counted.
$defDocumented = @('VirtualMachines','SqlServers','AppServices','StorageAccounts','SqlServerVirtualMachines','KubernetesService','ContainerRegistry','KeyVaults','Dns','Arm','OpenSourceRelationalDatabases','CosmosDbs','Containers','CloudPosture','Api','AI')
$defFiles = @(LFiles 'arm-*-defender-pricings.json'); $defReadN = 0; $defStd = @(); $defFree = @(); $defOther = @()
foreach ($f in $defFiles) {
    $plans = LJ $f.Name
    if ($null -eq $plans) { continue }
    $defReadN++
    foreach ($p in @($plans)) {
        if (-not $p.name) { continue }
        $std = ("$($p.properties.pricingTier)" -eq 'Standard')
        if ($defDocumented -contains $p.name) { if ($std) { $defStd += $p.name } else { $defFree += $p.name } }
        elseif ($std) { $defOther += $p.name }
    }
}
$defStd   = @($defStd | Select-Object -Unique)
$defFree  = @($defFree | Where-Object { $defStd -notcontains $_ } | Select-Object -Unique)
$defOther = @($defOther | Select-Object -Unique)

$sqlServers = @(); foreach ($f in @(LFiles 'arm-*-sql.json')) { $srvs = LJ $f.Name; if ($null -eq $srvs) { continue }; $sqlServers += @($srvs | Where-Object { $_ }) }
$sqlN = $sqlServers.Count
$sqlTlsWeak  = @($sqlServers | Where-Object { $v = "$($_.properties.minimalTlsVersion)"; $v -and ($v -notin '1.2','1.3') })
$sqlTlsUnset = Cnt ($sqlServers | Where-Object { -not "$($_.properties.minimalTlsVersion)" })

# Environments. Microsoft does not allow a security group on Default or Developer environments,
# and Teams environments get their team's group automatically - only the rest are "eligible".
$envAll   = @($ppEnv | Where-Object { $_ -and $_.properties })
$envAllN  = $envAll.Count
$envDv    = @($envAll | Where-Object { $_.properties.linkedEnvironmentMetadata })
$envNoDvN = $envAllN - $envDv.Count
$envEligible = @($envDv | Where-Object { (EnvSku $_) -notin 'Default','Developer','Teams' })
$envBound    = @($envEligible | Where-Object { EnvHasSg $_ })
$envUnbound  = @($envEligible | Where-Object { -not (EnvHasSg $_) })
$managedN    = Cnt ($envAll | Where-Object { "$($_.properties.governanceConfiguration.protectionLevel)" -eq 'Standard' })
$unmanagedBySku = (@($envAll | Where-Object { "$($_.properties.governanceConfiguration.protectionLevel)" -ne 'Standard' } | Group-Object { EnvSku $_ } | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" })) -join ', '
$defaultEnv  = First (@($envAll | Where-Object { $_.properties.isDefault -eq $true }))
$defaultManaged = ($defaultEnv -and "$($defaultEnv.properties.governanceConfiguration.protectionLevel)" -eq 'Standard')
$defaultDlp  = $null
if ($defaultEnv) { $defaultDlp = DlpCovers $dlp "$($defaultEnv.name)" }
$regions     = (@($envAll | ForEach-Object { $_.properties.azureRegion } | Where-Object { $_ } | Select-Object -Unique)) -join ', '

# ---------- checks ----------
$checks = New-Object System.Collections.ArrayList
function Chk($no,$dom,$check,$status,$ev) { [void]$checks.Add([pscustomobject]@{ No=$no; Domain=$dom; Check=$check; Status=$status; Evidence=$ev }) }

# Domain 1 - Entra ID configuration
if (Have $ppEnv) {
    $s11 = 'Aligned'
    $e11 = "Platform fact, not a tenant setting: Dataverse/D365 online authenticate only through Entra ID. Verified: $($envDv.Count) Dataverse environment(s) inventoried from the Power Platform admin API$(if($d365SignIns){"; $d365SignIns of $signinN sampled sign-ins targeted Dataverse/Dynamics resources through Entra"}). Not verified: whether a federated IdP performs MFA that Entra never records (see the sign-in sample)."
} else {
    $s11 = 'Not checked'
    $e11 = 'Platform fact: D365 online authenticates only through Entra ID, but no environment inventory was read (Power Platform admin API not reachable), so nothing tenant-specific was verified.'
}
Chk '1.1' '1 Entra ID' 'Entra integrated with D365' $s11 $e11

if ($rolesEnvN -eq 0) { $s12 = 'Not checked'; $e12 = 'Security roles not read: set DATAVERSE_ENVIRONMENTS in .env so the basic Dataverse sweep pulls roles per environment.' }
elseif ($customRoles -eq 0) { $s12 = 'Gap'; $e12 = "0 custom security roles across $rolesEnvN environment(s) read - only built-in roles are ever assigned." }
else { $s12 = 'Partial'; $e12 = "$customRoles custom security role(s) across $rolesEnvN environment(s) read; whether they are least-privilege needs a role review." }
Chk '1.2' '1 Entra ID' 'Roles least privilege' $s12 $e12

if (-not (Have $ppEnv)) { $sgStatus = 'Not checked'; $sgEv = 'Environment list not read (Power Platform admin API; register the app with New-PowerAppManagementApp).' }
elseif ($envEligible.Count -eq 0) { $sgStatus = 'Not checked'; $sgEv = "No environment where a security group applies: Microsoft does not allow one on Default or Developer environments, Teams environments are bound to their team automatically, and $envNoDvN of the $envAllN environment(s) read have no Dataverse." }
else {
    if ($envBound.Count -eq $envEligible.Count) { $sgStatus = 'Aligned' } elseif ($envBound.Count -gt 0) { $sgStatus = 'Partial' } else { $sgStatus = 'Gap' }
    $sgEv = "$($envBound.Count) of $($envEligible.Count) eligible environment(s) have a security group (eligible = has Dataverse and is not Default, Developer or Teams: Microsoft forbids a group on the first two and sets it automatically on Teams; $envNoDvN without Dataverse not counted)."
    if ($envUnbound.Count) { $sgEv += ' Without one: ' + (Names ($envUnbound | ForEach-Object { "$($_.properties.displayName) [$(EnvSku $_)]" })) + '. Fix: PPAC > Manage > Environments > (env) > Edit > Security group.' }
}
Chk '1.3' '1 Entra ID' 'Security group restricts environment access' $sgStatus $sgEv

if (-not (Have $ca)) { $s14 = 'Not checked'; $e14 = 'Conditional Access policies not read (needs Policy.Read.All with admin consent).' }
elseif ($caMfa -eq 0 -and $sdOn) { $s14 = 'Partial'; $e14 = "Security defaults are ON (baseline MFA for everyone); $caTotal Conditional Access policies, none enforcing MFA (CA needs Entra ID P1)." }
elseif ($caTotal -eq 0) { $s14 = 'Gap'; $e14 = 'No Conditional Access policies exist and security defaults are off.' }
elseif ($caMfa -eq 0) { $s14 = 'Gap'; $e14 = "$caTotal policies, $caOn enabled, none enforce MFA." }
else { $s14 = 'Aligned'; $e14 = "$caTotal policies, $caOn enabled, $caMfa enforce MFA." }
if ((Have $secDef) -and $s14 -ne 'Partial') { $e14 += " Security defaults: $(if($sdOn){'ON'}else{'off'})." }
Chk '1.4' '1 Entra ID' 'Conditional Access' $s14 $e14

$intuneHint = 'Intune not read (needs DeviceManagementConfiguration.Read.All with admin consent, and an active Intune licence).'
if (-not (Have $intune)) { $s15 = 'Not checked'; $e15 = $intuneHint }
elseif ($intuneN -eq 0) { $s15 = 'Gap'; $e15 = 'Intune readable but 0 device compliance policies exist.' }
else { $s15 = 'Partial'; $e15 = "$intuneN compliance policies found$(if($devOverview -and $null -ne $devOverview.enrolledDeviceCount){"; $($devOverview.enrolledDeviceCount) enrolled device(s)"}); assignment scope to review." }
Chk '1.5' '1 Entra ID' 'Intune device management' $s15 $e15

if (-not (Have $intune)) { $s16 = 'Not checked'; $e16 = $intuneHint }
elseif ($intuneN -eq 0) { $s16 = 'Gap'; $e16 = 'No Intune compliance policy exists, so no device state can be required for D365 access.' }
else { $s16 = 'Partial'; $e16 = "$intuneN Intune compliance policies; $caCompliant enabled Conditional Access policies require a compliant device$(if($caCompliant -eq 0){' - nothing ties device compliance to access, so it is not enforced for D365'}else{' (confirm they target Dataverse/D365)'})." }
Chk '1.6' '1 Entra ID' 'Device compliance enforced for D365' $s16 $e16

# Domain 2 - Authentication
if (-not (Have $apps)) { $s21 = 'Not checked'; $e21 = 'App registrations not read (needs Application.Read.All with admin consent).' }
else {
    if ($riskyN -gt 0) { $s21 = 'Partial' } else { $s21 = 'Aligned' }
    $e21 = "$(Cnt $apps) app registrations$(if(Have $sps){" and $(Cnt $sps) service principals"}) inventoried; $riskyN high-privilege tenant-wide permission(s) flagged in the findings. Not verified: that each integration runs under its own least-privilege identity."
}
Chk '2.1' '2 Authentication' 'Service-to-service app access' $s21 $e21

if ((Have $apps) -and (Have $sps)) {
    $s22 = 'Partial'
    $e22 = "Inventory produced by this run: $(Cnt $apps) app registrations, $(Cnt $sps) service principals, $(Cnt $asnGraph) Graph + $(Cnt $asnExo) Exchange app-role assignments, $(Cnt $dirRoles) directory roles with members$(if($null -ne $guestTotal){", $guestTotal guest accounts"}). Not verified: that an owner reviews this inventory on a schedule (a process, not a setting)."
} else { $s22 = 'Not checked'; $e22 = 'Inventory incomplete: applications.json or servicePrincipals.json not read (needs Application.Read.All with admin consent).' }
Chk '2.2' '2 Authentication' 'App/user access inventory' $s22 $e22

if (-not (Have $pimElig)) { $s23 = 'Not checked'; $e23 = 'PIM not read (needs RoleManagement.Read.Directory with admin consent; if pim-eligible-ERROR.json cites a licence, Entra ID P2/PIM is not in use and all admin access is standing).' }
elseif ($pimEligN -eq 0) { $s23 = 'Gap'; $e23 = "0 PIM-eligible assignments - every admin role is standing (permanent) access$(if(Have $pimActive){"; $pimActiveN active assignment(s), $pimPermanent permanent"})." }
else { $s23 = 'Aligned'; $e23 = "$pimEligN PIM-eligible (just-in-time) assignment(s)$(if(Have $pimActive){"; $pimActiveN active, $pimPermanent of them permanent - review those"})." }
Chk '2.3' '2 Authentication' 'PIM / segregation of duties' $s23 $e23
Chk '2.4' '2 Authentication' 'Security groups restrict environment access' $sgStatus ('Same evidence as 1.3: ' + $sgEv)
Chk '2.5' '2 Authentication' 'Security groups (MS-template duplicate of 2.4)' $sgStatus 'Duplicate of 2.4 in the Microsoft template - same verdict; excluded from the tally.'

# Domain 3 - Data security
$e31 = 'Platform fact, not read from your tenant: Dataverse/D365 encrypt data at rest (Microsoft-managed keys by default) and in transit (TLS 1.2+).'
if ($sqlN -gt 0) {
    $e31 += " Verified from Azure: $($sqlN - $sqlTlsWeak.Count - $sqlTlsUnset) of $sqlN SQL server(s) enforce minimum TLS 1.2$(if($sqlTlsWeak.Count){'; older TLS still accepted on: ' + (Names ($sqlTlsWeak | ForEach-Object { $_.name }))})."
} else { $e31 += ' Nothing tenant-specific verified (no Azure SQL servers read).' }
$e31 += ' Not verified: customer-managed keys - PPAC > Manage > Environments > (env) > See all > Encryption.'
Chk '3.1' '3 Data security' 'Encryption at rest / in transit' $(if($sqlTlsWeak.Count -gt 0){'Partial'}else{'Aligned'}) $e31
Chk '3.2' '3 Data security' 'Customer Lockbox + consent' 'MANUAL' "Tenant setting not exposed to this app. Confirm: PPAC > Manage > Tenant settings > Customer Lockbox (enable); requests under Security > Compliance > Customer Lockbox. Note: the policy only applies to Managed Environments$(if(Have $ppEnv){" ($managedN of $envAllN here)"})."
Chk '3.3' '3 Data security' 'PII / sensitivity labels' 'MANUAL' 'Confirm in the Microsoft Purview portal (purview.microsoft.com) > Solutions > Information Protection > Sensitivity labels, and Policies > Auto-labeling policies; Dataverse columns are labeled through Purview Data Map (each Dataverse environment registered as a data source).'
if ($envN -eq 0) { $s34 = 'Not checked'; $e34 = 'Dataverse org settings not read (no environment reachable as an Application User).' }
elseif ($retentionSet -gt 0) { $s34 = 'Partial'; $e34 = "Audit retention set in $retentionSet of $envN environment(s); broader retention to confirm in Purview (purview.microsoft.com > Solutions > Data Lifecycle Management)." }
else { $s34 = 'Gap'; $e34 = "Audit retention set in 0 of $envN environment(s) (PPAC > Manage > Environments > (env) > Settings > Audit and logs > Audit settings > Retain these logs for)." }
Chk '3.4' '3 Data security' 'Data retention' $s34 $e34
if ($emailReadN -eq 0) { $s35 = 'Not checked'; $e35 = 'Email server profiles not read (no environment reachable as an Application User).' }
elseif ($emailProfiles -gt 0) { $s35 = 'Partial'; $e35 = "$emailProfiles email server profile(s) across $($emailReadN) environment(s); server-side sync auth (OAuth vs basic) to confirm per profile." }
else { $s35 = 'Not in use'; $e35 = "0 email server profiles in $($emailReadN) environment(s)." }
Chk '3.5' '3 Data security' 'Record sync / Outlook' $s35 $e35
if ($emailReadN -eq 0) { $s36 = 'Not checked'; $e36 = 'Mailboxes/queues not read (no environment reachable as an Application User).' }
elseif ($emailProfiles -le $emailReadN) { $s36 = 'Not in use'; $e36 = "Only the default email profile per environment ($emailProfiles across $($emailReadN)); $mailboxN mailbox record(s), $queueN queue(s) - no custom mailbox integration in active use." }
else { $s36 = 'Partial'; $e36 = "$emailProfiles email profiles across $($emailReadN) environment(s) (more than the default), $mailboxN mailbox record(s), $queueN queue(s); review which integrations are approved." }
Chk '3.6' '3 Data security' 'Mailbox / queue integration' $s36 $e36

# Domain 4 - Auditing & monitoring
if ($envN -eq 0) { $s41 = 'Not checked'; $e41 = 'Dataverse org settings not read (no environment reachable as an Application User).' }
elseif ($auditOn -eq 0) { $s41 = 'Gap'; $e41 = "Org auditing OFF in all $envN environment(s) read (PPAC > Manage > Environments > (env) > Settings > Audit and logs > Audit settings > Start auditing)." }
elseif ($auditOn -lt $envN) { $s41 = 'Partial'; $e41 = "Org auditing ON in $auditOn of $envN environment(s) read." }
else { $s41 = 'Aligned'; $e41 = "Org auditing ON in all $envN environment(s) read." }
Chk '4.1' '4 Auditing' 'D365 auditing enabled' $s41 $e41
$e42 = 'Depends on 4.1.'
if ($envN -gt 0) {
    $e42 += " User-access auditing ON in $userAccessOn of $envN"
    if ($readAuditKnown -gt 0) { $e42 += "; read-log auditing ON in $readAuditOn of $readAuditKnown" }
    $e42 += ' environment(s).'
}
Chk '4.2' '4 Auditing' 'Events / user activity logged' $(if($envN -eq 0){'Not checked'}elseif($auditOn -eq 0){'Gap'}else{'Partial'}) $e42
if ($sentinelReadN -eq 0) { $s43 = 'Not checked'; $e43 = 'Azure Log Analytics/Sentinel not read (needs Reader on the subscriptions).' }
elseif ($sentinelOn) { $s43 = 'Partial'; $e43 = "Sentinel enabled on at least one of $wsN Log Analytics workspace(s); whether Power Platform/Dataverse logs are ingested is not verified." }
else { $s43 = 'Gap'; $e43 = "No Sentinel onboarding on $wsN Log Analytics workspace(s) across $($sentinelReadN) subscription(s)." }
Chk '4.3' '4 Auditing' 'SIEM / monitoring over Power Platform' $s43 $e43
Chk '4.4' '4 Auditing' 'Purview / Sentinel integration' $(if($sentinelOn){'Partial'}else{'Not checked'}) $(if($sentinelOn){'Sentinel state read; Purview audit to confirm: purview.microsoft.com > Solutions > Audit.'}else{'Sentinel not found or not read; Purview audit to confirm manually: purview.microsoft.com > Solutions > Audit.'})

# Domain 5 - Security settings
if ($rolesEnvN -eq 0) { $s51 = 'Not checked'; $e51 = 'Security roles not read: set DATAVERSE_ENVIRONMENTS in .env so the basic Dataverse sweep pulls roles.' }
elseif ($customRoles -eq 0) { $s51 = 'Gap'; $e51 = "0 custom roles in $rolesEnvN environment(s) read - only built-in roles available to assign." }
else { $s51 = 'Partial'; $e51 = "$customRoles custom role(s) in $rolesEnvN environment(s) read; privilege depth per role to review." }
Chk '5.1' '5 Security settings' 'Security role design' $s51 $e51
if ($fpReadN -eq 0) { $s52 = 'Not checked'; $e52 = 'Field security profiles/permissions not read (no environment reachable as an Application User).' }
elseif ($fieldPerms -gt 0) { $s52 = 'Partial'; $e52 = "$fieldPerms field-security permission(s)/profile(s) across $($fpReadN) file(s); business-unit and record-level design to review." }
else { $s52 = 'Gap'; $e52 = "0 field-security permissions/profiles in $($fpReadN) environment(s) read - no column-level security in use." }
Chk '5.2' '5 Security settings' 'Field-level / record / BU security' $s52 $e52
$dlpN = Cnt $dlp
if (-not (Have $dlp)) { $s53 = 'Not checked'; $e53 = 'DLP policies not read (needs the app registered as a Power Platform management app: New-PowerAppManagementApp).' }
elseif ($dlpN -eq 0) { $s53 = 'Gap'; $e53 = 'No DLP (connector data) policy exists - any connector can be combined with any other in every environment. Fix: PPAC > Security > Data and privacy > Data policy > New Policy.' }
else {
    if ($defaultDlp -eq $true) { $s53 = 'Aligned' } else { $s53 = 'Partial' }
    $e53 = "$dlpN DLP polic$(if($dlpN -eq 1){'y'}else{'ies'}); default environment covered: $(if($defaultDlp -eq $true){'yes'}elseif($defaultDlp -eq $false){'NO'}else{'unknown'}). Not verified: which connectors are blocked or business-only."
}
Chk '5.3' '5 Security settings' 'DLP / IRM / classification' $s53 $e53

# Domain 6 - Integration security
Chk '6.1' '6 Integration' 'External integration security' $(if($logicReadN -eq 0){'Not checked'}else{'Partial'}) $(if($logicReadN -eq 0){'Logic Apps not read (needs Reader on the subscriptions).'}else{"$logicApps Logic App workflow(s) inventoried across $($logicReadN) subscription(s); per-integration auth to review."})
Chk '6.2' '6 Integration' 'API keys / credentials / tokens' $(if(-not (Have $apps)){'Not checked'}elseif($expiredSecrets -gt 0){'Gap'}else{'Partial'}) $(if(-not (Have $apps)){'App credentials not read (needs Application.Read.All with admin consent).'}else{"$expiredSecrets expired app credential(s) still present across $(Cnt $apps) app registrations; secret rotation/vaulting practice to confirm."})

# Domain 7 - Incident response
Chk '7.1' '7 Incident response' 'Incident response plan' 'MANUAL' 'A document/process - no API can confirm it exists. Collect: the written IR plan, named owners for Entra / Power Platform / Azure incidents, and the last exercise date. Check alerts are being worked: Microsoft Defender portal (security.microsoft.com) > Incidents & alerts.'
$defPath = 'Azure portal > Microsoft Defender for Cloud > Environment settings > (subscription) > Defender plans'
if ($defReadN -eq 0) { $s72 = 'MANUAL'; $e72 = "Defender for Cloud plans not read (needs Reader on the subscriptions). Confirm at $defPath; the pen-test program itself is a process to confirm manually." }
elseif ($defStd.Count -gt 0) { $s72 = 'Partial'; $e72 = "Defender for Cloud plans on Standard tier in $($defReadN) subscription(s) read: $($defStd -join ', ')$(if($defFree.Count){"; still Free: $($defFree -join ', ')"})$(if($defOther.Count){"; other Standard entries not counted: $($defOther -join ', ')"}). Partial proxy only - vulnerability scanning covers those workloads; a pen-test program is a manual confirmation." }
else { $s72 = 'MANUAL'; $e72 = "All $($defFree.Count) documented Defender for Cloud plans are on the Free tier in $($defReadN) subscription(s) read$(if($defOther.Count){" (Standard entries not counted: $($defOther -join ', '))"}) - no paid vulnerability scanning. Enable at $defPath; confirm the pen-test program manually." }
Chk '7.2' '7 Incident response' 'Vulnerability scanning / pen testing' $s72 $e72

# Domain 8 - Compliance
$e81Path = 'Confirm: PPAC > Manage > Environments (Region column); M365 admin center (admin.microsoft.com) > Settings > Org settings > Organization profile > Data location.'
if ($regions) { $e81 = "Environment region(s): $regions. Whether that satisfies your obligations is a legal call. $e81Path" }
elseif (Have $ppEnv) { $e81 = "Environment inventory read but it lists no environment with a region; residency adequacy is a legal call. $e81Path" }
else { $e81 = "Region not read (Power Platform admin API); residency adequacy is a legal call. $e81Path" }
Chk '8.1' '8 Compliance' 'Data sovereignty / residency' 'MANUAL' $e81

# ---------- output ----------
$order  = @{ 'Gap'=0; 'Not in use'=1; 'Partial'=2; 'Not checked'=3; 'MANUAL'=4; 'Aligned'=5 }
$unique = @($checks | Where-Object { $_.No -ne '2.5' })
$tally  = $unique | Group-Object Status | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.Count)" }
$manual = @($unique | Where-Object { $_.Status -eq 'MANUAL' })

$md = @()
$md += "# D365 / Power Platform Security Assessment"
$md += ""
$md += "Based on Microsoft's Power Platform & Dynamics 365 Security Review: 8 domains, 29 checks (28 unique - 2.5 is an MS-template duplicate of 2.4), read from the live configuration and extended with deeper infrastructure and credential-hygiene checks that an interview-based review does not cover."
$md += ""
$md += "Generated read-only. Statuses: **Aligned** (good), **Partial** (okay, needs work), **Gap** (fix), **Not in use**, **Not checked** (evidence file missing - the evidence column names the access that unlocks it), **MANUAL** (no API can answer; the evidence column gives the portal click-path)."
$md += ""
$md += "Tally over the 28 unique checks: " + ($tally -join ' | ')
$md += ""
$md += "## The 29 checks (28 unique)"
$md += ""
$md += "| # | Domain | Check | Status | Evidence |"
$md += "|---|--------|-------|--------|----------|"
foreach ($c in $checks) { $md += "| $($c.No) | $($c.Domain) | $($c.Check) | **$($c.Status)** | $($c.Evidence) |" }
$md += ""
$md += "## Beyond the Microsoft checklist (extra security depth)"
$md += ""
$md += "### Power Platform governance (from the environment inventory)"
if (Have $ppEnv) {
    $md += "- Managed Environments: $managedN of $envAllN environment(s) (governanceConfiguration.protectionLevel = Standard)$(if($unmanagedBySku){"; not managed by type: $unmanagedBySku"}). Managed Environments unlock sharing limits, usage insights and Customer Lockbox (PPAC > Manage > Environments > ... > Enable Managed Environments)."
    $md += "- Environment security groups: $($envBound.Count) of $($envEligible.Count) eligible environment(s) bound (see 1.3)."
    if ($defaultEnv) {
        $dlpWord = if ($defaultDlp -eq $true) { 'covered by a DLP policy' } elseif ($defaultDlp -eq $false) { 'NOT covered by any DLP policy' } else { 'DLP coverage unknown (pp-dlp-policies.json not read)' }
        $md += "- Default environment '$($defaultEnv.properties.displayName)': $dlpWord; Managed = $(if($defaultManaged){'yes'}else{'no'}); security group not allowed on Default (Microsoft rule)$(if($null -ne $routing){"; default environment routing for new makers = $routing"}). Every licensed user can build here, so its DLP policy is the one that matters most."
    }
} else { $md += "- Environment inventory not read (Power Platform admin API)." }
$md += ""
$md += "### Guest accounts"
if ($null -ne $guestTotal) { $md += "- $guestTotal guest account(s)$(if($topDomains.Count){" across $domainN home domain(s); top 3: $($topDomains -join ', ')"}). Confirm access reviews cover them (Entra admin center > Identity governance > Access reviews)." }
else { $md += "- Guest count not read (needs User.Read.All with admin consent)." }
$md += ""
$md += "### Technical findings (from analyze.ps1)"
$md += ""
if (Have $findings) {
    $md += "| Severity | Area | Finding |"
    $md += "|----------|------|---------|"
    foreach ($f in @($findings)) { $md += "| $($f.Severity) | $($f.Area) | $($f.Finding) |" }
} else {
    $md += "_Run analyze.ps1 first to populate the extra technical findings (open firewalls, RDP exposure, expired secrets, over-privileged apps, legacy auth, Owner sprawl)._"
}
$md += ""
$md += "## Manual items (no API can answer these)"
foreach ($m in $manual) { $md += "- $($m.No) $($m.Check)" }
$md += "- Each evidence cell above names the portal path where a human confirms it."

$mdPath = Join-Path $out 'assessment-report.md'
$md -join "`n" | Out-File -Encoding utf8 $mdPath
Save-Json $checks 'assessment-report.json' | Out-Null

Write-Host ""
Write-Host "==================== ASSESSMENT (29 checks, 28 unique) ====================" -ForegroundColor Green
$checks | Sort-Object { $order[$_.Status] }, No | Format-Table No, Domain, Status, Check -AutoSize
Write-Host ("Tally (28 unique): " + ($tally -join '  |  ')) -ForegroundColor Yellow
Write-Host ("Report: {0}" -f $mdPath) -ForegroundColor Green
Write-Host "This maps Microsoft's assessment structure to your live config, plus the extra findings from analyze.ps1." -ForegroundColor Green
