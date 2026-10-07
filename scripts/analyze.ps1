# analyze.ps1 - read the JSON in ./output and print a plain-language findings summary.
# Pure local processing. No network calls.

. (Join-Path $PSScriptRoot '_common.ps1')
$out = Get-OutDir
# Load: missing, empty or unparseable = $null (skipped with a warning, never aborts the run); a
# JSON [] stays an empty array. -NoEnumerate keeps arrays intact on return; callers assign first
# and only then wrap in @( ), because @( ) around the call itself would nest the array.
function Load($name) {
    $p = Join-Path $out $name
    if (-not (Test-Path $p)) { return $null }
    try {
        $raw = Get-Content $p -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { Write-Warning "analyze: $name is empty; skipped"; return $null }
        $r = $raw | ConvertFrom-Json
        if ($null -eq $r) { Write-Output -NoEnumerate @() } else { Write-Output -NoEnumerate $r }
    } catch { Write-Warning "analyze: $name could not be parsed; skipped ($($_.Exception.Message))"; $null }
}
$now = [datetimeoffset]::Now
$findings = @()
# On a scoped run every finding carries the slice of the estate it describes (Scope); a full
# run keeps the pre-scope shape exactly.
$scope = Read-ScopeEffective
function Add-Finding($sev, $area, $text, $plane = 'tenant') {
    $f = [ordered]@{ Severity=$sev; Area=$area; Finding=$text }
    if ($scope.partial) { $f.Scope = Get-ScopeTag $scope $plane }
    $script:findings += [pscustomobject]$f
}

# Allowed-IP rules across the estate (SQL and Synapse firewalls, storage IP rules, NSG sources,
# App Service access restrictions, Logic App caller ranges, the Dataverse IP firewall), graded by
# breadth: the whole internet is HIGH, wider than a /16 is MEDIUM, every rule is counted for a
# stale-entry review in one LOW inventory finding at the end. $Entries: @{ rule; range } each.
$allowRules = 0; $allowByKind = [ordered]@{}; $allowPlanes = @{}
function Add-AllowList([string]$Kind, [string]$Name, $Entries, [string]$Plane = 'azure', [string]$What = 'allows', [switch]$IgnorePrivate) {
    $list = @($Entries | Where-Object { $_ })
    if (-not $list.Count) { return }
    $script:allowRules += $list.Count
    $script:allowByKind[$Kind] = 1 + [int]$script:allowByKind[$Kind]
    $script:allowPlanes[$Plane] = 1
    $internet = @(); $broad = @()
    foreach ($en in $list) {
        $br = Get-IpBreadth (Get-IpRange $en.range) -IgnorePrivate:$IgnorePrivate
        if ($br -eq 'internet') { $internet += "$($en.rule)" } elseif ($br -eq 'broad') { $broad += $(if ("$($en.rule)" -eq "$($en.range)") { "$($en.range)" } else { "$($en.rule) ($($en.range))" }) }
    }
    if ($internet.Count) { Add-Finding 'HIGH' 'Network' "$Kind '$Name' $What the entire internet (0.0.0.0-255.255.255.255): $($internet -join ', ')." $Plane }
    if ($broad.Count) { Add-Finding 'MEDIUM' 'Network' "$Kind '$Name' $What range(s) wider than a /16: $($broad -join '; ')." $Plane }
}

# --- Expired app credentials ---
# One unparseable record must never stop the run: the date helper returns $null and the
# per-app try/catch skips, matching the fail-soft rule in CONTRIBUTING.
$apps = Load 'applications.json'
if ($apps) {
    $expired = 0; $soon = 0
    foreach ($a in $apps) {
        try {
            foreach ($c in @($a.passwordCredentials) + @($a.keyCredentials)) {
                if (-not $c.endDateTime) { continue }
                $end = ConvertTo-DateSafe $c.endDateTime
                if ($null -eq $end) { continue }
                if ($end -lt $now) { $expired++ } elseif ($end -lt $now.AddDays(60)) { $soon++ }
            }
        } catch { Write-Warning "analyze: credential expiry check skipped for one app ($($_.Exception.Message))" }
    }
    if ($expired) { Add-Finding 'MEDIUM' 'App secrets' "$expired expired app credentials still present (orphaned / never cleaned up)." }
    if ($soon)    { Add-Finding 'LOW' 'App secrets' "$soon app credentials expire within 60 days - renew before outage." }
}

# --- High-privilege app permissions (Microsoft Graph and Exchange Online) ---
# Each resource's assignments are matched against its own role catalogue: Exchange roles such as
# full_access_as_app (every mailbox) and Exchange.ManageAsApp (Exchange admin) only exist in the
# Exchange catalogue. Apps are counted once even when a role was assigned more than once.
$risky = 'Mail.Read','Mail.ReadWrite','Mail.Send','Directory.ReadWrite.All','Application.ReadWrite.All','RoleManagement.ReadWrite.Directory','User.ReadWrite.All','Files.ReadWrite.All','Sites.FullControl.All','full_access_as_app','Exchange.ManageAsApp',
         'AppRoleAssignment.ReadWrite.All','RoleAssignmentSchedule.ReadWrite.Directory','RoleEligibilitySchedule.ReadWrite.Directory','UserAuthenticationMethod.ReadWrite.All','Policy.ReadWrite.ConditionalAccess','Domain.ReadWrite.All'
foreach ($res in @(@('graph', ' (tenant-wide)'), @('exo', ' (Exchange Online; every mailbox unless an application access policy limits it)'))) {
    $defs = Load "appRoleDefinitions-$($res[0]).json"; $asn = Load "appRoleAssignments-$($res[0]).json"
    if (-not ($defs -and $asn)) { continue }
    $map = @{}
    foreach ($d in @($defs)) { if ($d -and $d.id) { $map["$($d.id)"] = "$($d.value)" } }
    $hits = @{}
    foreach ($m in @($asn)) {
        if (-not $m -or -not $m.appRoleId) { continue }
        $rn = $map["$($m.appRoleId)"]
        if ($risky -contains $rn) { if (-not $hits.ContainsKey($rn)) { $hits[$rn] = @() }; $hits[$rn] += "$($m.principalDisplayName)" }
    }
    foreach ($r in $hits.Keys) {
        $who = @($hits[$r] | Where-Object { $_ } | Select-Object -Unique)
        Add-Finding 'HIGH' 'App access' "$($who.Count) app(s) hold $r$($res[1]): $($who -join ', ')"
    }
}

# --- Conditional Access ---
# A file holding [] means the tenant has zero policies: that is a finding, not a missing pull.
# Security defaults (when read) soften the severity: they enforce baseline MFA on their own.
$ca = Load 'ca-policies.json'
$sd = Load 'security-defaults.json'
$sdOn = ($null -ne $sd -and $sd.isEnabled -eq $true)
if ($null -ne $ca) {
    $on = @($ca | Where-Object { $_.state -eq 'enabled' })
    $mfaEnforced = @($ca | Where-Object { $_.state -eq 'enabled' -and ($_.grantControls.builtInControls -contains 'mfa' -or $null -ne $_.grantControls.authenticationStrength) })
    $sev = 'HIGH'; if ($mfaEnforced.Count -gt 0 -or $sdOn) { $sev = 'LOW' }
    Add-Finding $sev 'Conditional Access' "$(@($ca).Count) CA policies; $($on.Count) enabled; $($mfaEnforced.Count) enabled policies require MFA$(if($sdOn){'; security defaults ON (baseline MFA for everyone)'})."
}

# --- Legacy / basic authentication in the sign-in sample ---
# clientAppUsed names Microsoft classes as legacy authentication (the Conditional Access
# "Exchange ActiveSync clients" + "Other clients" categories). These protocols cannot do
# MFA, so a CA policy that requires MFA silently does not apply to them - block them.
$signins = Load 'signins-sample.json'
if ($signins) {
    $legacyRx = '^(Exchange ActiveSync|Authenticated SMTP|SMTP|Autodiscover|Exchange Online PowerShell|Exchange Web Services.*|IMAP4?|MAPI over HTTP.*|Offline Address Book.*|Outlook Anywhere.*|Outlook Service|POP3?|Reporting Web Services|Other clients)$'
    $total  = @($signins).Count
    $legacy = @($signins | Where-Object { $_.clientAppUsed -and "$($_.clientAppUsed)" -match $legacyRx })
    if ($legacy.Count) {
        $byClient = ($legacy | Group-Object clientAppUsed | Sort-Object Count -Descending | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
        $accounts = @($legacy | ForEach-Object { $_.userPrincipalName } | Where-Object { $_ } | Select-Object -Unique).Count
        Add-Finding 'HIGH' 'Legacy auth' "$($legacy.Count) of $total sampled sign-ins used legacy/basic authentication ($byClient; $accounts account(s)). These protocols cannot do MFA - block them with a Conditional Access policy (client apps: Exchange ActiveSync + Other clients)."
    } else {
        Add-Finding 'LOW' 'Legacy auth' "0 of $total sampled sign-ins used legacy/basic authentication (sample = most recent interactive sign-ins only; confirm with the Entra 'Sign-ins using legacy authentication' workbook)."
    }
}

# --- Guests ---
$g = Load 'guest-count.json'
if ($null -ne $g -and $null -ne $g.guestCount) {
    $gn = 0; try { $gn = [int]$g.guestCount } catch {}
    if ($gn -gt 0) { Add-Finding 'MEDIUM' 'Guests' "$gn guest accounts tenant-wide. Confirm access reviews exist." }
    else { Add-Finding 'LOW' 'Guests' '0 guest accounts tenant-wide.' }
}

# --- Directory roles ---
$dr = Load 'directoryRoles.json'
if ($dr) { $ga = ($dr | Where-Object { $_.role -eq 'Global Administrator' }).memberCount; if ($ga) { Add-Finding $(if($ga -gt 5){'MEDIUM'}else{'LOW'}) 'Admin roles' "$ga Global Administrator(s). Microsoft recommends fewer than 5, all with MFA." } }

# --- Dormant accounts (no sign-in for 90+ days), and dormant accounts that hold admin roles ---
# Dormancy uses lastSuccessfulSignInDateTime (interactive or non-interactive, successful only).
# lastSignInDateTime and lastNonInteractiveSignInDateTime also record FAILED attempts, so an idle
# account under password spray would look active if they counted; they are used only when the
# successful-sign-in property is absent (an older API shape). Microsoft records successful
# sign-ins since 1 Dec 2023, so an empty value means none since then. Accounts created in the
# last 90 days are skipped (they may simply be new). Needs AuditLog.Read.All and Entra ID P1.
$dormantSet = @{}
$dormantCut = $now.AddDays(-90)
$ua = Load 'users-signin-activity.json'
if ($ua) {
    $never = 0; $dormantGuests = 0; $enabledN = 0
    foreach ($u in @($ua)) {
        if (-not $u -or -not $u.userPrincipalName) { continue }
        if ($u.accountEnabled -ne $true) { continue }
        $enabledN++
        $created = ConvertTo-DateSafe $u.createdDateTime
        if ($created -and $created -gt $dormantCut) { continue }
        $latest = $null
        $sia = $u.signInActivity
        if ($sia) {
            if ($sia.PSObject.Properties.Name -contains 'lastSuccessfulSignInDateTime') {
                $latest = ConvertTo-DateSafe $sia.lastSuccessfulSignInDateTime
            } else {
                foreach ($k in 'lastSignInDateTime', 'lastNonInteractiveSignInDateTime') {
                    $d = ConvertTo-DateSafe $sia.$k
                    if ($d -and ($null -eq $latest -or $d -gt $latest)) { $latest = $d }
                }
            }
        }
        if ($null -eq $latest -or $latest -lt $dormantCut) {
            $dormantSet["$($u.userPrincipalName)".ToLower()] = $true
            if ($null -eq $latest) { $never++ }
            if ("$($u.userType)" -eq 'Guest') { $dormantGuests++ }
        }
    }
    if ($dormantSet.Count) { Add-Finding 'MEDIUM' 'Dormant accounts' "$($dormantSet.Count) of $enabledN enabled account(s) have not signed in for 90+ days ($never with no successful sign-in on record, $dormantGuests guest(s)). Disable or review them: they keep their access, and their passwords stay valid." }
    else { Add-Finding 'LOW' 'Dormant accounts' "0 of $enabledN enabled account(s) idle for 90+ days." }
    $privDormant = @()
    foreach ($r in @($dr)) {
        if (-not $r) { continue }
        foreach ($m in @($r.members)) { if ($m -and $dormantSet.ContainsKey("$m".ToLower())) { $privDormant += "$($r.role): $m" } }
    }
    if ($privDormant.Count) { Add-Finding 'HIGH' 'Dormant admins' "$($privDormant.Count) directory-role assignment(s) belong to accounts idle for 90+ days: $((@($privDormant) | Select-Object -First 15) -join '; ')$(if($privDormant.Count -gt 15){" (+$($privDormant.Count - 15) more)"}). For each: if it is an emergency-access (break-glass) account, keep it but test its sign-in at least every 90 days and alert on any use; otherwise remove the role or disable the account." }
}

# --- Dataverse per environment ---
Get-ChildItem $out -Filter 'dv-*-org.json' | ForEach-Object {
    $envName = ($_.BaseName -replace '^dv-' -replace '-org$')
    $orgs = Load $_.Name; $org = @($orgs)[0]
    if ($org -and $org.isauditenabled -eq $false) { Add-Finding 'HIGH' 'Auditing' "[$envName] Dataverse auditing is OFF - no record of who changes data." 'dataverse' }
    $roles = Load "dv-$envName-roles.json"
    if ($null -ne $roles) { $custom = @($roles | Where-Object { $_.ismanaged -eq $false }).Count; if ($custom -eq 0) { Add-Finding 'LOW' 'Roles' "[$envName] No unmanaged (customer-authored) security role. Roles delivered in managed solutions are not told apart from built-in ones by this read; confirm a least-privilege role exists for everyday users." 'dataverse' } }
}

# --- Dataverse: table-level auditing ---
# Org auditing alone records nothing for a table whose own audit flag is off, so the key
# security tables are checked one by one, plus a count over the custom tables.
$keyTables = @('account', 'contact', 'systemuser', 'role', 'team', 'businessunit', 'fieldsecurityprofile')
foreach ($f in @(Get-ChildItem $out -Filter 'dv-*-entities.json')) {
    $envName = $f.BaseName -replace '^dv-' -replace '-entities$'
    $ents = Load $f.Name
    if ($null -eq $ents) { continue }
    $off = @(); $customN = 0; $customOff = 0
    foreach ($e in @($ents)) {
        if (-not $e) { continue }
        $a = $e.IsAuditEnabled
        if ($null -ne $a -and -not ($a -is [bool]) -and ($a.PSObject.Properties.Name -contains 'Value')) { $a = $a.Value }
        if ($keyTables -contains "$($e.LogicalName)" -and $a -eq $false) { $off += "$($e.LogicalName)" }
        if ($e.IsCustomEntity -eq $true) { $customN++; if ($a -eq $false) { $customOff++ } }
    }
    if ($off.Count) { Add-Finding 'MEDIUM' 'Auditing' "[$envName] Table-level auditing is OFF on key table(s): $($off -join ', '). Org auditing records nothing for these tables (Power Apps > Tables > (table) > Properties > Audit changes to its data)." 'dataverse' }
    if ($customOff -gt 0) { Add-Finding 'LOW' 'Auditing' "[$envName] $customOff of $customN custom table(s) have auditing off." 'dataverse' }
}

# --- Dataverse: unmanaged solutions in Production environments ---
# The environment type comes from the Power Platform inventory or, without it, from the
# environment itself (dv-<env>-orginfo.json); matched on the first label of the instance URL
# (the same name the Dataverse sweeps use for their files). A type that was not read at all is
# said out loud, never treated as non-production.
$skuByHost = (Get-EnvSkuMap $out).sku
foreach ($f in @(Get-ChildItem $out -Filter 'dv-*-solutions.json')) {
    $envName = $f.BaseName -replace '^dv-' -replace '-solutions$'
    $sku = $skuByHost["$envName".ToLower()]
    if ($sku -and $sku -ne 'Production') { continue }
    $sols = Load $f.Name
    if ($null -eq $sols) { continue }
    $um = @($sols | Where-Object { $_ -and $_.ismanaged -eq $false -and $_.isvisible -eq $true -and "$($_.uniquename)" -notin 'Default', 'Active', 'Basic' -and "$($_.friendlyname)" -ne 'Common Data Services Default Solution' })
    if (-not $um.Count) { continue }
    $umNames = (@($um | ForEach-Object { "$($_.friendlyname)" }) | Select-Object -First 10) -join ', '
    if ($sku) { Add-Finding 'MEDIUM' 'Solutions' "[$envName] $($um.Count) unmanaged solution(s) in a Production environment: $umNames. Production should only receive managed solutions through a pipeline." 'dataverse' }
    else { Add-Finding 'LOW' 'Solutions' "[$envName] $($um.Count) unmanaged solution(s): $umNames. The environment type was not read; if this is Production it is MEDIUM (Production should only receive managed solutions through a pipeline)." 'dataverse' }
}

# --- Dataverse: who holds System Administrator, per environment ---
# dv-<env>-users.json = enabled users with their DIRECTLY assigned roles; a role inherited
# through a team is not visible here, and the findings say so. Left out: built-in accounts
# (SYSTEM, INTEGRATION, support users) and Microsoft-owned application users, identified by the
# owner tenant of the app's service principal (dual-write, first-party apps). The '#' in front
# of an application user's name is NOT a Microsoft marker: Dataverse adds it to every app user.
# More than 3 people is MEDIUM in Production and LOW elsewhere (makers often hold it in dev).
$msTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
$appOwner = $null
$dvSysAdmins = @{}
foreach ($f in @(Get-ChildItem $out -Filter 'dv-*-users.json')) {
    $envName = $f.BaseName -replace '^dv-' -replace '-users$'
    $users = Load $f.Name
    if ($null -eq $users) { continue }
    $sa = @($users | Where-Object { $_ -and @($_.systemuserroles_association | Where-Object { $_ -and "$($_.name)" -eq 'System Administrator' }).Count -gt 0 })
    $real = @($sa | Where-Object { "$($_.fullname)" -notin 'SYSTEM', 'INTEGRATION' -and "$($_.accessmode)" -ne '3' })
    $people = @($real | Where-Object { -not $_.applicationid })
    $appUsers = @($real | Where-Object { $_.applicationid })
    if ($appUsers.Count -and $null -eq $appOwner) {
        $appOwner = @{}
        $spAll2 = Load 'servicePrincipals.json'
        foreach ($sp in @($spAll2)) { if ($sp -and $sp.appId) { $appOwner["$($sp.appId)".ToLower()] = "$($sp.appOwnerOrganizationId)".ToLower() } }
    }
    $appUsers = @($appUsers | Where-Object { $msTenants -notcontains $appOwner["$($_.applicationid)".ToLower()] })
    $names = @($people | ForEach-Object { if ($_.domainname) { "$($_.domainname)" } else { "$($_.fullname)" } })
    $dvSysAdmins[$envName] = $names
    $sku = $skuByHost["$envName".ToLower()]
    if ($people.Count) {
        $sev = if ($people.Count -gt 3 -and $sku -eq 'Production') { 'MEDIUM' } else { 'LOW' }
        Add-Finding $sev 'D365 admins' "[$envName$(if($sku){" ($sku)"}else{' (type not read)'})] $($people.Count) user(s) directly assigned System Administrator (roles inherited through teams not counted): $((@($names) | Select-Object -First 12) -join ', ')$(if($names.Count -gt 12){" (+$($names.Count - 12) more)"}). Keep it to a handful; give everyone else a scoped role.$(if(-not $sku -and $people.Count -gt 3){' MEDIUM if this is a Production environment.'})" 'dataverse'
    }
    if ($appUsers.Count) {
        Add-Finding 'MEDIUM' 'Service identities' "[$envName] $($appUsers.Count) non-Microsoft application user(s) directly assigned System Administrator: $((@($appUsers | ForEach-Object { "$($_.fullname)" }) | Select-Object -Unique) -join ', '). Service identities should get a scoped role, not full control of the environment.$(if($appOwner.Count -eq 0){' Service principal owners were not read, so Microsoft-owned apps could not be filtered out.'})" 'dataverse'
    }
}
if ($dormantSet.Count -and $dvSysAdmins.Count) {
    $dvDormant = @()
    foreach ($envKey in $dvSysAdmins.Keys) {
        foreach ($upn in @($dvSysAdmins[$envKey])) { if ($upn -and $dormantSet.ContainsKey("$upn".ToLower())) { $dvDormant += "[$envKey] $upn" } }
    }
    if ($dvDormant.Count) { Add-Finding 'HIGH' 'Dormant admins' "$($dvDormant.Count) Dataverse System Administrator(s) have not signed in for 90+ days: $((@($dvDormant) | Select-Object -First 15) -join '; '). Remove the role unless it is a documented emergency-access account." 'dataverse' }
}

# --- Dataverse IP firewall (dvplus-<env>-ipfirewall.json) ---
# Off, or on in audit-only mode (logs, never blocks), per environment; enforced ranges feed the
# allowlist grading. It is a Managed Environments feature, so it is advice (LOW), not a defect.
$dvFwOff = @(); $dvFwAudit = @()
foreach ($f in @(Get-ChildItem $out -Filter 'dvplus-*-ipfirewall.json')) {
    $envName = $f.BaseName -replace '^dvplus-' -replace '-ipfirewall$'
    $o = Load $f.Name; $o = @($o)[0]
    if (-not $o -or -not ($o.PSObject.Properties.Name -contains 'enableipbasedfirewallrule')) { continue }
    $sku = $skuByHost["$envName".ToLower()]; $label = "$envName$(if($sku){" ($sku)"})"
    if ($o.enableipbasedfirewallrule -ne $true) { $dvFwOff += $label; continue }
    if ($o.enableipbasedfirewallruleinauditmode -eq $true) { $dvFwAudit += $label }
    $ranges = @("$($o.allowediprangeforfirewall)" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    Add-AllowList 'Dataverse environment' $envName @($ranges | ForEach-Object { @{ rule = $_; range = $_ } }) 'dataverse' 'IP firewall allows'
}
if ($dvFwOff.Count) { Add-Finding 'LOW' 'Network' "Dataverse IP firewall is off in $($dvFwOff.Count) environment(s): $($dvFwOff -join ', '). It limits Dataverse to your office and VPN ranges, which also stops a stolen token being replayed from anywhere else (Managed Environments feature; start in audit-only mode)." 'dataverse' }
if ($dvFwAudit.Count) { Add-Finding 'LOW' 'Network' "Dataverse IP firewall is in audit-only mode (it logs, it never blocks) in: $($dvFwAudit -join ', ')." 'dataverse' }

# --- Azure network ---
Get-ChildItem $out -Filter 'arm-*-sql.json' | ForEach-Object {
    $items = Load $_.Name
    foreach ($srv in @($items | Where-Object { $_ })) {
        if ($srv.properties.publicNetworkAccess -eq 'Enabled') { Add-Finding 'HIGH' 'Network' "SQL server '$($srv.name)' has public network access enabled." 'azure' }
        if (@($srv._firewallRules | Where-Object { $_.properties.startIpAddress -eq '0.0.0.0' -and $_.properties.endIpAddress -eq '0.0.0.0' }).Count) { Add-Finding 'HIGH' 'Network' "SQL server '$($srv.name)' allows all Azure IPs (0.0.0.0)." 'azure' }
    }
}
# NSG inbound Allow rules from '*', 'Internet' or 0.0.0.0/0, graded by port: remote-admin and
# database ports (or every port) are HIGH; other ports (typically 80/443 on a web server) are
# listed once as LOW. The plural fields (sourceAddressPrefixes, destinationPortRanges) count too.
# Rules from a specific source range feed the allowlist grading (private ranges ignored).
# String keys on purpose: an [ordered] dictionary indexed with an integer is read by position.
$riskyPorts = [ordered]@{ '22' = 'SSH'; '3389' = 'RDP'; '5985' = 'WinRM'; '5986' = 'WinRM'; '23' = 'Telnet'; '21' = 'FTP'; '445' = 'SMB'; '135' = 'RPC'; '139' = 'NetBIOS'; '5900' = 'VNC'; '1433' = 'SQL Server'; '3306' = 'MySQL'; '5432' = 'PostgreSQL'; '1521' = 'Oracle'; '27017' = 'MongoDB'; '6379' = 'Redis' }
function Get-RiskyPortHits($Ports) {
    $hits = @()
    foreach ($pr in @($Ports)) {
        $t = "$pr".Trim()
        if ($t -eq '*') { return @('all ports') }
        if ($t -match '^(\d+)-(\d+)$') { $lo = [int]$Matches[1]; $hi = [int]$Matches[2] } elseif ($t -match '^\d+$') { $lo = [int]$t; $hi = $lo } else { continue }
        if ($hi - $lo -ge 60000) { return @('all ports') }
        foreach ($k in @($riskyPorts.Keys)) { $kp = [int]$k; if ($kp -ge $lo -and $kp -le $hi) { $hits += "$k ($($riskyPorts[$k]))" } }
    }
    return @($hits | Select-Object -Unique)
}
$nsgWebOpen = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-nsgs.json')) {
    $items = Load $f.Name
    foreach ($nsg in @($items | Where-Object { $_ })) {
        $attached = (@($nsg.properties.networkInterfaces | Where-Object { $_ }).Count + @($nsg.properties.subnets | Where-Object { $_ }).Count) -gt 0
        $nsgNote = if ($attached) { '' } else { ' (this NSG is not attached to any subnet or network interface)' }
        $allowEntries = @()
        foreach ($rule in @($nsg.properties.securityRules | Where-Object { $_ })) {
            $p = $rule.properties
            if ("$($p.access)" -ne 'Allow' -or "$($p.direction)" -ne 'Inbound') { continue }
            if ("$($p.protocol)" -eq 'Icmp') { continue }   # ping, not a port
            $srcs = @(@($p.sourceAddressPrefix) + @($p.sourceAddressPrefixes) | Where-Object { $_ } | ForEach-Object { "$_" })
            $ports = @(@($p.destinationPortRange) + @($p.destinationPortRanges) | Where-Object { $_ } | ForEach-Object { "$_" })
            $hits = @(Get-RiskyPortHits $ports)
            $portText = if ($hits -contains 'all ports') { 'all ports' } else { "port(s) $($hits -join ', ')" }
            if (@($srcs | Where-Object { $_ -in '*', 'Internet', 'Any', '0.0.0.0/0' }).Count) {
                if ($hits.Count) { Add-Finding 'HIGH' 'Network' "NSG '$($nsg.name)' rule '$($rule.name)' opens $portText to the internet.$nsgNote" 'azure' }
                else { $nsgWebOpen += "$($nsg.name)/$($rule.name) ($($ports -join ','))" }
                continue
            }
            if ($hits.Count -and @($srcs | Where-Object { $_ -eq 'AzureCloud' -or $_ -like 'AzureCloud.*' }).Count) {
                Add-Finding 'MEDIUM' 'Network' "NSG '$($nsg.name)' rule '$($rule.name)' opens $portText to every Azure customer's address space (service tag AzureCloud).$nsgNote" 'azure'
            }
            foreach ($src in $srcs) { if ($null -ne (Get-IpRange $src)) { $allowEntries += @{ rule = "$($rule.name)"; range = $src } } }
        }
        Add-AllowList 'NSG' $nsg.name $allowEntries 'azure' 'allows inbound from' -IgnorePrivate
    }
}
if ($nsgWebOpen.Count) { Add-Finding 'LOW' 'Network' "$($nsgWebOpen.Count) NSG rule(s) allow inbound internet traffic on other ports (for example web traffic): $((@($nsgWebOpen) | Select-Object -First 12) -join '; ')$(if($nsgWebOpen.Count -gt 12){" (+$($nsgWebOpen.Count - 12) more)"}). Confirm each one fronts a service that is meant to be public." 'azure' }
Get-ChildItem $out -Filter 'arm-*-keyvaults.json' | ForEach-Object {
    $items = Load $_.Name
    foreach ($v in @($items | Where-Object { $_ })) {
        if (-not $v.properties.enableRbacAuthorization) { Add-Finding 'MEDIUM' 'Key Vault' "Key vault '$($v.name)' uses legacy access policies (not RBAC)." 'azure' }
        if ("$($v.properties.publicNetworkAccess)" -ne 'Disabled' -and "$($v.properties.networkAcls.defaultAction)" -ne 'Deny') { Add-Finding 'MEDIUM' 'Key Vault' "Key vault '$($v.name)' allows public network access from any network (no firewall default-deny)." 'azure' }
    }
}

# --- Synapse workspaces: public access and the allow-all-Azure rule ---
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-synapse.json')) {
    $items = Load $f.Name
    foreach ($ws in @($items | Where-Object { $_ })) {
        if ("$($ws.properties.publicNetworkAccess)" -eq 'Enabled') { Add-Finding 'HIGH' 'Network' "Synapse workspace '$($ws.name)' has public network access enabled." 'azure' }
        if (@($ws._firewallRules | Where-Object { $_ -and "$($_.properties.startIpAddress)" -eq '0.0.0.0' -and "$($_.properties.endIpAddress)" -eq '0.0.0.0' }).Count) { Add-Finding 'HIGH' 'Network' "Synapse workspace '$($ws.name)' allows all Azure IPs (0.0.0.0)." 'azure' }
    }
}

# --- Allowed-IP firewall rules on SQL servers and Synapse workspaces, graded by breadth ---
# 0.0.0.0-255.255.255.255 is the whole internet; a range wider than a /16 (65,536 addresses) is
# flagged for review; 0.0.0.0-0.0.0.0 ("allow Azure services") has its own rule above. The total
# feeds a stale-entry review of the raw rules.
foreach ($kind in @(@('sql', 'SQL server'), @('synapse', 'Synapse workspace'))) {
    foreach ($f in @(Get-ChildItem $out -Filter "arm-*-$($kind[0]).json")) {
        $items = Load $f.Name
        foreach ($res in @($items | Where-Object { $_ })) {
            $entries = @(foreach ($r in @($res._firewallRules | Where-Object { $_ })) {
                $p = if ($r.properties) { $r.properties } else { $r }
                $sIp = "$($p.startIpAddress)"; $eIp = "$($p.endIpAddress)"
                if ($null -eq (Get-IpNumber $sIp) -or $null -eq (Get-IpNumber $eIp)) { continue }
                @{ rule = "$($r.name)"; range = "$sIp-$eIp" }
            })
            Add-AllowList $kind[1] $res.name $entries 'azure' 'firewall allows'
        }
    }
}

# --- VMs on the internet (arm-*-vms / nics / publicips / vnets) ---
# A VM is on the internet when one of its network interfaces has a public IP. With no NSG on the
# interface or on its subnet, every port the operating system listens on is reachable. A subnet
# the run did not read is never assumed to be unprotected.
$nicById = @{}; $pipById = @{}; $subnetNsg = @{}
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-nics.json')) { $x = Load $f.Name; foreach ($n in @($x | Where-Object { $_ -and $_.id })) { $nicById["$($n.id)".ToLower()] = $n } }
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-publicips.json')) { $x = Load $f.Name; foreach ($p in @($x | Where-Object { $_ -and $_.id })) { $pipById["$($p.id)".ToLower()] = $p } }
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-vnets.json')) { $x = Load $f.Name; foreach ($v in @($x | Where-Object { $_ })) { foreach ($sn in @($v.subnets | Where-Object { $_ -and $_.id })) { $subnetNsg["$($sn.id)".ToLower()] = "$($sn.nsg)" } } }
$vmOnNet = @(); $vmBare = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-vms.json')) {
    $x = Load $f.Name
    foreach ($vm in @($x | Where-Object { $_ })) {
        $ips = @(); $bare = $false
        foreach ($nid in @($vm.nics | Where-Object { $_ })) {
            $nic = $nicById["$nid".ToLower()]
            if (-not $nic) { continue }
            foreach ($ipc in @($nic.ipConfigs | Where-Object { $_ -and $_.publicIp })) {
                $pip = $pipById["$($ipc.publicIp)".ToLower()]
                $ips += $(if ($pip -and $pip.ipAddress) { "$($pip.ipAddress)" } else { 'public IP' })
                $subKey = "$($ipc.subnet)".ToLower()
                if (-not $nic.nsg -and $subnetNsg.ContainsKey($subKey) -and -not $subnetNsg[$subKey]) { $bare = $true }
            }
        }
        if ($ips.Count) { $vmOnNet += "$($vm.name) ($($ips -join ', '))"; if ($bare) { $vmBare += "$($vm.name) ($($ips -join ', '))" } }
    }
}
if ($vmBare.Count) { Add-Finding 'HIGH' 'Network' "$($vmBare.Count) VM(s) have a public IP and no NSG on the network interface or its subnet, so every port the OS listens on is reachable from the internet: $($vmBare -join '; ')." 'azure' }
if ($vmOnNet.Count) { Add-Finding 'LOW' 'Network' "$($vmOnNet.Count) VM(s) have a public IP address: $((@($vmOnNet) | Select-Object -First 15) -join '; ')$(if($vmOnNet.Count -gt 15){" (+$($vmOnNet.Count - 15) more)"}). Anything their NSG lets in is reachable from the internet; prefer Azure Bastion or a VPN for admin access." 'azure' }

# --- Storage accounts (arm-*-storage.json) ---
$stOpen = @(); $stAnon = @(); $stHttp = @(); $stTls = @(); $stKey = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-storage.json')) {
    $x = Load $f.Name
    foreach ($a in @($x | Where-Object { $_ })) {
        if ("$($a.publicNetworkAccess)" -notin 'Disabled', 'SecuredByPerimeter' -and "$($a.defaultAction)" -eq 'Allow') { $stOpen += $a.name }
        if ($a.allowBlobPublicAccess -ne $false) { $stAnon += $a.name }
        if ($a.supportsHttpsTrafficOnly -eq $false) { $stHttp += $a.name }
        if ("$($a.minimumTlsVersion)" -in 'TLS1_0', 'TLS1_1') { $stTls += "$($a.name) ($($a.minimumTlsVersion))" }
        if ($a.allowSharedKeyAccess -ne $false) { $stKey += $a.name }
        Add-AllowList 'Storage account' $a.name @(@($a.ipRules | Where-Object { $_ }) | ForEach-Object { @{ rule = "$_"; range = "$_" } }) 'azure' 'allows'
    }
}
if ($stOpen.Count) { Add-Finding 'MEDIUM' 'Storage' "$($stOpen.Count) storage account(s) accept connections from all networks (public network access on, default action Allow): $($stOpen -join ', '). Data access still needs a key or a token, but anyone can try; limit them to selected networks or private endpoints." 'azure' }
if ($stAnon.Count) { Add-Finding 'MEDIUM' 'Storage' "$($stAnon.Count) storage account(s) allow, or do not block (setting unset on an older account), anonymous blob access on containers: $($stAnon -join ', '). Set 'Allow Blob anonymous access' to Disabled unless a container is meant to be public." 'azure' }
if ($stHttp.Count) { Add-Finding 'MEDIUM' 'Storage' "$($stHttp.Count) storage account(s) accept plain HTTP (secure transfer not required): $($stHttp -join ', ')." 'azure' }
if ($stTls.Count) { Add-Finding 'LOW' 'Storage' "$($stTls.Count) storage account(s) are set to accept TLS below 1.2: $($stTls -join ', '). Set the minimum to TLS 1.2." 'azure' }
if ($stKey.Count) { Add-Finding 'LOW' 'Storage' "$($stKey.Count) storage account(s) still accept shared-key authorization (account keys and SAS tokens), which bypasses Entra ID and leaves no per-user trail: $($stKey -join ', '). Turn it off where nothing depends on it." 'azure' }

# --- App Service and Function Apps (arm-*-appservice.json) ---
$apHttp = @(); $apTls = @(); $apFtp = @(); $apDebug = @(); $apOpen = @(); $apUnread = @(); $fnOpen = @(); $fnLimited = @(); $fnAuth = @(); $fnUnknown = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-appservice.json')) {
    $x = Load $f.Name
    foreach ($site in @($x | Where-Object { $_ })) {
        if ($site.httpsOnly -eq $false) { $apHttp += $site.name }
        $c = $site.config
        $open = $null   # unknown until the web config was read
        if ($c) {
            if ("$($c.minTlsVersion)" -in '1.0', '1.1') { $apTls += "$($site.name) ($($c.minTlsVersion))" }
            if ("$($c.ftpsState)" -eq 'AllAllowed') { $apFtp += $site.name }
            if ($c.remoteDebuggingEnabled -eq $true) { $apDebug += $site.name }
            $pna = if ($site.publicNetworkAccess) { "$($site.publicNetworkAccess)" } else { "$($c.publicNetworkAccess)" }
            $rules = @($c.ipSecurityRestrictions | Where-Object { $_ })
            # Restricted when the unmatched-rule action is Deny, or (older configs, no explicit
            # default) when an Allow rule names a range or a subnet: everything else is then denied.
            # An explicit default of Allow means the Allow rules restrict nothing.
            $dfl = "$($c.ipSecurityRestrictionsDefaultAction)"
            $explicitAllow = @($rules | Where-Object { "$($_.action)" -eq 'Allow' -and (("$($_.ipAddress)" -and "$($_.ipAddress)" -ne 'Any') -or $_.vnetSubnetResourceId) }).Count -gt 0
            $limited = ($dfl -eq 'Deny') -or ((-not $dfl) -and $explicitAllow)
            $open = ($pna -ne 'Disabled') -and -not $limited
            if ($open) { $apOpen += $site.name }
            Add-AllowList 'App' $site.name @($rules | Where-Object { "$($_.action)" -eq 'Allow' -and "$($_.ipAddress)" -and "$($_.ipAddress)" -ne 'Any' -and "$($_.tag)" -ne 'ServiceTag' } | ForEach-Object { @{ rule = "$($_.name)"; range = "$($_.ipAddress)" } }) 'azure' 'allows'
        } else { $apUnread += $site.name }
        foreach ($fn in @($site.functions | Where-Object { $_ -and $_.httpTrigger -and "$($_.authLevel)" -eq 'anonymous' -and $_.disabled -ne $true })) {
            $label = "$($site.name)/$($fn.name)"
            if ($site.easyAuth -eq $true) { $fnAuth += $label }
            elseif ($null -eq $open) { $fnUnknown += $label }
            elseif ($open) { $fnOpen += $label } else { $fnLimited += $label }
        }
    }
}
if ($fnOpen.Count) { Add-Finding 'MEDIUM' 'App Service' "$($fnOpen.Count) HTTP function(s) need no key (authLevel anonymous) on app(s) that accept traffic from any IP and have no App Service authentication: $((@($fnOpen) | Select-Object -First 12) -join ', '). Anyone who finds the URL can call them; use function keys, App Service authentication or access restrictions unless they are meant to be public." 'azure' }
if ($fnUnknown.Count) { Add-Finding 'LOW' 'App Service' "$($fnUnknown.Count) HTTP function(s) need no key, and the app's web config could not be read, so whether anyone can reach them is unknown: $((@($fnUnknown) | Select-Object -First 12) -join ', ')." 'azure' }
if ($fnLimited.Count) { Add-Finding 'LOW' 'App Service' "$($fnLimited.Count) HTTP function(s) need no key but sit behind access restrictions or private access: $((@($fnLimited) | Select-Object -First 12) -join ', ')." 'azure' }
if ($fnAuth.Count) { Add-Finding 'LOW' 'App Service' "$($fnAuth.Count) HTTP function(s) need no function key but App Service authentication requires a sign-in first: $((@($fnAuth) | Select-Object -First 12) -join ', ')." 'azure' }
if ($apUnread.Count) { Add-Finding 'LOW' 'App Service' "$($apUnread.Count) app(s) whose web configuration could not be read (TLS, FTP, debugging and access restrictions unknown; see arm-*-appservice.json errors): $((@($apUnread) | Select-Object -First 15) -join ', ')." 'azure' }
if ($apHttp.Count) { Add-Finding 'MEDIUM' 'App Service' "$($apHttp.Count) app(s) do not force HTTPS (HTTPS Only off): $($apHttp -join ', ')." 'azure' }
if ($apTls.Count) { Add-Finding 'MEDIUM' 'App Service' "$($apTls.Count) app(s) accept TLS below 1.2: $($apTls -join ', ')." 'azure' }
if ($apFtp.Count) { Add-Finding 'MEDIUM' 'App Service' "$($apFtp.Count) app(s) accept plain FTP for deployments (FTP state All allowed): $($apFtp -join ', '). Set it to FTPS only or Disabled." 'azure' }
if ($apDebug.Count) { Add-Finding 'MEDIUM' 'App Service' "$($apDebug.Count) app(s) have remote debugging turned on: $($apDebug -join ', ')." 'azure' }
if ($apOpen.Count) { Add-Finding 'LOW' 'App Service' "$($apOpen.Count) app(s) accept traffic from any IP address (no access restrictions): $((@($apOpen) | Select-Object -First 15) -join ', '). Fine for a public site; for internal APIs and Function Apps, add access restrictions or a private endpoint." 'azure' }

# --- Logic Apps with HTTP triggers open to any caller (arm-*-logicapps.json) ---
$laOpen = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-logicapps.json')) {
    $x = Load $f.Name
    foreach ($la in @($x | Where-Object { $_ })) {
        $http = @($la.triggers | Where-Object { $_ -and "$($_.type)" -eq 'Request' })
        if ($http.Count -and "$($la.callers)" -eq 'any' -and -not ($la.entraAuthPolicy -eq $true -and $la.sasDisabled -eq $true)) { $laOpen += "$($la.name)$(if($la.state -and "$($la.state)" -ne 'Enabled'){" ($($la.state))"})$(if($la.entraAuthPolicy -eq $true){' (Entra policy present, but SAS URLs still accepted)'})" }
        Add-AllowList 'Logic App' $la.name @(@($la.allowedCallerIps | Where-Object { $_ }) | ForEach-Object { @{ rule = "$_"; range = "$_" } }) 'azure' 'accepts calls from'
    }
}
if ($laOpen.Count) { Add-Finding 'LOW' 'Integration' "$($laOpen.Count) Logic App(s) start from an HTTP request and accept calls from any IP: $((@($laOpen) | Select-Object -First 15) -join ', '). Each call still needs the trigger URL's signature, so anyone holding that URL can start the workflow; restrict caller IPs, or add an Entra ID authorization policy and disable SAS authentication." 'azure' }

# --- Automation: retired Run As connections (arm-*-automation.json) ---
$runAs = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-automation.json')) {
    $x = Load $f.Name
    foreach ($acct in @($x | Where-Object { $_ })) {
        $ra = @($acct.connections | Where-Object { $_ -and ("$($_.type)" -eq 'AzureServicePrincipal' -or "$($_.name)" -in 'AzureRunAsConnection', 'AzureClassicRunAsConnection') })
        if ($ra.Count) { $runAs += "$($acct.name) ($((@($ra | ForEach-Object { "$($_.name)" })) -join ', '))" }
    }
}
if ($runAs.Count) { Add-Finding 'MEDIUM' 'Service identities' "$($runAs.Count) Automation account(s) hold an AzureServicePrincipal (Run As style) connection asset; Microsoft retired the Run As feature on 30 September 2023, and a hand-made one carries the same risk: $($runAs -join '; '). Its app registration can still carry Contributor on the subscription; move the runbooks to a managed identity, then delete that app registration and its role assignment." 'azure' }

# --- API connections that sign in as a named account (arm-*-apiconnections.json) ---
$apiNamed = @(); $apiDormant = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-apiconnections.json')) {
    $x = Load $f.Name
    foreach ($c in @($x | Where-Object { $_ -and "$($_.authenticatedUser)" -match '@' })) {
        $apiNamed += "$($c.name) ($($c.api)) as $($c.authenticatedUser)"
        if ($dormantSet.ContainsKey("$($c.authenticatedUser)".ToLower())) { $apiDormant += "$($c.name) as $($c.authenticatedUser)" }
    }
}
if ($apiDormant.Count) { Add-Finding 'MEDIUM' 'Service identities' "$($apiDormant.Count) API connection(s) sign in as an account with no successful sign-in for 90+ days: $($apiDormant -join '; '). Confirm the account is a managed service account, or move the connection to one." 'azure' }
if ($apiNamed.Count) { Add-Finding 'LOW' 'Service identities' "$($apiNamed.Count) API connection(s) sign in as a named account: $((@($apiNamed) | Select-Object -First 12) -join '; ')$(if($apiNamed.Count -gt 12){" (+$($apiNamed.Count - 12) more)"}). Each runs with that account's access and breaks when the person leaves or the password changes; use a dedicated service account or a managed identity." 'azure' }

# --- One inventory line for every allowlist read above ---
if ($allowByKind.Count) {
    $parts = @($allowByKind.Keys | ForEach-Object { "$($allowByKind[$_]) $($_)(s)" })
    Add-Finding 'LOW' 'Network' "Allowed-IP inventory: $allowRules rule(s) across $($parts -join ', '). Review every range for stale or over-broad entries (raw rules in output/: arm-*-sql.json and arm-*-synapse.json _firewallRules, arm-*-storage.json, arm-*-nsgs.json, arm-*-appservice.json, arm-*-logicapps.json, dvplus-*-ipfirewall.json)." $(if($allowPlanes.ContainsKey('dataverse')){'mixed'}else{'azure'})
}

# --- Azure RBAC: Owner sprawl, and service principals holding Owner ---
# Direct Owner / User Access Administrator grants at subscription scope (management-group
# inheritance excluded). Microsoft Defender for Cloud recommends at most 3 owners per
# subscription. A service principal holding either role turns one leaked app secret into full
# control of the subscription, so those are named.
$roleOwner = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; $roleUaa = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
$spNames = $null; $mgPriv = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-rbac.json')) {
    $sub = $f.BaseName -replace '^arm-' -replace '-rbac$'
    $ra = Load $f.Name
    if ($null -eq $ra) { continue }
    $atSub  = @($ra | Where-Object { $_ -and $_.properties -and "$($_.properties.scope)" -match '^/subscriptions/[^/]+/?$' })
    $owners = @($atSub | Where-Object { "$($_.properties.roleDefinitionId)".Split('/')[-1] -eq $roleOwner })
    $uaa    = @($atSub | Where-Object { "$($_.properties.roleDefinitionId)".Split('/')[-1] -eq $roleUaa })
    if ($owners.Count -gt 3) {
        $byType = (@($owners | Group-Object { "$($_.properties.principalType)" } | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" })) -join ', '
        Add-Finding 'MEDIUM' 'Owner sprawl' "[$sub] $($owners.Count) Owner assignment(s) at subscription scope ($byType)$(if($uaa.Count){" plus $($uaa.Count) User Access Administrator"}); Microsoft recommends at most 3 owners. Move the rest to PIM-eligible or resource-group scope." 'azure'
    }
    $spPriv = @(@($owners) + @($uaa) | Where-Object { "$($_.properties.principalType)" -eq 'ServicePrincipal' })
    if ($spPriv.Count -gt 0) {
        if ($null -eq $spNames) {
            $spNames = @{}
            $spAll = Load 'servicePrincipals.json'
            foreach ($sp in @($spAll)) { if ($sp -and $sp.id) { $spNames["$($sp.id)"] = "$($sp.displayName)" } }
        }
        $who = @($spPriv | ForEach-Object { $pid0 = "$($_.properties.principalId)"; if ($spNames[$pid0]) { $spNames[$pid0] } else { $pid0 } } | Select-Object -Unique)
        Add-Finding 'HIGH' 'Service identities' "[$sub] $($who.Count) service principal(s) hold Owner or User Access Administrator at subscription scope: $($who -join ', '). Compromise of any of them (a leaked secret or certificate, or code running as a managed identity) is full control of the subscription." 'azure'
    }
    $script:mgPriv += @($ra | Where-Object { $_ -and $_.properties -and ("$($_.properties.scope)" -match '^/providers/Microsoft\.Management/managementGroups/' -or "$($_.properties.scope)" -eq '/') -and @($roleOwner, $roleUaa) -contains "$($_.properties.roleDefinitionId)".Split('/')[-1] })
}
# Owner / UAA granted at a management group or the root ('/') is inherited by every subscription
# below it, so it is reported once here (deduplicated) instead of once per subscription.
$mgSp = @($mgPriv | Where-Object { "$($_.properties.principalType)" -eq 'ServicePrincipal' } | Group-Object { "$($_.id)" } | ForEach-Object { $_.Group[0] })
if ($mgSp.Count) {
    if ($null -eq $spNames) { $spNames = @{}; $spAll3 = Load 'servicePrincipals.json'; foreach ($sp in @($spAll3)) { if ($sp -and $sp.id) { $spNames["$($sp.id)"] = "$($sp.displayName)" } } }
    $who = @($mgSp | ForEach-Object { $pid0 = "$($_.properties.principalId)"; if ($spNames[$pid0]) { $spNames[$pid0] } else { $pid0 } } | Select-Object -Unique)
    Add-Finding 'HIGH' 'Service identities' "$($who.Count) service principal(s) hold Owner or User Access Administrator at management-group or root scope, inherited by every subscription below: $($who -join ', ')." 'azure'
}

# --- Output ---
$order = @{ HIGH=0; MEDIUM=1; LOW=2 }
$sorted = $findings | Sort-Object { $order[$_.Severity] }, Area
Write-Host ""
Write-Host "==================== FINDINGS ($($findings.Count)) ====================" -ForegroundColor Green
$sorted | Format-Table Severity, Area, Finding -AutoSize -Wrap
Save-Json $sorted 'FINDINGS-summary.json' | Out-Null
Write-Host (Get-ScopeBanner $scope) -ForegroundColor Yellow
Write-Host "Saved: output/FINDINGS-summary.json" -ForegroundColor Green
