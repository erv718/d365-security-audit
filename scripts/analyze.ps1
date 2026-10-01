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
    $mfaEnforced = @($ca | Where-Object { $_.state -eq 'enabled' -and $_.grantControls.builtInControls -contains 'mfa' })
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
    if ($null -ne $roles) { $custom = @($roles | Where-Object { $_.ismanaged -eq $false }).Count; if ($custom -eq 0) { Add-Finding 'MEDIUM' 'Roles' "[$envName] Zero custom security roles - only built-in roles available to assign." 'dataverse' } }
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
# The environment type comes from the Power Platform inventory, matched on the first label of
# the instance URL (the same name the Dataverse sweep uses for its files).
$skuByHost = @{}
$ppEnvA = Load 'pp-environments.json'
foreach ($e in @($ppEnvA)) {
    if (-not $e -or -not $e.properties -or -not $e.properties.linkedEnvironmentMetadata) { continue }
    $iu = "$($e.properties.linkedEnvironmentMetadata.instanceUrl)"
    if (-not $iu) { continue }
    try { $skuByHost[([Uri]$iu).Host.Split('.')[0].ToLower()] = "$($e.properties.environmentSku)" } catch {}
}
foreach ($f in @(Get-ChildItem $out -Filter 'dv-*-solutions.json')) {
    $envName = $f.BaseName -replace '^dv-' -replace '-solutions$'
    if ($skuByHost["$envName".ToLower()] -ne 'Production') { continue }
    $sols = Load $f.Name
    if ($null -eq $sols) { continue }
    $um = @($sols | Where-Object { $_ -and $_.ismanaged -eq $false -and $_.isvisible -eq $true -and "$($_.uniquename)" -notin 'Default', 'Active', 'Basic' -and "$($_.friendlyname)" -ne 'Common Data Services Default Solution' })
    if ($um.Count) { Add-Finding 'MEDIUM' 'Solutions' "[$envName] $($um.Count) unmanaged solution(s) in a Production environment: $((@($um | ForEach-Object { "$($_.friendlyname)" }) | Select-Object -First 10) -join ', '). Production should only receive managed solutions through a pipeline." 'dataverse' }
}

# --- Dataverse: who holds System Administrator, per environment ---
# dv-<env>-users.json = enabled users with their DIRECTLY assigned roles; a role inherited
# through a team is not visible here, and the findings say so. Left out: built-in accounts
# (SYSTEM, INTEGRATION, support users) and Microsoft-owned application users (first-party '#'
# names, or an app whose service principal is owned by a Microsoft tenant, such as dual-write).
# More than 3 people is MEDIUM in Production and LOW elsewhere (makers often hold it in dev).
$msTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
$appOwner = $null
$dvSysAdmins = @{}
foreach ($f in @(Get-ChildItem $out -Filter 'dv-*-users.json')) {
    $envName = $f.BaseName -replace '^dv-' -replace '-users$'
    $users = Load $f.Name
    if ($null -eq $users) { continue }
    $sa = @($users | Where-Object { $_ -and @($_.systemuserroles_association | Where-Object { $_ -and "$($_.name)" -eq 'System Administrator' }).Count -gt 0 })
    $real = @($sa | Where-Object { "$($_.fullname)" -notin 'SYSTEM', 'INTEGRATION' -and "$($_.fullname)" -notlike '#*' -and "$($_.accessmode)" -ne '3' })
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
        Add-Finding $sev 'D365 admins' "[$envName$(if($sku){" ($sku)"})] $($people.Count) user(s) directly assigned System Administrator (roles inherited through teams not counted): $((@($names) | Select-Object -First 12) -join ', ')$(if($names.Count -gt 12){" (+$($names.Count - 12) more)"}). Keep it to a handful; give everyone else a scoped role." 'dataverse'
    }
    if ($appUsers.Count) {
        Add-Finding 'MEDIUM' 'Service identities' "[$envName] $($appUsers.Count) non-Microsoft application user(s) directly assigned System Administrator: $((@($appUsers | ForEach-Object { "$($_.fullname)" }) | Select-Object -Unique) -join ', '). Service identities should get a scoped role, not full control of the environment." 'dataverse'
    }
}
if ($dormantSet.Count -and $dvSysAdmins.Count) {
    $dvDormant = @()
    foreach ($envKey in $dvSysAdmins.Keys) {
        foreach ($upn in @($dvSysAdmins[$envKey])) { if ($upn -and $dormantSet.ContainsKey("$upn".ToLower())) { $dvDormant += "[$envKey] $upn" } }
    }
    if ($dvDormant.Count) { Add-Finding 'HIGH' 'Dormant admins' "$($dvDormant.Count) Dataverse System Administrator(s) have not signed in for 90+ days: $((@($dvDormant) | Select-Object -First 15) -join '; '). Remove the role unless it is a documented emergency-access account." 'dataverse' }
}

# --- Azure network ---
Get-ChildItem $out -Filter 'arm-*-sql.json' | ForEach-Object {
    $items = Load $_.Name
    foreach ($srv in @($items | Where-Object { $_ })) {
        if ($srv.properties.publicNetworkAccess -eq 'Enabled') { Add-Finding 'HIGH' 'Network' "SQL server '$($srv.name)' has public network access enabled." 'azure' }
        if (@($srv._firewallRules | Where-Object { $_.properties.startIpAddress -eq '0.0.0.0' -and $_.properties.endIpAddress -eq '0.0.0.0' }).Count) { Add-Finding 'HIGH' 'Network' "SQL server '$($srv.name)' allows all Azure IPs (0.0.0.0)." 'azure' }
    }
}
Get-ChildItem $out -Filter 'arm-*-nsgs.json' | ForEach-Object {
    $items = Load $_.Name
    foreach ($nsg in @($items | Where-Object { $_ })) {
        foreach ($rule in $nsg.properties.securityRules) {
            $p = $rule.properties
            if ($p.access -eq 'Allow' -and $p.direction -eq 'Inbound' -and $p.destinationPortRange -in '3389','22','*' -and $p.sourceAddressPrefix -in '*','0.0.0.0/0','Internet') {
                Add-Finding 'HIGH' 'Network' "NSG '$($nsg.name)' rule '$($rule.name)' opens port $($p.destinationPortRange) to the internet." 'azure'
            }
        }
    }
}
Get-ChildItem $out -Filter 'arm-*-keyvaults.json' | ForEach-Object {
    $items = Load $_.Name
    foreach ($v in @($items | Where-Object { $_ })) {
        if (-not $v.properties.enableRbacAuthorization) { Add-Finding 'MEDIUM' 'Key Vault' "Key vault '$($v.name)' uses legacy access policies (not RBAC)." 'azure' }
        if ($v.properties.publicNetworkAccess -eq 'Enabled') { Add-Finding 'MEDIUM' 'Key Vault' "Key vault '$($v.name)' allows public network access." 'azure' }
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
function Get-IpNumber($ip) {
    $o = "$ip".Trim().Split('.')
    if ($o.Count -ne 4) { return $null }
    $n = [double]0
    foreach ($x in $o) { $v = 0; if (-not [int]::TryParse($x, [ref]$v) -or $v -lt 0 -or $v -gt 255) { return $null }; $n = $n * 256 + $v }
    return $n
}
$fwRuleN = 0; $fwResN = 0
foreach ($kind in @(@('sql', 'SQL server'), @('synapse', 'Synapse workspace'))) {
    foreach ($f in @(Get-ChildItem $out -Filter "arm-*-$($kind[0]).json")) {
        $items = Load $f.Name
        foreach ($res in @($items | Where-Object { $_ })) {
            $fwResN++
            $internet = @(); $broad = @()
            foreach ($r in @($res._firewallRules | Where-Object { $_ })) {
                $p = if ($r.properties) { $r.properties } else { $r }
                $sIp = "$($p.startIpAddress)"; $eIp = "$($p.endIpAddress)"
                $a = Get-IpNumber $sIp; $b = Get-IpNumber $eIp
                if ($null -eq $a -or $null -eq $b) { continue }
                $fwRuleN++
                if ($sIp -eq '0.0.0.0' -and $eIp -eq '0.0.0.0') { continue }
                if ($a -eq 0 -and $b -eq 4294967295) { $internet += "$($r.name)" }
                elseif (($b - $a + 1) -gt 65536) { $broad += "$($r.name) ($sIp-$eIp)" }
            }
            if ($internet.Count) { Add-Finding 'HIGH' 'Network' "$($kind[1]) '$($res.name)' firewall allows the entire internet (0.0.0.0-255.255.255.255): $($internet -join ', ')." 'azure' }
            if ($broad.Count) { Add-Finding 'MEDIUM' 'Network' "$($kind[1]) '$($res.name)' firewall allows range(s) wider than a /16: $($broad -join '; ')." 'azure' }
        }
    }
}
if ($fwResN -gt 0) { Add-Finding 'LOW' 'Network' "Allowed-IP inventory: $fwRuleN firewall rule(s) across $fwResN SQL server(s) and Synapse workspace(s). Review every range for stale or over-broad entries (raw rules: output/arm-*-sql.json and arm-*-synapse.json, _firewallRules)." 'azure' }

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
