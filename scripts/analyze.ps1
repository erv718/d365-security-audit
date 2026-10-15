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
# Key names the finding's entry in finding-catalog.json (the plain-language explanation, the fix
# steps and the Microsoft links that security-report.ps1 prints); Kind narrows an allow-list
# finding to its resource type, so the report links that service's firewall page.
function Add-Finding($sev, $area, $text, $plane = 'tenant', $key = '', $kind = '') {
    $f = [ordered]@{ Severity=$sev; Area=$area; Finding=$text }
    if ($scope.partial) { $f.Scope = Get-ScopeTag $scope $plane }
    if ($key) { $f.Key = $key }
    if ($kind) { $f.Kind = $kind }
    $script:findings += [pscustomobject]$f
}
# The documented office and VPN ranges (Conditional Access IP named locations). An allowed address
# inside one is known; one outside every range is somebody's own connection until shown otherwise.
$namedRanges = Get-NamedIpRanges $out
# A named location that an enabled (or report-only) policy uses to block sign-ins lists bad
# addresses, not offices; the estate's own Azure public IPs are known too.
$blockedLocIds = @{}
$caForLoc = Load 'ca-policies.json'
foreach ($cp in @($caForLoc | Where-Object { $_ -and "$($_.state)" -ne 'disabled' -and @($_.grantControls.builtInControls) -contains 'block' })) {
    foreach ($lid in @($cp.conditions.locations.includeLocations | Where-Object { $_ })) { $blockedLocIds["$lid"] = $true }
}
$ownIps = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-publicips.json')) { $x = Load $f.Name; foreach ($p in @($x | Where-Object { $_ -and $_.ipAddress })) { $ownIps += [pscustomobject]@{ ip = "$($p.ipAddress)"; name = "$($p.name)" } } }
$knownRanges = Get-KnownIpRanges $namedRanges $blockedLocIds $ownIps   # plus Microsoft's Lifecycle Services management addresses
$namedUsableN = 0; if ($null -ne $namedRanges) { foreach ($kr in $namedRanges) { if ($null -ne $kr -and -not $blockedLocIds.ContainsKey("$($kr[3])")) { $namedUsableN++ } } }
$allowUnknown = @()

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
        $rg = Get-IpRange $en.range
        $br = Get-IpBreadth $rg -IgnorePrivate:$IgnorePrivate
        if ($br -eq 'internet') { $internet += "$($en.rule)" } elseif ($br -eq 'broad') { $broad += $(if ("$($en.rule)" -eq "$($en.range)") { "$($en.range)" } else { "$($en.rule) ($($en.range))" }) }
        elseif ($null -ne $rg -and -not $en.admin -and -not (Test-IpRangeInternal $rg) -and -not (Get-KnownLocationName $rg $script:knownRanges)) {
            # A specific public address outside every named location (NSG admin ports are graded on their own).
            $script:allowUnknown += "$Kind '$Name'$(if ("$($en.rule)" -ne "$($en.range)") { " rule '$($en.rule)'" }) ($($en.range))"
        }
    }
    if ($internet.Count) { Add-Finding -Key 'allowlist-internet' -Kind $Kind 'HIGH' 'Network' "$Kind '$Name' $What the entire internet (0.0.0.0-255.255.255.255): $($internet -join ', ')." $Plane }
    if ($broad.Count) { Add-Finding -Key 'allowlist-broad' -Kind $Kind 'MEDIUM' 'Network' "$Kind '$Name' $What range(s) wider than a /16: $($broad -join '; ')." $Plane }
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
    if ($expired) { Add-Finding -Key 'app-cred-expired' 'LOW' 'App secrets' "$expired expired app credentials are still attached to app registrations. They can no longer sign in, so this is cleanup: remove them so only live secrets are listed." }
    if ($soon)    { Add-Finding -Key 'app-cred-expiring' 'LOW' 'App secrets' "$soon app credentials expire within 60 days - renew before outage." }
}

# --- High-privilege app permissions (Microsoft Graph and Exchange Online) ---
# Each resource's assignments are matched against its own role catalogue: Exchange roles such as
# full_access_as_app (every mailbox) and Exchange.ManageAsApp (Exchange admin) only exist in the
# Exchange catalogue. Apps are counted once even when a role was assigned more than once.
$risky = $script:RiskyAppRoles   # _common.ps1: graph-sweep.ps1 reads the owners of the apps that hold one
# What each permission reaches, in the finding's words. Mailbox permissions reach every mailbox
# unless Exchange Online scopes the app (RBAC for Applications, which replaces application access
# policies); Exchange.ManageAsApp is PowerShell without a user, as strong as the role the app holds.
function Get-AppRoleReach([string]$Res, [string]$Role) {
    if ($Res -eq 'exo') {
        if ($Role -eq 'Exchange.ManageAsApp') { return ' (Exchange Online PowerShell without a user; what it can change depends on the Exchange or Entra role the app holds)' }
        if ($Role -eq 'full_access_as_app') { return ' (Exchange Online, EWS: full access to every mailbox)' }
        return ' (Exchange Online: every mailbox unless scoped with RBAC for Applications)'
    }
    if ($Role -like 'Mail.*') { return ' (tenant-wide: every mailbox unless scoped with RBAC for Applications in Exchange Online)' }
    return ' (tenant-wide)'
}
$riskySpIds = @{}; $riskyAppNames = @{}; $appRoleRead = $false
foreach ($res in @(@('graph', ''), @('exo', ''))) {
    $defs = Load "appRoleDefinitions-$($res[0]).json"; $asn = Load "appRoleAssignments-$($res[0]).json"
    if (-not ($defs -and $asn)) { continue }
    $appRoleRead = $true
    $map = @{}
    foreach ($d in @($defs)) { if ($d -and $d.id) { $map["$($d.id)"] = "$($d.value)" } }
    $hits = @{}
    foreach ($m in @($asn)) {
        if (-not $m -or -not $m.appRoleId) { continue }
        $rn = $map["$($m.appRoleId)"]
        if ($risky -contains $rn) { if (-not $hits.ContainsKey($rn)) { $hits[$rn] = @() }; $hits[$rn] += "$($m.principalDisplayName)"; $riskySpIds["$($m.principalId)"] = $true; $riskyAppNames["$($m.principalDisplayName)".ToLower()] = $true }
    }
    foreach ($r in $hits.Keys) {
        $who = @($hits[$r] | Where-Object { $_ } | Select-Object -Unique)
        Add-Finding -Key 'app-high-privilege' 'HIGH' 'App access' "$($who.Count) app(s) hold $r$(Get-AppRoleReach $res[0] $r): $($who -join ', ')"
    }
}

# --- Who can add a secret to those apps ---
# An app's owners can add a new client secret or certificate to it and sign in as the app, with no
# admin role (app-owners.json: the owners of each app that holds one of the permissions above).
$appOwnersAll = Load 'app-owners.json'
# Only apps that hold one of the permissions in THIS run's assignment files: an owners file from an
# earlier run, or an app whose permission was since removed, is never reported.
$appOwnersCur = @($appOwnersAll | Where-Object { $_ -and $(if ($_.spId) { $riskySpIds.ContainsKey("$($_.spId)") } else { $riskyAppNames.ContainsKey("$($_.displayName)".ToLower()) }) })
if ($appRoleRead -and $appOwnersCur.Count) {
    $appOwnersAll = $appOwnersCur
    # Graph returns only the id of an owner whose type the app cannot read; the user list fills in names.
    $ownerUpn = @{}
    if (@($appOwnersAll | ForEach-Object { @($_.owners) } | Where-Object { $_ -and -not $_.userPrincipalName -and -not $_.displayName }).Count) {
        $uaOwn = Load 'users-signin-activity.json'
        foreach ($u in @($uaOwn)) { if ($u -and $u.id) { $ownerUpn["$($u.id)"] = "$($u.userPrincipalName)" } }
    }
    $ownLines = @()
    foreach ($ao in @($appOwnersAll | Where-Object { $_ -and @($_.owners | Where-Object { $_ }).Count })) {
        $oNames = @($ao.owners | Where-Object { $_ } | ForEach-Object { if ($_.userPrincipalName) { "$($_.userPrincipalName)" } elseif ($_.displayName) { "$($_.displayName)" } elseif ($ownerUpn["$($_.id)"]) { $ownerUpn["$($_.id)"] } else { "object $($_.id)" } } | Select-Object -Unique)
        $ownLines += "$($ao.displayName) ($(@($ao.roles) -join ', ')) owned by $($oNames -join ', ')"
    }
    $ownErr = @($appOwnersAll | Where-Object { $_.error } | ForEach-Object { "$($_.displayName)" })
    $ownErrText = if ($ownErr.Count) { " The owners of $($ownErr.Count) app(s) could not be read: $((@($ownErr) | Select-Object -First 8) -join ', ')." } else { '' }
    if ($ownLines.Count) { Add-Finding -Key 'app-owner-privileged' 'MEDIUM' 'App access' "$($ownLines.Count) app(s) that hold one of the permissions above have owners, and an owner can add a new secret and sign in as the app with no admin role: $((@($ownLines) | Select-Object -First 12) -join '; ')$(if($ownLines.Count -gt 12){" (+$($ownLines.Count - 12) more)"}).$ownErrText" }
    elseif ($ownErr.Count) { Add-Finding -Key 'app-owner-privileged' 'LOW' 'App access' "Owners not read for $($ownErr.Count) app(s) that hold one of the permissions above: $((@($ownErr) | Select-Object -First 8) -join ', '). An owner can add a secret and act as the app; check them in the Entra admin center." }
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
    $mfaWide = @($mfaEnforced | Where-Object { Test-CaPolicyCoversD365 $_ })
    $mfaOr = @($mfaEnforced | Where-Object { Test-CaPolicyMfaOrOther $_ })
    # No MFA policy and no security defaults: HIGH. MFA policies that reach only a pilot group or a
    # single app: MEDIUM. At least one for all users on all apps (or the Dynamics apps): LOW.
    $sev = 'HIGH'; if ($mfaWide.Count -gt 0 -or $sdOn) { $sev = 'LOW' } elseif ($mfaEnforced.Count -gt 0) { $sev = 'MEDIUM' }
    Add-Finding -Key 'ca-mfa-coverage' $sev 'Conditional Access' "$(@($ca).Count) CA policies; $($on.Count) enabled; $($mfaEnforced.Count) enabled policies require MFA$(if($mfaEnforced.Count){", $($mfaWide.Count) of them for all users on all apps (or the Dynamics apps)"})$(if($mfaEnforced.Count -and -not $mfaWide.Count){'; the rest target only some users or apps (a group, a role or named apps), so not everyone who uses D365 is covered'})$(if($mfaOr.Count){"; $($mfaOr.Count) of them also accept another control (for example a compliant device) instead of MFA"})$(if($sdOn){'; security defaults ON (baseline MFA for everyone)'})."
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
        # 0 = success; these codes come after the password was accepted (MFA or registration
        # required, an external challenge, or a Conditional Access block), so the password is known.
        $pwCodes = '50072', '50074', '50076', '50079', '50158', '53003'
        $legacyOk = @($legacy | Where-Object { "$($_.status.errorCode)" -eq '0' }).Count
        $legacyPw = @($legacy | Where-Object { "$($_.status.errorCode)" -in $pwCodes }).Count
        $legacyFail = $legacy.Count - $legacyOk - $legacyPw
        Add-Finding -Key 'legacy-auth-seen' $(if ($legacyOk + $legacyPw) { 'HIGH' } else { 'MEDIUM' }) 'Legacy auth' "$($legacy.Count) of $total sampled sign-in attempts used legacy/basic authentication ($byClient; $accounts account(s)): $legacyOk succeeded, $legacyPw had the right password and were then stopped by MFA or Conditional Access, $legacyFail failed$(if($legacyPw){'. A right password on a legacy protocol means someone else knows it: reset it'})$(if($legacyFail){'. Failed basic-auth attempts are often password guessing'}). These protocols cannot do MFA - block them with a Conditional Access policy (client apps: Exchange ActiveSync + Other clients)."
    } else {
        Add-Finding -Key 'legacy-auth-none' 'LOW' 'Legacy auth' "0 of $total sampled sign-ins used legacy/basic authentication (sample = most recent interactive sign-ins only; confirm with the Entra 'Sign-ins using legacy authentication' workbook, which needs sign-in logs sent to Log Analytics)."
    }
}

# --- Guests ---
$g = Load 'guest-count.json'
if ($null -ne $g -and $null -ne $g.guestCount) {
    $gn = 0; try { $gn = [int]$g.guestCount } catch {}
    if ($gn -gt 0) { Add-Finding -Key 'guests' 'MEDIUM' 'Guests' "$gn guest accounts tenant-wide. Confirm access reviews exist." }
    else { Add-Finding -Key 'guests-none' 'LOW' 'Guests' '0 guest accounts tenant-wide.' }
}

# --- Directory roles ---
$dr = Load 'directoryRoles.json'
if ($dr) { $ga = [int](@($dr | Where-Object { $_ -and $_.role -eq 'Global Administrator' } | ForEach-Object { [int]$_.memberCount }) | Measure-Object -Maximum).Maximum; if ($ga) { Add-Finding -Key 'global-admins' $(if($ga -ge 5){'MEDIUM'}else{'LOW'}) 'Admin roles' "$ga Global Administrator(s). Microsoft recommends fewer than 5, all with MFA." } }
# Application Administrator and Cloud Application Administrator can add a secret to any app,
# including the ones that hold tenant-wide permissions.
if ($dr) {
    $appAdm = @(); $appAdmOther = 0
    foreach ($r in @($dr | Where-Object { $_ -and "$($_.role)" -in 'Application Administrator', 'Cloud Application Administrator', 'Partner Tier1 Support', 'Partner Tier2 Support' })) {
        $named = @($r.members | Where-Object { $_ })
        foreach ($m in $named) { $appAdm += "$($r.role): $m" }
        $appAdmOther += [Math]::Max(0, [int]$r.memberCount - $named.Count)
    }
    if ($appAdm.Count + $appAdmOther) { Add-Finding -Key 'app-admin-roles' 'LOW' 'Admin roles' "$($appAdm.Count + $appAdmOther) holder(s) of Application Administrator, Cloud Application Administrator or the deprecated Partner Tier1/Tier2 Support roles, which can add a secret to any app (including the ones that hold tenant-wide permissions) and act as it: $((@($appAdm) | Select-Object -First 15) -join '; ')$(if($appAdm.Count -gt 15){" (+$($appAdm.Count - 15) more)"})$(if($appAdmOther){"$(if($appAdm.Count){'; plus '})$appAdmOther app(s), group(s) or account(s) without a sign-in name"})." }
}

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
    if ($dormantSet.Count) { Add-Finding -Key 'dormant-accounts' 'MEDIUM' 'Dormant accounts' "$($dormantSet.Count) of $enabledN enabled account(s) have not signed in for 90+ days ($never with no successful sign-in recorded since Microsoft began recording them in December 2023, $dormantGuests guest(s)). Disable or review them: they keep their access until someone does." }
    else { Add-Finding -Key 'dormant-none' 'LOW' 'Dormant accounts' "0 of $enabledN enabled account(s) idle for 90+ days." }
    $privDormant = @()
    foreach ($r in @($dr)) {
        if (-not $r) { continue }
        foreach ($m in @($r.members)) { if ($m -and $dormantSet.ContainsKey("$m".ToLower())) { $privDormant += "$($r.role): $m" } }
    }
    if ($privDormant.Count) { Add-Finding -Key 'dormant-admins-directory' 'HIGH' 'Dormant admins' "$($privDormant.Count) directory-role assignment(s) belong to accounts idle for 90+ days: $((@($privDormant) | Select-Object -First 15) -join '; ')$(if($privDormant.Count -gt 15){" (+$($privDormant.Count - 15) more)"}). For each: if it is an emergency-access (break-glass) account, keep it but test its sign-in at least every 90 days and alert on any use; otherwise remove the role or disable the account." }
}

# --- Dataverse per environment ---
Get-ChildItem $out -Filter 'dv-*-org.json' | ForEach-Object {
    $envName = ($_.BaseName -replace '^dv-' -replace '-org$')
    $orgs = Load $_.Name; $org = @($orgs)[0]
    if ($org -and $org.isauditenabled -eq $false) { Add-Finding -Key 'dv-audit-off' 'HIGH' 'Auditing' "[$envName] Dataverse auditing is OFF: there is no history of who changed or deleted data (a record only shows who changed it last)." 'dataverse' }
    $roles = Load "dv-$envName-roles.json"
    if ($null -ne $roles) { $custom = @($roles | Where-Object { $_.ismanaged -eq $false }).Count; if ($custom -eq 0) { Add-Finding -Key 'dv-no-custom-role' 'LOW' 'Roles' "[$envName] No unmanaged (customer-authored) security role. Roles delivered in managed solutions are not told apart from built-in ones by this read; confirm a least-privilege role exists for everyday users." 'dataverse' } }
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
    if ($off.Count) { Add-Finding -Key 'dv-table-audit-off' 'MEDIUM' 'Auditing' "[$envName] Table-level auditing is OFF on key table(s): $($off -join ', '). Org auditing records nothing for these tables (Power Apps > Tables > (table) > Properties > Audit changes to its data)." 'dataverse' }
    if ($customOff -gt 0) { Add-Finding -Key 'dv-custom-table-audit-off' 'LOW' 'Auditing' "[$envName] $customOff of $customN custom table(s) have auditing off." 'dataverse' }
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
    if ($um.Count -gt 10) { $umNames += " (+$($um.Count - 10) more)" }
    if ($sku) { Add-Finding -Key 'dv-unmanaged-solutions' 'MEDIUM' 'Solutions' "[$envName] $($um.Count) unmanaged solution(s) in a Production environment: $umNames. Production should only receive managed solutions through a pipeline." 'dataverse' }
    else { Add-Finding -Key 'dv-unmanaged-solutions' 'LOW' 'Solutions' "[$envName] $($um.Count) unmanaged solution(s): $umNames. The environment type was not read; if this is Production it is MEDIUM (Production should only receive managed solutions through a pipeline)." 'dataverse' }
}

# --- Dataverse: who holds System Administrator, per environment ---
# dv-<env>-users.json = enabled users with their DIRECTLY assigned roles; a role inherited
# through a team is not visible here, and the findings say so. Left out: built-in accounts
# (SYSTEM, INTEGRATION, support users) and Microsoft-owned application users: the app's service
# principal is owned by a Microsoft tenant, or the app has no service principal in this tenant at
# all (Dataverse's own platform users; an organisation's own or consented apps always have one).
# Without the service principal list (identity read skipped or failed) they cannot be told
# apart, and the finding says so at LOW. The '#' in front of an application user's name is NOT a
# Microsoft marker: Dataverse adds it to every app user.
# More than 3 people is MEDIUM in Production and LOW elsewhere (makers often hold it in dev).
$msTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
$appOwner = $null
$dvSysAdmins = @{}
foreach ($f in @(Get-ChildItem $out -Filter 'dv-*-users.json')) {
    $envName = $f.BaseName -replace '^dv-' -replace '-users$'
    $users = Load $f.Name
    if ($null -eq $users) { continue }
    $sa = @($users | Where-Object { $_ -and @($_.systemuserroles_association | Where-Object { $_ -and "$($_.name)" -eq 'System Administrator' }).Count -gt 0 })
    # accessmode 3 = Support User (Microsoft support), 5 = Delegated Admin (the built-in account a partner
    # with delegated admin rights works through; Microsoft says not to change its roles): neither is one
    # of the organisation's people.
    $delegated = @($sa | Where-Object { "$($_.accessmode)" -eq '5' })
    $real = @($sa | Where-Object { "$($_.fullname)" -notin 'SYSTEM', 'INTEGRATION' -and "$($_.accessmode)" -notin '3', '5' })
    $people = @($real | Where-Object { -not $_.applicationid })
    $appUsers = @($real | Where-Object { $_.applicationid })
    if ($appUsers.Count -and $null -eq $appOwner) {
        $appOwner = @{}
        $spAll2 = Load 'servicePrincipals.json'
        foreach ($sp in @($spAll2)) { if ($sp -and $sp.appId) { $appOwner["$($sp.appId)".ToLower()] = "$($sp.appOwnerOrganizationId)".ToLower() } }
    }
    # Three groups once owners were read: Microsoft-owned (dropped), a known non-Microsoft owner
    # (the organisation's own or a consented third-party app), and no owner on record (no service
    # principal in this tenant, or one with an empty owner: a platform service or a deleted app).
    $ownersKnown = ($appOwner.Count -gt 0)
    $appNoOwner = @()
    if ($ownersKnown) {
        $appNoOwner = @($appUsers | Where-Object { $k = "$($_.applicationid)".ToLower(); -not $appOwner.ContainsKey($k) -or -not $appOwner[$k] })
        $appUsers   = @($appUsers | Where-Object { $k = "$($_.applicationid)".ToLower(); $appOwner.ContainsKey($k) -and $appOwner[$k] -and $msTenants -notcontains $appOwner[$k] })
    }
    $names = @($people | ForEach-Object { if ($_.domainname) { "$($_.domainname)" } else { "$($_.fullname)" } })
    $dvSysAdmins[$envName] = $names   # bare UPNs: the dormant-admin cross-check matches on them
    # Listed with a marker when the account is not a member of the organisation or not a person.
    $shown = @($people | ForEach-Object { $n = if ($_.domainname) { "$($_.domainname)" } else { "$($_.fullname)" }; $k = Get-DvUserKind $_; if ($k) { "$n ($k)" } else { $n } })
    $sku = $skuByHost["$envName".ToLower()]
    if ($people.Count) {
        $sev = if ($people.Count -gt 3 -and $sku -eq 'Production') { 'MEDIUM' } else { 'LOW' }
        Add-Finding -Key 'dv-sysadmin-people' $sev 'D365 admins' "[$envName$(if($sku){" ($sku)"}else{' (type not read)'})] $($people.Count) user(s) directly assigned System Administrator (roles inherited through teams not counted): $((@($shown) | Select-Object -First 12) -join ', ')$(if($shown.Count -gt 12){" (+$($shown.Count - 12) more)"}). Keep it to a handful; give everyone else a scoped role.$(if($delegated.Count){" Not counted: $($delegated.Count) delegated-admin account(s), the built-in account a partner with delegated admin rights works through; Microsoft says not to change its roles, so end the partner's delegated admin access instead when it is no longer needed."})$(if(-not $sku -and $people.Count -gt 3){' MEDIUM if this is a Production environment.'})" 'dataverse'
    }
    if ($appUsers.Count -and $ownersKnown) {
        Add-Finding -Key 'dv-sysadmin-apps-own' 'MEDIUM' 'Service identities' "[$envName] $($appUsers.Count) of your organisation's own (or consented third-party) application user(s) directly assigned System Administrator: $((@($appUsers | ForEach-Object { "$($_.fullname)" }) | Select-Object -Unique) -join ', '). Service identities should get a scoped role, not full control of the environment." 'dataverse'
    } elseif ($appUsers.Count) {
        Add-Finding -Key 'dv-sysadmin-apps-unread' 'LOW' 'Service identities' "[$envName] $($appUsers.Count) application user(s) directly assigned System Administrator. Most are usually Dynamics' own platform accounts, which this run could not tell apart from your organisation's apps because the service principal list was not read (identity sweep skipped or failed); run without -SkipGraph to list only your own: $((@($appUsers | ForEach-Object { "$($_.fullname)" }) | Select-Object -Unique -First 15) -join ', ')$(if($appUsers.Count -gt 15){" (+$($appUsers.Count - 15) more)"})." 'dataverse'
    }
    if ($appNoOwner.Count) {
        $noOwnerNames = @($appNoOwner | ForEach-Object { "$($_.fullname)" } | Select-Object -Unique)
        Add-Finding -Key 'dv-sysadmin-apps-noowner' 'LOW' 'Service identities' "[$envName] $($appNoOwner.Count) application user(s) directly assigned System Administrator whose app's owner could not be told (no service principal in this tenant, or one that records no owner): $((@($noOwnerNames) | Select-Object -First 15) -join ', ')$(if($noOwnerNames.Count -gt 15){" (+$($noOwnerNames.Count - 15) more)"}). A Microsoft platform service can look like this, and so can an app registration that was deleted. Look each one up by its application id: expected for a platform service, but remove the role from any you do not recognize." 'dataverse'
    }
}
if ($dormantSet.Count -and $dvSysAdmins.Count) {
    $dvDormant = @()
    foreach ($envKey in $dvSysAdmins.Keys) {
        foreach ($upn in @($dvSysAdmins[$envKey])) { if ($upn -and $dormantSet.ContainsKey("$upn".ToLower())) { $dvDormant += "[$envKey] $upn" } }
    }
    if ($dvDormant.Count) { Add-Finding -Key 'dormant-admins-dataverse' 'HIGH' 'Dormant admins' "$($dvDormant.Count) Dataverse System Administrator(s) have not signed in for 90+ days: $((@($dvDormant) | Select-Object -First 15) -join '; ')$(if($dvDormant.Count -gt 15){" (+$($dvDormant.Count - 15) more)"}). Remove the role unless it is a documented emergency-access account, and sign in to an emergency account at least every 90 days to test it, as Microsoft advises." 'dataverse' }
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
if ($dvFwOff.Count) { Add-Finding -Key 'dv-ipfirewall-off' 'LOW' 'Network' "Dataverse IP firewall is off in $($dvFwOff.Count) environment(s): $($dvFwOff -join ', '). It limits Dataverse to your office and VPN ranges, so a stolen sign-in token cannot be used from anywhere else (it needs Managed Environments and has licensing requirements; start in audit-only mode)." 'dataverse' }
if ($dvFwAudit.Count) { Add-Finding -Key 'dv-ipfirewall-audit' 'LOW' 'Network' "Dataverse IP firewall is in audit-only mode (it logs, it never blocks) in: $($dvFwAudit -join ', ')." 'dataverse' }

# --- Azure network ---
Get-ChildItem $out -Filter 'arm-*-sql.json' | ForEach-Object {
    $items = Load $_.Name
    foreach ($srv in @($items | Where-Object { $_ })) {
        if ($srv.properties.publicNetworkAccess -eq 'Enabled') { Add-Finding -Key 'sql-public' 'HIGH' 'Network' "SQL server '$($srv.name)' has public network access enabled." 'azure' }
        if (@($srv._firewallRules | Where-Object { $_.properties.startIpAddress -eq '0.0.0.0' -and $_.properties.endIpAddress -eq '0.0.0.0' }).Count) { Add-Finding -Key 'sql-allow-azure' 'HIGH' 'Network' "SQL server '$($srv.name)' allows all Azure IPs (0.0.0.0)." 'azure' }
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
# Azure applies an NSG's rules in priority order and stops at the first match: an Allow is shadowed
# for a source when a Deny with a lower priority number covers that source, its protocol and every
# risky port the Allow opens. (Several Denies that only cover it together are not combined.)
function Get-NsgDenies($Nsg) {
    $d = @()
    foreach ($r in @($Nsg.properties.securityRules | Where-Object { $_ -and "$($_.properties.access)" -eq 'Deny' -and "$($_.properties.direction)" -eq 'Inbound' })) {
        $q = $r.properties
        $d += [pscustomobject]@{ priority = [int]$q.priority; protocol = "$($q.protocol)"
            srcs = @(@($q.sourceAddressPrefix) + @($q.sourceAddressPrefixes) | Where-Object { $_ } | ForEach-Object { "$_" })
            ports = @(@($q.destinationPortRange) + @($q.destinationPortRanges) | Where-Object { $_ } | ForEach-Object { "$_" }) }
    }
    return $d
}
function Test-PortInRanges([int]$Port, $Ranges) {
    foreach ($pr in @($Ranges)) {
        $t = "$pr".Trim()
        if ($t -eq '*') { return $true }
        if ($t -match '^(\d+)-(\d+)$') { if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true } }
        elseif ($t -match '^\d+$' -and [int]$t -eq $Port) { return $true }
    }
    return $false
}
function Test-AllowShadowed($Rule, [string]$Src, $Ports, $Denies) {
    $prio = [int]$Rule.properties.priority; $proto = "$($Rule.properties.protocol)"
    $sr = Get-IpRange $Src
    foreach ($d in @($Denies | Where-Object { $_ -and $_.priority -lt $prio })) {
        if ($d.protocol -ne '*' -and $d.protocol -ne $proto) { continue }
        $covered = $false
        foreach ($ds in @($d.srcs)) {
            if ("$ds" -in '*', 'Internet', 'Any', '0.0.0.0/0', '::/0') { $covered = $true; break }
            $dr = Get-IpRange "$ds"
            if ($null -ne $dr -and $null -ne $sr -and $sr[0] -ge $dr[0] -and $sr[1] -le $dr[1]) { $covered = $true; break }
        }
        if (-not $covered) { continue }
        if (-not @($Ports | Where-Object { -not (Test-PortInRanges $_ $d.ports) }).Count) { return $true }
    }
    return $false
}
$riskyPortNumbers = @($riskyPorts.Keys | ForEach-Object { [int]$_ })
$nsgWebOpen = @(); $nsgAdminIp = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-nsgs.json')) {
    $items = Load $f.Name
    foreach ($nsg in @($items | Where-Object { $_ })) {
        $attached = (@($nsg.properties.networkInterfaces | Where-Object { $_ }).Count + @($nsg.properties.subnets | Where-Object { $_ }).Count) -gt 0
        $nsgNote = if ($attached) { '' } else { ' (this NSG is not attached to any subnet or network interface)' }
        $allowEntries = @()
        $denies = Get-NsgDenies $nsg
        foreach ($rule in @($nsg.properties.securityRules | Where-Object { $_ })) {
            $p = $rule.properties
            if ("$($p.access)" -ne 'Allow' -or "$($p.direction)" -ne 'Inbound') { continue }
            if ("$($p.protocol)" -eq 'Icmp') { continue }   # ping, not a port
            $srcs = @(@($p.sourceAddressPrefix) + @($p.sourceAddressPrefixes) | Where-Object { $_ } | ForEach-Object { "$_" })
            $ports = @(@($p.destinationPortRange) + @($p.destinationPortRanges) | Where-Object { $_ } | ForEach-Object { "$_" })
            $hits = @(Get-RiskyPortHits $ports)
            $portText = if ($hits -contains 'all ports') { 'all ports' } else { "port(s) $($hits -join ', ')" }
            $hitPorts = if ($hits -contains 'all ports') { $riskyPortNumbers } else { @($hits | ForEach-Object { if ("$_" -match '^(\d+)') { [int]$Matches[1] } }) }
            $dsts = @(@($p.destinationAddressPrefix) + @($p.destinationAddressPrefixes) | Where-Object { $_ } | ForEach-Object { "$_" })
            if (@($srcs | Where-Object { $_ -in '*', 'Internet', 'Any', '0.0.0.0/0', '::/0' }).Count) {
                if ($hits.Count -and -not (Test-AllowShadowed $rule '*' $hitPorts $denies)) { Add-Finding -Key 'nsg-admin-internet' 'HIGH' 'Network' "NSG '$($nsg.name)' rule '$($rule.name)' opens $portText to the internet.$nsgNote" 'azure' }
                else { $nsgWebOpen += "$($nsg.name)/$($rule.name) ($($ports -join ','))" }
                continue
            }
            if ($hits.Count -and @($srcs | Where-Object { $_ -eq 'AzureCloud' -or $_ -like 'AzureCloud.*' }).Count) {
                Add-Finding -Key 'nsg-azurecloud' 'MEDIUM' 'Network' "NSG '$($nsg.name)' rule '$($rule.name)' opens $portText to every Azure customer's address space (service tag AzureCloud).$nsgNote" 'azure'
            }
            foreach ($src in $srcs) {
                $srcRange = Get-IpRange $src
                if ($null -eq $srcRange) {
                    # An IPv6 address or range on an admin port: listed, never compared with named locations.
                    if ($hits.Count -and "$src" -match ':' -and -not (Test-AllowShadowed $rule $src $hitPorts $denies)) {
                        $nsgAdminIp += [pscustomobject]@{ nsg = "$($nsg.name)"; nsgId = "$($nsg.id)".ToLower(); rule = "$($rule.name)"; ports = $portText; src = $src; attached = $attached; dst = $dsts; ipv6 = $true }
                    }
                    continue
                }
                # A specific public address (not private space, not wider than a /16) on a remote-admin
                # or database port is graded on its own below; the allow-list pass only counts it.
                $isAdmin = ($hits.Count -gt 0 -and -not (Test-IpRangeInternal $srcRange) -and $null -eq (Get-IpBreadth $srcRange))
                if ($isAdmin -and -not (Test-AllowShadowed $rule $src $hitPorts $denies)) { $nsgAdminIp += [pscustomobject]@{ nsg = "$($nsg.name)"; nsgId = "$($nsg.id)".ToLower(); rule = "$($rule.name)"; ports = $portText; src = $src; attached = $attached; dst = $dsts; ipv6 = $false } }
                $allowEntries += @{ rule = "$($rule.name)"; range = $src; admin = $isAdmin }
            }
        }
        Add-AllowList 'NSG' $nsg.name $allowEntries 'azure' 'allows inbound from' -IgnorePrivate
    }
}
if ($nsgWebOpen.Count) { Add-Finding -Key 'nsg-web-open' 'LOW' 'Network' "$($nsgWebOpen.Count) NSG rule(s) allow inbound internet traffic on other ports (for example web traffic): $((@($nsgWebOpen) | Select-Object -First 12) -join '; ')$(if($nsgWebOpen.Count -gt 12){" (+$($nsgWebOpen.Count - 12) more)"}). Confirm each one fronts a service that is meant to be public." 'azure' }
$kvSoftOff = @(); $kvPurgeOff = @()
foreach ($kvFile in @(Get-ChildItem $out -Filter 'arm-*-keyvaults.json')) {
    $items = Load $kvFile.Name
    foreach ($v in @($items | Where-Object { $_ })) {
        if (-not $v.properties.enableRbacAuthorization) { Add-Finding -Key 'kv-access-policies' 'MEDIUM' 'Key Vault' "Key vault '$($v.name)' uses legacy access policies (not RBAC)." 'azure' }
        if ("$($v.properties.publicNetworkAccess)" -ne 'Disabled' -and "$($v.properties.networkAcls.defaultAction)" -ne 'Deny') { Add-Finding -Key 'kv-public' 'MEDIUM' 'Key Vault' "Key vault '$($v.name)' allows public network access from any network (no firewall default-deny)." 'azure' }
        # Soft delete keeps a deleted key, secret or certificate recoverable for the retention period;
        # purge protection stops anyone purging it before that. As in Microsoft's built-in Azure
        # Policy definitions, anything but true counts as not enabled.
        if ($v.properties.enableSoftDelete -ne $true) { $kvSoftOff += "$($v.name)" }
        if ($v.properties.enablePurgeProtection -ne $true) { $kvPurgeOff += "$($v.name)" }
    }
}
if ($kvSoftOff.Count) { Add-Finding -Key 'kv-delete-protection' 'MEDIUM' 'Key Vault' "$($kvSoftOff.Count) key vault(s) do not have soft delete on, so a deleted key, secret or certificate can be gone at once with no way to recover it: $($kvSoftOff -join ', ')." 'azure' }
if ($kvPurgeOff.Count) { Add-Finding -Key 'kv-delete-protection' 'LOW' 'Key Vault' "$($kvPurgeOff.Count) key vault(s) have purge protection off, so a deleted key, secret or certificate can be purged for good before its retention period ends: $((@($kvPurgeOff) | Select-Object -First 15) -join ', ')$(if($kvPurgeOff.Count -gt 15){" (+$($kvPurgeOff.Count - 15) more)"})." 'azure' }

# --- Synapse workspaces: public access and the allow-all-Azure rule ---
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-synapse.json')) {
    $items = Load $f.Name
    foreach ($ws in @($items | Where-Object { $_ })) {
        if ("$($ws.properties.publicNetworkAccess)" -eq 'Enabled') { Add-Finding -Key 'synapse-public' 'HIGH' 'Network' "Synapse workspace '$($ws.name)' has public network access enabled." 'azure' }
        if (@($ws._firewallRules | Where-Object { $_ -and "$($_.properties.startIpAddress)" -eq '0.0.0.0' -and "$($_.properties.endIpAddress)" -eq '0.0.0.0' }).Count) { Add-Finding -Key 'synapse-allow-azure' 'HIGH' 'Network' "Synapse workspace '$($ws.name)' allows all Azure IPs (0.0.0.0)." 'azure' }
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
# interface or on its subnet, a Basic SKU public IP leaves every port the operating system
# listens on reachable; a Standard SKU public IP blocks all inbound traffic until an NSG allows
# it, so it is not exposed (Microsoft, "Public IP addresses"). An unread SKU is reported with
# that condition. A subnet the run did not read is never assumed to be unprotected. VMs behind a
# public load balancer (Lifecycle Services cloud-hosted VMs, for one) have no public IP on the
# interface; their NSG rules are still graded above.
$nicById = @{}; $pipById = @{}; $subnetNsg = @{}
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-nics.json')) { $x = Load $f.Name; foreach ($n in @($x | Where-Object { $_ -and $_.id })) { $nicById["$($n.id)".ToLower()] = $n } }
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-publicips.json')) { $x = Load $f.Name; foreach ($p in @($x | Where-Object { $_ -and $_.id })) { $pipById["$($p.id)".ToLower()] = $p } }
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-vnets.json')) { $x = Load $f.Name; foreach ($v in @($x | Where-Object { $_ })) { foreach ($sn in @($v.subnets | Where-Object { $_ -and $_.id })) { $subnetNsg["$($sn.id)".ToLower()] = "$($sn.nsg)" } } }
$vmOnNet = @(); $vmBare = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-vms.json')) {
    $x = Load $f.Name
    foreach ($vm in @($x | Where-Object { $_ })) {
        $ips = @(); $bare = $false; $skuUnread = $false; $skuBasic = $false
        foreach ($nid in @($vm.nics | Where-Object { $_ })) {
            $nic = $nicById["$nid".ToLower()]
            if (-not $nic) { continue }
            foreach ($ipc in @($nic.ipConfigs | Where-Object { $_ -and $_.publicIp })) {
                $pip = $pipById["$($ipc.publicIp)".ToLower()]
                $ips += $(if ($pip -and $pip.ipAddress) { "$($pip.ipAddress)" } else { 'public IP' })
                $subKey = "$($ipc.subnet)".ToLower()
                $pipSku = if ($pip) { "$($pip.sku)" } else { '' }
                if (-not $nic.nsg -and $subnetNsg.ContainsKey($subKey) -and -not $subnetNsg[$subKey] -and $pipSku -ne 'Standard') { $bare = $true; if (-not $pipSku) { $skuUnread = $true } else { $skuBasic = $true } }
            }
        }
        if ($ips.Count) { $vmOnNet += "$($vm.name) ($($ips -join ', '))"; if ($bare) { $vmBare += "$($vm.name) ($($ips -join ', '))$(if ($skuBasic) { ' (Basic SKU)' } elseif ($skuUnread) { ' (public IP SKU not read: open only if it is Basic)' })" } }
    }
}
if ($vmBare.Count) { Add-Finding -Key 'vm-public-no-nsg' 'HIGH' 'Network' "$($vmBare.Count) VM(s) have a public IP and no NSG on the network interface or its subnet; with a Basic SKU public IP every port the OS listens on is reachable from the internet: $($vmBare -join '; '). Basic SKU public IPs were retired on 30 September 2025; a Standard SKU public IP blocks inbound traffic until an NSG allows it." 'azure' }
if ($vmOnNet.Count) { Add-Finding -Key 'vm-public-ip' 'LOW' 'Network' "$($vmOnNet.Count) VM(s) have a public IP address: $((@($vmOnNet) | Select-Object -First 15) -join '; ')$(if($vmOnNet.Count -gt 15){" (+$($vmOnNet.Count - 15) more)"}). Anything their NSG lets in is reachable from the internet; prefer a VPN for admin access (Azure Bastion where it is supported)." 'azure' }

# --- Specific public addresses on remote-admin or database ports (collected in the NSG pass) ---
# Usually one person's own connection added to reach a VM directly (for example a developer's
# home address on a Lifecycle Services cloud-hosted VM). An address inside a Conditional Access IP
# named location is a documented office or VPN range and is listed apart.
$vmByNsg = @{}; $vmIps = @{}; $vmTwoNsg = @{}
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-vms.json')) {
    $x = Load $f.Name
    foreach ($vm in @($x | Where-Object { $_ })) {
        foreach ($nid in @($vm.nics | Where-Object { $_ })) {
            $nic = $nicById["$nid".ToLower()]
            if (-not $nic) { continue }
            $vmIps["$($vm.name)"] = @($vmIps["$($vm.name)"]) + @($nic.ipConfigs | Where-Object { $_ -and $_.privateIp } | ForEach-Object { "$($_.privateIp)" })
            $subNsgs = @($nic.ipConfigs | Where-Object { $_ } | ForEach-Object { $subnetNsg["$($_.subnet)".ToLower()] } | Where-Object { $_ })
            if ($nic.nsg -and $subNsgs.Count) { $vmTwoNsg["$($vm.name)"] = $true }   # traffic must pass both NSGs
            $nsgIds = @("$($nic.nsg)") + @($nic.ipConfigs | Where-Object { $_ } | ForEach-Object { $subnetNsg["$($_.subnet)".ToLower()] })
            foreach ($ng in @($nsgIds | Where-Object { $_ })) { $k = "$ng".ToLower(); if (-not $vmByNsg.ContainsKey($k)) { $vmByNsg[$k] = @() }; $vmByNsg[$k] += "$($vm.name)" }
        }
    }
}
$adminUnknown = @(); $adminKnown = @(); $adminUnknownSrc = @{}; $adminDormant = 0
foreach ($e in $nsgAdminIp) {
    if (-not $e.attached) { $adminDormant++; continue }   # an NSG attached to nothing lets nothing in today
    $vms = @($vmByNsg[$e.nsgId] | Where-Object { $_ } | Select-Object -Unique)
    # A rule aimed at specific private addresses reaches only the VMs that hold them.
    $dstIp = @($e.dst | Where-Object { $_ -and "$_" -notin '*', 'Any', 'VirtualNetwork' -and $null -ne (Get-IpRange "$_") })
    if ($dstIp.Count -and $vms.Count) {
        $keep = @()
        foreach ($vn in $vms) {
            $hit = $false
            foreach ($vip in @($vmIps[$vn] | Where-Object { $_ })) {
                $vr = Get-IpRange "$vip"
                foreach ($dp in $dstIp) { $dr = Get-IpRange "$dp"; if ($vr -and $dr -and $vr[0] -ge $dr[0] -and $vr[1] -le $dr[1]) { $hit = $true } }
            }
            if ($hit) { $keep += $vn }
        }
        $vms = $keep
    }
    $where = if ($vms.Count) { " on VM $($vms -join ', ')$(if (@($vms | Where-Object { $vmTwoNsg[$_] }).Count) { ' (another NSG on the way must also allow it)' })" } else { '' }
    $line = "$($e.nsg)/$($e.rule) $($e.ports) from $($e.src)$where"
    $loc = if ($e.ipv6) { $null } else { Get-KnownLocationName (Get-IpRange $e.src) $knownRanges }
    if ($loc) { $adminKnown += "$line ($loc)" } else { $adminUnknown += $(if ($e.ipv6) { "$line (IPv6, not compared with named locations)" } else { $line }); $adminUnknownSrc["$($e.src)"] = $true }
}
$namedNote = if ($null -eq $namedRanges) { 'Conditional Access named locations were not read, so none could be compared with your office and VPN ranges' } elseif (-not $namedUsableN) { 'no Conditional Access IP named location (other than ones used to block sign-ins) exists to compare them with' } else { "none is inside your $namedUsableN Conditional Access IP range(s) (your documented office and VPN ranges)" }
if ($adminUnknown.Count) { Add-Finding -Key 'nsg-admin-public-ip' 'MEDIUM' 'Network' "$($adminUnknown.Count) NSG rule source(s) let a specific public IP address ($($adminUnknownSrc.Count) distinct) reach remote-admin or database ports, and $($namedNote): $((@($adminUnknown) | Select-Object -First 15) -join '; ')$(if($adminUnknown.Count -gt 15){" (+$($adminUnknown.Count - 15) more)"}). These are usually one person's own connection (home, hotel, phone hotspot) added to reach a VM directly.$(if($adminDormant){" ($adminDormant more on NSGs attached to nothing are not counted.)"})" 'azure' }
if ($adminKnown.Count) { Add-Finding -Key 'nsg-admin-known-ip' 'LOW' 'Network' "$($adminKnown.Count) NSG rule source(s) allow remote-admin or database ports only from known addresses (your named office or VPN ranges, or Microsoft's Lifecycle Services management addresses): $((@($adminKnown) | Select-Object -First 15) -join '; ')$(if($adminKnown.Count -gt 15){" (+$($adminKnown.Count - 15) more)"}). Confirm each one is still needed." 'azure' }

# --- Storage accounts (arm-*-storage.json) ---
$stOpen = @(); $stAnon = @(); $stHttp = @(); $stTls = @(); $stKey = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-storage.json')) {
    $x = Load $f.Name
    foreach ($a in @($x | Where-Object { $_ })) {
        if ("$($a.publicNetworkAccess)" -notin 'Disabled', 'SecuredByPerimeter' -and "$($a.defaultAction)" -eq 'Allow') { $stOpen += $a.name }
        if ($a.allowBlobPublicAccess -ne $false) { $stAnon += $a.name }
        if ($a.supportsHttpsTrafficOnly -eq $false) { $stHttp += $a.name }
        $tlsV = "$($a.minimumTlsVersion)"
        if (-not $tlsV) { $stTls += "$($a.name) (no minimum set)" } elseif ($tlsV -in 'TLS1_0', 'TLS1_1') { $stTls += "$($a.name) ($tlsV)" }
        if ($a.allowSharedKeyAccess -ne $false) { $stKey += $a.name }
        Add-AllowList 'Storage account' $a.name @(@($a.ipRules | Where-Object { $_ }) | ForEach-Object { @{ rule = "$_"; range = "$_" } }) 'azure' 'allows'
    }
}
if ($stOpen.Count) { Add-Finding -Key 'storage-open-networks' 'MEDIUM' 'Storage' "$($stOpen.Count) storage account(s) accept connections from all networks (public network access on, default action Allow): $($stOpen -join ', '). Most data access still needs a key or a token (a container set to anonymous access does not), but anyone can try; limit them to selected networks or private endpoints." 'azure' }
if ($stAnon.Count) { Add-Finding -Key 'storage-anon-blob' 'MEDIUM' 'Storage' "$($stAnon.Count) storage account(s) allow, or do not block (setting unset on an older account), anonymous blob access on containers: $($stAnon -join ', '). Set 'Allow Blob anonymous access' to Disabled unless a container is meant to be public." 'azure' }
if ($stHttp.Count) { Add-Finding -Key 'storage-http' 'MEDIUM' 'Storage' "$($stHttp.Count) storage account(s) accept plain HTTP (secure transfer not required): $($stHttp -join ', ')." 'azure' }
if ($stTls.Count) { Add-Finding -Key 'storage-tls' 'LOW' 'Storage' "$($stTls.Count) storage account(s) are set to accept TLS below 1.2 (a minimum of 1.0 or 1.1, or none set): $($stTls -join ', '). Azure Storage stopped accepting TLS 1.0 and 1.1 on 3 February 2026, so this is mostly configuration hygiene now; set the minimum to TLS 1.2 so the setting matches (Microsoft's own policy flags anything else)." 'azure' }
if ($stKey.Count) { Add-Finding -Key 'storage-shared-key' 'LOW' 'Storage' "$($stKey.Count) storage account(s) still accept shared-key authorization (account keys, and account or service SAS tokens), which bypasses Entra ID and leaves no per-user trail: $($stKey -join ', '). Turn it off where nothing depends on it." 'azure' }

# --- App Service and Function Apps (arm-*-appservice.json) ---
$apHttp = @(); $apTls = @(); $apFtp = @(); $apDebug = @(); $apOpen = @(); $apUnread = @(); $fnOpen = @(); $fnLimited = @(); $fnAuth = @(); $fnUnknown = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-appservice.json')) {
    $x = Load $f.Name
    foreach ($site in @($x | Where-Object { $_ })) {
        if ($site.httpsOnly -eq $false) { $apHttp += $(if ($site.easyAuth -eq $true) { "$($site.name) (App Service authentication is on and redirects to HTTPS by default)" } else { "$($site.name)" }) }
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
if ($fnOpen.Count) { Add-Finding -Key 'fn-anon-open' 'MEDIUM' 'App Service' "$($fnOpen.Count) HTTP function(s) need no key (authLevel anonymous) on app(s) that accept traffic from any IP and have no App Service authentication: $((@($fnOpen) | Select-Object -First 12) -join ', ')$(if($fnOpen.Count -gt 12){" (+$($fnOpen.Count - 12) more)"}). Anyone who finds the URL can call them; use function keys, App Service authentication or access restrictions unless they are meant to be public." 'azure' }
if ($fnUnknown.Count) { Add-Finding -Key 'fn-anon-unknown' 'LOW' 'App Service' "$($fnUnknown.Count) HTTP function(s) need no key, and the app's web config could not be read, so whether anyone can reach them is unknown: $((@($fnUnknown) | Select-Object -First 12) -join ', ')$(if($fnUnknown.Count -gt 12){" (+$($fnUnknown.Count - 12) more)"})." 'azure' }
if ($fnLimited.Count) { Add-Finding -Key 'fn-anon-limited' 'LOW' 'App Service' "$($fnLimited.Count) HTTP function(s) need no key but sit behind access restrictions or private access: $((@($fnLimited) | Select-Object -First 12) -join ', ')$(if($fnLimited.Count -gt 12){" (+$($fnLimited.Count - 12) more)"})." 'azure' }
if ($fnAuth.Count) { Add-Finding -Key 'fn-anon-auth' 'LOW' 'App Service' "$($fnAuth.Count) HTTP function(s) need no function key but App Service authentication requires a sign-in first: $((@($fnAuth) | Select-Object -First 12) -join ', ')$(if($fnAuth.Count -gt 12){" (+$($fnAuth.Count - 12) more)"})." 'azure' }
if ($apUnread.Count) { Add-Finding -Key 'app-config-unread' 'LOW' 'App Service' "$($apUnread.Count) app(s) whose web configuration could not be read (TLS, FTP, debugging and access restrictions unknown; see arm-*-appservice.json errors): $((@($apUnread) | Select-Object -First 15) -join ', ')$(if($apUnread.Count -gt 15){" (+$($apUnread.Count - 15) more)"})." 'azure' }
if ($apHttp.Count) { Add-Finding -Key 'app-https-off' 'MEDIUM' 'App Service' "$($apHttp.Count) app(s) do not force HTTPS (HTTPS Only off): $($apHttp -join ', ')." 'azure' }
if ($apTls.Count) { Add-Finding -Key 'app-tls-old' 'MEDIUM' 'App Service' "$($apTls.Count) app(s) accept TLS below 1.2: $($apTls -join ', ')." 'azure' }
if ($apFtp.Count) { Add-Finding -Key 'app-ftp' 'MEDIUM' 'App Service' "$($apFtp.Count) app(s) allow plain FTP for deployments (FTP state All allowed; it works wherever FTP basic-auth publishing credentials are also on, which this run does not read): $($apFtp -join ', '). Set it to FTPS only or Disabled." 'azure' }
if ($apDebug.Count) { Add-Finding -Key 'app-remote-debug' 'MEDIUM' 'App Service' "$($apDebug.Count) app(s) have remote debugging turned on: $($apDebug -join ', ')." 'azure' }
if ($apOpen.Count) { Add-Finding -Key 'app-open-ip' 'LOW' 'App Service' "$($apOpen.Count) app(s) accept traffic from any IP address (no access restrictions): $((@($apOpen) | Select-Object -First 15) -join ', ')$(if($apOpen.Count -gt 15){" (+$($apOpen.Count - 15) more)"}). Fine for a public site; for internal APIs and Function Apps, add access restrictions or a private endpoint." 'azure' }

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
if ($laOpen.Count) { Add-Finding -Key 'logicapp-open-trigger' 'LOW' 'Integration' "$($laOpen.Count) Logic App(s) start from an HTTP request and accept calls from any IP: $((@($laOpen) | Select-Object -First 15) -join ', ')$(if($laOpen.Count -gt 15){" (+$($laOpen.Count - 15) more)"}). Each call still needs the trigger URL's signature, so anyone holding that URL can start the workflow; restrict caller IPs (on Consumption logic apps you can also require Microsoft Entra ID and then turn off SAS, once every caller has moved off the old URL)." 'azure' }

# --- Automation: retired Run As connections (arm-*-automation.json) ---
$runAs = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-automation.json')) {
    $x = Load $f.Name
    foreach ($acct in @($x | Where-Object { $_ })) {
        $ra = @($acct.connections | Where-Object { $_ -and ("$($_.type)" -eq 'AzureServicePrincipal' -or "$($_.name)" -in 'AzureRunAsConnection', 'AzureClassicRunAsConnection') })
        if ($ra.Count) { $runAs += "$($acct.name) ($((@($ra | ForEach-Object { "$($_.name)" })) -join ', '))" }
    }
}
if ($runAs.Count) { Add-Finding -Key 'automation-runas' 'MEDIUM' 'Service identities' "$($runAs.Count) Automation account(s) hold an AzureServicePrincipal (Run As style) connection asset; Microsoft retired the Run As feature on 30 September 2023, and a hand-made one carries the same risk: $($runAs -join '; '). Its app registration can still carry Contributor on the subscription; move the runbooks to a managed identity, then delete that app registration and its role assignment." 'azure' }

# --- API connections that sign in as a named account (arm-*-apiconnections.json) ---
$apiNamed = @(); $apiDormant = @()
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-apiconnections.json')) {
    $x = Load $f.Name
    foreach ($c in @($x | Where-Object { $_ -and "$($_.authenticatedUser)" -match '@' })) {
        $apiNamed += "$($c.name) ($($c.api)) as $($c.authenticatedUser)"
        if ($dormantSet.ContainsKey("$($c.authenticatedUser)".ToLower())) { $apiDormant += "$($c.name) as $($c.authenticatedUser)" }
    }
}
if ($apiDormant.Count) { Add-Finding -Key 'apiconn-dormant' 'MEDIUM' 'Service identities' "$($apiDormant.Count) API connection(s) sign in as an account with no successful sign-in for 90+ days: $($apiDormant -join '; '). A connection in use keeps its account signing in, so these are probably unused or broken: check each one, then remove it or move it to a dedicated service account." 'azure' }
if ($apiNamed.Count) { Add-Finding -Key 'apiconn-named' 'LOW' 'Service identities' "$($apiNamed.Count) API connection(s) sign in as a named account: $((@($apiNamed) | Select-Object -First 12) -join '; ')$(if($apiNamed.Count -gt 12){" (+$($apiNamed.Count - 12) more)"}). Each runs with that person's access and can stop working when they leave or change their password; use a dedicated service account (or a managed identity where the connector supports one)." 'azure' }

# --- One inventory line for every allowlist read above ---
if ($allowByKind.Count) {
    $parts = @($allowByKind.Keys | ForEach-Object { "$($allowByKind[$_]) $($_)(s)" })
    Add-Finding -Key 'allowlist-inventory' 'LOW' 'Network' "Allowed-IP inventory: $allowRules rule(s) across $($parts -join ', '). Review every range for stale or over-broad entries (raw rules in output/: arm-*-sql.json and arm-*-synapse.json _firewallRules, arm-*-storage.json, arm-*-nsgs.json, arm-*-appservice.json, arm-*-logicapps.json, dvplus-*-ipfirewall.json)." $(if($allowPlanes.ContainsKey('dataverse')){'mixed'}else{'azure'})
}
if ($allowUnknown.Count) {
    $unknownWhy = if ($null -eq $namedRanges) { 'and Conditional Access named locations were not read to compare them with' } elseif (-not $namedRanges.Count) { 'and no Conditional Access IP named location exists to compare them with' } else { "that is in none of your $($namedRanges.Count) Conditional Access IP range(s)" }
    $clientNote = if (@($allowUnknown | Where-Object { $_ -match "rule 'ClientIP" }).Count) { " ClientIPAddress_<date> is the usual name when someone adds their own current address in one click (Azure portal or SQL Server Management Studio), so such a rule was one person's connection at that moment." } else { '' }
    Add-Finding -Key 'allowlist-unknown-ip' 'LOW' 'Network' "$($allowUnknown.Count) allow-list entr(ies) name a public IP address or small range $($unknownWhy): $((@($allowUnknown) | Select-Object -First 15) -join '; ')$(if($allowUnknown.Count -gt 15){" (+$($allowUnknown.Count - 15) more)"}). Find out whose address each one is and remove the ones nobody can explain.$clientNote" $(if($allowPlanes.ContainsKey('dataverse')){'mixed'}else{'azure'})
}

# --- Azure RBAC: Owner sprawl, and service principals holding Owner ---
# Direct Owner / User Access Administrator grants at subscription scope (management-group
# inheritance excluded). Microsoft Defender for Cloud recommends at most 3 owners per
# subscription. A service principal holding either role turns one leaked app secret into full
# control of the subscription, so those are named.
$roleOwner = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; $roleUaa = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
$spNames = @{}; $spAllR = Load 'servicePrincipals.json'; foreach ($sp in @($spAllR)) { if ($sp -and $sp.id) { $spNames["$($sp.id)"] = "$($sp.displayName)" } }
$upnById = @{}; foreach ($u in @($ua)) { if ($u -and $u.id) { $upnById["$($u.id)"] = "$($u.userPrincipalName)" } }
$mgPriv = @(); $mgWriters = @(); $mgGranters = @(); $mgSeen = @{}
# One "who can change network rules" finding: $label is [subscription] or the management-group line.
function Add-NetworkWriters([string]$Label, $Writers, $Granters, [bool]$CustomUsed, [string]$Where, [string]$Note = '') {
    $Writers  = @($Writers  | Group-Object { "$($_.who)|$($_.role)|$($_.at)" } | ForEach-Object { $_.Group[0] })
    $Granters = @($Granters | Group-Object { "$($_.who)|$($_.role)|$($_.at)" } | ForEach-Object { $_.Group[0] })
    if (-not $Writers.Count) { return }
    $fmtW = { param($list, $max) $l = @($list | ForEach-Object { "$($_.who) ($($_.role), $($_.at))" }); "$((@($l) | Select-Object -First $max) -join '; ')$(if($l.Count -gt $max){" (+$($l.Count - $max) more)"})" }
    $parts = @()
    $wu = @($Writers | Where-Object { $_.type -eq 'User' }); if ($wu.Count) { $parts += "people: $(& $fmtW $wu 15)" }
    $wg = @($Writers | Where-Object { $_.type -eq 'Group' }); if ($wg.Count) { $parts += "groups (everyone in them can too): $(& $fmtW $wg 8)" }
    $ws = @($Writers | Where-Object { $_.type -eq 'ServicePrincipal' }); if ($ws.Count) { $parts += "apps and managed identities: $(& $fmtW $ws 10)" }
    $wo = @($Writers | Where-Object { $_.type -notin 'User', 'Group', 'ServicePrincipal' }); if ($wo.Count) { $parts += "other: $(& $fmtW $wo 5)" }
    $userWide = @($Writers | Where-Object { $_.type -eq 'User' -and ($_.at -eq 'subscription' -or $_.at -eq 'root' -or $_.at -like 'management group*') }).Count
    $nWho = @($Writers | ForEach-Object { $_.who } | Select-Object -Unique).Count
    $grantText = if ($Granters.Count) { " Also $(@($Granters | ForEach-Object { $_.who } | Select-Object -Unique).Count) with User Access Administrator or Role Based Access Control Administrator, who can give themselves that access: $(& $fmtW $Granters 8)." } else { '' }
    $wideText = if ($userWide) { " $userWide of these grants give individual people this access across the whole $(if($Label -like '`[management*'){'management group'}else{'subscription'}); give it through a group, at the smallest scope that works, unless a setup needs a named user (the Lifecycle Services Azure connector can)." } else { '' }
    Add-Finding -Key 'azure-network-writers' $(if ($userWide) { 'MEDIUM' } else { 'LOW' }) 'Azure access' "$Label $nWho account(s) can change network rules $Where (open a port, add an IP address) through Owner, Contributor, Network Contributor$(if($CustomUsed){' or another role that can write network rules'}): $($parts -join '. ').$grantText$wideText$Note" 'azure'
}
foreach ($f in @(Get-ChildItem $out -Filter 'arm-*-rbac.json')) {
    $sub = $f.BaseName -replace '^arm-' -replace '-rbac$'
    $ra = Load $f.Name
    if ($null -eq $ra) { continue }
    $atSub  = @($ra | Where-Object { $_ -and $_.properties -and "$($_.properties.scope)" -match '^/subscriptions/[^/]+/?$' })
    $owners = @($atSub | Where-Object { "$($_.properties.roleDefinitionId)".Split('/')[-1] -eq $roleOwner })
    $uaa    = @($atSub | Where-Object { "$($_.properties.roleDefinitionId)".Split('/')[-1] -eq $roleUaa })
    if ($owners.Count -gt 3) {
        $byType = (@($owners | Group-Object { "$($_.properties.principalType)" } | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" })) -join ', '
        Add-Finding -Key 'owner-sprawl' 'MEDIUM' 'Owner sprawl' "[$sub] $($owners.Count) Owner assignment(s) at subscription scope ($byType)$(if($uaa.Count){" plus $($uaa.Count) User Access Administrator"}); Microsoft recommends at most 3 owners. Move the rest to resource-group scope, or to eligible (just-in-time) assignments if you have Entra ID P2; apps and managed identities cannot be eligible." 'azure'
    }
    $spPriv = @(@($owners) + @($uaa) | Where-Object { "$($_.properties.principalType)" -eq 'ServicePrincipal' })
    if ($spPriv.Count -gt 0) {
        if ($null -eq $spNames) {
            $spNames = @{}
            $spAll = Load 'servicePrincipals.json'
            foreach ($sp in @($spAll)) { if ($sp -and $sp.id) { $spNames["$($sp.id)"] = "$($sp.displayName)" } }
        }
        $who = @($spPriv | ForEach-Object { $pid0 = "$($_.properties.principalId)"; if ($spNames[$pid0]) { $spNames[$pid0] } else { $pid0 } } | Select-Object -Unique)
        Add-Finding -Key 'sp-owner-subscription' 'HIGH' 'Service identities' "[$sub] $($who.Count) service principal(s) hold Owner or User Access Administrator at subscription scope: $($who -join ', '). Compromise of any of them (a leaked secret or certificate, or code running as a managed identity) is full control of the subscription." 'azure'
    }
    # Who can change network rules here (open a port, add an IP address): Owner, Contributor, Network
    # Contributor or a custom role that can write NSG rules, at any scope inside this subscription or
    # inherited from above. User Access Administrator and Role Based Access Control Administrator can
    # grant themselves one of those, so they are named too.
    $customNet = @{}; $defsRead = @{}
    $crAll = Load "arm-$sub-roledefs.json"
    foreach ($cr in @($crAll | Where-Object { $_ -and -not $_.error -and $_.properties })) {
        $defsRead["$($cr.name)".ToLower()] = $true
        if (Test-RoleGrantsNetworkWrite $cr) { $customNet["$($cr.name)".ToLower()] = "$($cr.properties.roleName)$(if ("$($cr.properties.type)" -eq 'CustomRole') { ' (custom role)' })" }
    }
    $writers = @(); $granters = @(); $unreadN = 0
    foreach ($a in @($ra | Where-Object { $_ -and $_.properties })) {
        $rid = "$($a.properties.roleDefinitionId)".Split('/')[-1].ToLower()
        $rname = if ($script:NetworkWriteRoles.ContainsKey($rid)) { $script:NetworkWriteRoles[$rid] } elseif ($customNet.ContainsKey($rid)) { "$($customNet[$rid])" } else { $null }
        $gname = if ($script:RoleGrantRoles.ContainsKey($rid)) { $script:RoleGrantRoles[$rid] } else { $null }
        if (-not $rname -and -not $gname) {
            # A role whose definition was not read could still write network rules: counted, not guessed.
            if (-not $defsRead.ContainsKey($rid) -and $rid -ne 'acdd72a7-3385-48ef-bd42-f606fba81ae7') { $unreadN++ }
            continue
        }
        $scp = "$($a.properties.scope)"
        $at = if ($scp -match '^/subscriptions/[^/]+/?$') { 'subscription' } elseif ($scp -match '/resourceGroups/([^/]+)/?$') { "resource group $($Matches[1])" } elseif ($scp -match '/resourceGroups/' -and $scp -match '/providers/(.+)$') { "resource $(($Matches[1] -split '/')[-1])" } elseif ($scp -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)') { "management group $($Matches[1])" } elseif ($scp -eq '/') { 'root' } else { $scp }
        $ptype = "$($a.properties.principalType)"; $pidv = "$($a.properties.principalId)"
        $who = switch ($ptype) {
            'User'             { if ($upnById[$pidv]) { $upnById[$pidv] } else { "user $pidv" } }
            'ServicePrincipal' { if ($spNames[$pidv]) { "$($spNames[$pidv])$(if ($spNames[$pidv] -like 'Dynamics Deployment Services*') { ' (the Lifecycle Services deployment app, which Microsoft says needs Contributor)' })" } else { "app $pidv" } }
            'Group'            { "group $pidv" }
            default            { "$ptype $pidv" }
        }
        $cond = if ("$($a.properties.condition)") { ' (limited by a condition)' } else { '' }
        $entry = [pscustomobject]@{ type = $ptype; who = $who; role = "$(if ($rname) { $rname } else { $gname })$cond"; at = $at }
        # A grant at a management group or the root is inherited by every subscription below it:
        # listed once, after this loop, instead of once per subscription.
        if ($at -eq 'root' -or $at -like 'management group*') {
            $aid = "$($a.id)"; if ($mgSeen.ContainsKey($aid)) { continue }; $mgSeen[$aid] = $true
            if ($rname) { $script:mgWriters += $entry } else { $script:mgGranters += $entry }
            continue
        }
        if ($rname) { $writers += $entry } else { $granters += $entry }
    }
    Add-NetworkWriters "[$sub]" $writers $granters ($customNet.Count -gt 0) 'here' $(if ($unreadN) { " $unreadN role assignment(s) use a role whose definition was not read (arm-$sub-roledefs.json), so their holders are not listed." } else { '' })
    $script:mgPriv += @($ra | Where-Object { $_ -and $_.properties -and ("$($_.properties.scope)" -match '^/providers/Microsoft\.Management/managementGroups/' -or "$($_.properties.scope)" -eq '/') -and @($roleOwner, $roleUaa) -contains "$($_.properties.roleDefinitionId)".Split('/')[-1] })
}
# Owner / UAA granted at a management group or the root ('/') is inherited by every subscription
# below it, so it is reported once here (deduplicated) instead of once per subscription.
$mgSp = @($mgPriv | Where-Object { "$($_.properties.principalType)" -eq 'ServicePrincipal' } | Group-Object { "$($_.id)" } | ForEach-Object { $_.Group[0] })
if ($mgSp.Count) {
    if ($null -eq $spNames) { $spNames = @{}; $spAll3 = Load 'servicePrincipals.json'; foreach ($sp in @($spAll3)) { if ($sp -and $sp.id) { $spNames["$($sp.id)"] = "$($sp.displayName)" } } }
    $who = @($mgSp | ForEach-Object { $pid0 = "$($_.properties.principalId)"; if ($spNames[$pid0]) { $spNames[$pid0] } else { $pid0 } } | Select-Object -Unique)
    Add-Finding -Key 'sp-owner-mg' 'HIGH' 'Service identities' "$($who.Count) service principal(s) hold Owner or User Access Administrator at management-group or root scope, inherited by every subscription below: $($who -join ', ')." 'azure'
}
Add-NetworkWriters '[management groups]' $mgWriters $mgGranters (@($mgWriters | Where-Object { "$($_.role)" -notmatch '^(Owner|Contributor|Network Contributor)( \(|$)' }).Count -gt 0) 'in every subscription below them'

# --- Output ---
$order = @{ HIGH=0; MEDIUM=1; LOW=2 }
$sorted = $findings | Sort-Object { $order[$_.Severity] }, Area
Write-Host ""
Write-Host "==================== FINDINGS ($($findings.Count)) ====================" -ForegroundColor Green
# Files a -Skip switch (or a narrowed scope) left from an earlier run are still read: say so here
# too, because this table and FINDINGS-summary.json are read without the report's header.
$staleNow = @(Get-StaleEvidence $out $scope)
if ($staleNow.Count) { Write-Host "Note: $($staleNow.Count) evidence file(s) come from an earlier run (a -Skip switch keeps a plane's files); findings built from them describe that earlier state. The report header names them." -ForegroundColor Yellow }
$sorted | Format-Table Severity, Area, Finding -AutoSize -Wrap
Save-Json $sorted 'FINDINGS-summary.json' | Out-Null
Write-Host (Get-ScopeBanner $scope) -ForegroundColor Yellow
Write-Host "Saved: output/FINDINGS-summary.json" -ForegroundColor Green
