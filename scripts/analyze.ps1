# analyze.ps1 - read the JSON in ./output and print a plain-language findings summary.
# Pure local processing. No network calls.

. (Join-Path $PSScriptRoot '_common.ps1')
$out = Get-OutDir
function Load($name) { $p = Join-Path $out $name; if (Test-Path $p) { Get-Content $p -Raw | ConvertFrom-Json } }
$today = Get-Date
$findings = @()
function Add-Finding($sev, $area, $text) { $script:findings += [pscustomobject]@{ Severity=$sev; Area=$area; Finding=$text } }

# --- Expired app credentials ---
$apps = Load 'applications.json'
if ($apps) {
    $expired = 0; $soon = 0
    foreach ($a in $apps) {
        foreach ($c in @($a.passwordCredentials) + @($a.keyCredentials)) {
            if (-not $c.endDateTime) { continue }
            $end = [datetime]$c.endDateTime
            if ($end -lt $today) { $expired++ } elseif ($end -lt $today.AddDays(60)) { $soon++ }
        }
    }
    if ($expired) { Add-Finding 'MEDIUM' 'App secrets' "$expired expired app credentials still present (orphaned / never cleaned up)." }
    if ($soon)    { Add-Finding 'LOW' 'App secrets' "$soon app credentials expire within 60 days - renew before outage." }
}

# --- High-privilege Graph app permissions ---
$defs = Load 'appRoleDefinitions-graph.json'; $asn = Load 'appRoleAssignments-graph.json'
if ($defs -and $asn) {
    $risky = 'Mail.Read','Mail.ReadWrite','Mail.Send','Directory.ReadWrite.All','Application.ReadWrite.All','RoleManagement.ReadWrite.Directory','User.ReadWrite.All','Files.ReadWrite.All','Sites.FullControl.All','full_access_as_app'
    $map = @{}; $defs | ForEach-Object { $map[$_.id] = $_.value }
    $hits = @{}
    foreach ($m in $asn) { $rn = $map[$m.appRoleId]; if ($risky -contains $rn) { if(-not $hits[$rn]){$hits[$rn]=@()}; $hits[$rn]+=$m.principalDisplayName } }
    foreach ($r in $hits.Keys) { Add-Finding 'HIGH' 'App access' "$($hits[$r].Count) app(s) hold $r (tenant-wide): $((($hits[$r] | Select-Object -Unique) -join ', '))" }
}

# --- Conditional Access ---
$ca = Load 'ca-policies.json'
if ($ca) {
    $on = @($ca | Where-Object { $_.state -eq 'enabled' })
    $mfaEnforced = @($ca | Where-Object { $_.state -eq 'enabled' -and $_.grantControls.builtInControls -contains 'mfa' })
    Add-Finding $(if($mfaEnforced.Count){'LOW'}else{'HIGH'}) 'Conditional Access' "$($ca.Count) CA policies; $($on.Count) enabled; $($mfaEnforced.Count) enabled policies require MFA."
}

# --- Guests ---
$g = Load 'guest-count.json'
if ($g) { Add-Finding 'MEDIUM' 'Guests' "$($g.guestCount) guest accounts tenant-wide. Confirm access reviews exist." }

# --- Directory roles ---
$dr = Load 'directoryRoles.json'
if ($dr) { $ga = ($dr | Where-Object { $_.role -eq 'Global Administrator' }).memberCount; if ($ga) { Add-Finding $(if($ga -gt 5){'MEDIUM'}else{'LOW'}) 'Admin roles' "$ga Global Administrator(s). Microsoft recommends fewer than 5, all with MFA." } }

# --- Dataverse per environment ---
Get-ChildItem $out -Filter 'dv-*-org.json' | ForEach-Object {
    $envName = ($_.BaseName -replace '^dv-' -replace '-org$')
    $org = (Get-Content $_.FullName -Raw | ConvertFrom-Json) | Select-Object -First 1
    if ($org.isauditenabled -eq $false) { Add-Finding 'HIGH' 'Auditing' "[$envName] Dataverse auditing is OFF - no record of who changes data." }
    $roles = Load "dv-$envName-roles.json"
    if ($roles) { $custom = @($roles | Where-Object { $_.ismanaged -eq $false }).Count; if ($custom -eq 0) { Add-Finding 'MEDIUM' 'Roles' "[$envName] Zero custom security roles - only built-in roles available to assign." } }
}

# --- Azure network ---
Get-ChildItem $out -Filter 'arm-*-sql.json' | ForEach-Object {
    foreach ($srv in (Get-Content $_.FullName -Raw | ConvertFrom-Json)) {
        if ($srv.properties.publicNetworkAccess -eq 'Enabled') { Add-Finding 'HIGH' 'Network' "SQL server '$($srv.name)' has public network access enabled." }
        if (@($srv._firewallRules | Where-Object { $_.properties.startIpAddress -eq '0.0.0.0' -and $_.properties.endIpAddress -eq '0.0.0.0' }).Count) { Add-Finding 'HIGH' 'Network' "SQL server '$($srv.name)' allows all Azure IPs (0.0.0.0)." }
    }
}
Get-ChildItem $out -Filter 'arm-*-nsgs.json' | ForEach-Object {
    foreach ($nsg in (Get-Content $_.FullName -Raw | ConvertFrom-Json)) {
        foreach ($rule in $nsg.properties.securityRules) {
            $p = $rule.properties
            if ($p.access -eq 'Allow' -and $p.direction -eq 'Inbound' -and $p.destinationPortRange -in '3389','22','*' -and $p.sourceAddressPrefix -in '*','0.0.0.0/0','Internet') {
                Add-Finding 'HIGH' 'Network' "NSG '$($nsg.name)' rule '$($rule.name)' opens port $($p.destinationPortRange) to the internet."
            }
        }
    }
}
Get-ChildItem $out -Filter 'arm-*-keyvaults.json' | ForEach-Object {
    foreach ($v in (Get-Content $_.FullName -Raw | ConvertFrom-Json)) {
        if (-not $v.properties.enableRbacAuthorization) { Add-Finding 'MEDIUM' 'Key Vault' "Key vault '$($v.name)' uses legacy access policies (not RBAC)." }
        if ($v.properties.publicNetworkAccess -eq 'Enabled') { Add-Finding 'MEDIUM' 'Key Vault' "Key vault '$($v.name)' allows public network access." }
    }
}

# --- Output ---
$order = @{ HIGH=0; MEDIUM=1; LOW=2 }
$sorted = $findings | Sort-Object { $order[$_.Severity] }, Area
Write-Host ""
Write-Host "==================== FINDINGS ($($findings.Count)) ====================" -ForegroundColor Green
$sorted | Format-Table Severity, Area, Finding -AutoSize -Wrap
Save-Json $sorted 'FINDINGS-summary.json' | Out-Null
Write-Host "Saved: output/FINDINGS-summary.json" -ForegroundColor Green
