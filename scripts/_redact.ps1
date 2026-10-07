# _redact.ps1 - the names in output/ that must not leave the machine, and the function that
# replaces them. Dot-sourced by ai-analysis.ps1 (redacted scope) and share-diagnostics.ps1.
# Local files only; nothing here touches the tenant.
#
# New-RedactionMap reads whatever evidence files exist and returns a dictionary of
# lower-cased name -> placeholder: environments <env-n>, subscriptions <sub-n>, resource
# groups <rg-n>, Azure resources and their rules <res-n>, the organisation's own and
# third-party apps <app-n>, Dataverse application users, custom roles, solutions, profiles and
# email server profiles <name-n>, guest home domains <domain-n>. Protect-Names applies the
# pattern masks first (emails and guest UPNs, IPs, GUIDs, onmicrosoft domains) and then the
# dictionary, longest names first, on word boundaries. Masking is best effort: a name that is
# also an ordinary word, or one the evidence files do not carry, can slip through, so a
# redacted file is still something to read before it is shared.

$script:RedactSkip = @('production', 'sandbox', 'default', 'developer', 'trial', 'teams', 'standard', 'free', 'enabled', 'disabled',
    'owner', 'reader', 'contributor', 'user', 'users', 'system administrator', 'system customizer', 'basic user', 'microsoft', 'graph',
    'azure', 'default solution', 'common data services default solution', 'active', 'basic', 'true', 'false', 'none', 'null',
    'microsoft graph', 'office 365 exchange online', 'windows azure active directory', 'windows', 'linux', 'test', 'dev', 'prod',
    'security', 'admin', 'audit', 'default-allow-rdp', 'default-allow-ssh', 'allow all', 'deny all', 'manual', 'recurrence', 'request',
    'sql', 'web', 'app', 'api', 'vm', 'nsg', 'vnet', 'synapse', 'storage', 'function', 'functions', 'logic', 'office365', 'sharepoint',
    'teams', 'outlook', 'excel', 'onedrive', 'dataverse', 'commondataservice', 'keyvault', 'azureblob', 'azuread', 'approvals', 'shared')
$script:MsTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

function Read-JsonQuiet([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    try { $raw = Get-Content $path -Raw; if ([string]::IsNullOrWhiteSpace($raw)) { return $null }; return ($raw | ConvertFrom-Json) } catch { return $null }
}
function Get-HostLabel([string]$url) {
    try { if ("$url" -match '^https?://') { return ([Uri]"$url").Host.Split('.')[0] } } catch {}
    return $null
}

function New-RedactionMap([string]$OutDir) {
    $map = [ordered]@{}; $counts = @{}
    $add = {
        param([string]$name, [string]$kind)
        $n = "$name".Trim()
        if ($n.Length -lt 3 -or $n -match '^[\d.\s_-]+$') { return }
        # A three-letter word ('sql', 'web') is more likely a word than a name; 'vm1' or 'rg-a' is a name.
        if ($n.Length -eq 3 -and $n -match '^[A-Za-z]+$') { return }
        $k = $n.ToLower()
        if ($map.Contains($k) -or $script:RedactSkip -contains $k) { return }
        if ($k -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return }   # GUIDs are masked by pattern
        $counts[$kind] = 1 + [int]$counts[$kind]
        $map[$k] = "<$kind-$($counts[$kind])>"
    }
    $files = @(Get-ChildItem $OutDir -Filter '*.json' -File -ErrorAction SilentlyContinue)
    $dvAreas  = @('org', 'orginfo', 'entities', 'roles', 'solutions', 'fieldsec', 'users', 'org-settings', 'emailprofiles', 'queues', 'mailboxes', 'fieldpermissions', 'ipfirewall')
    $armAreas = @('rbac', 'sql', 'synapse', 'keyvaults', 'nsgs', 'defender-pricings', 'loganalytics', 'sentinel', 'diagnostic-settings', 'logicapps', 'resources', 'storage', 'vms', 'nics', 'publicips', 'vnets', 'appservice', 'automation', 'apiconnections')
    $dvRx  = "^(dv|dvplus)-(.+)-($(($dvAreas  | ForEach-Object { [regex]::Escape($_) }) -join '|'))(-ERROR)?\.json$"
    $armRx = "^arm-(.+)-($(($armAreas | ForEach-Object { [regex]::Escape($_) }) -join '|'))(-ERROR)?\.json$"

    # Environments and subscriptions first, so their numbering matches the file names.
    $sc = Read-JsonQuiet (Join-Path $OutDir 'scope-effective.json')
    if ($sc -and $sc.scopeFile) { try { & $add (Split-Path "$($sc.scopeFile)" -Leaf) 'name' } catch {} }
    if ($sc -and $sc.powerPlatform) {
        foreach ($r in @($sc.powerPlatform.resolved)) { if ($r -and $r.url) { & $add (Get-HostLabel $r.url) 'env'; if ($r.displayName) { & $add $r.displayName 'env' } } }
        foreach ($s in @($sc.powerPlatform.environments) + @($sc.powerPlatform.unresolved)) { if ("$s" -match '^https?://') { & $add (Get-HostLabel $s) 'env' } else { & $add "$s" 'env' } }
    }
    $pp = Read-JsonQuiet (Join-Path $OutDir 'pp-environments.json')
    foreach ($e in @($pp)) {
        if (-not $e -or -not $e.properties) { continue }
        & $add (Get-HostLabel "$($e.properties.linkedEnvironmentMetadata.instanceUrl)") 'env'
        & $add "$($e.properties.linkedEnvironmentMetadata.domainName)" 'env'
        & $add "$($e.properties.linkedEnvironmentMetadata.uniqueName)" 'env'
        & $add "$($e.properties.displayName)" 'env'
    }
    foreach ($f in $files) {
        if ($f.Name -match $dvRx) { & $add $Matches[2] 'env' }
        elseif ($f.Name -match '^(dv|dvplus)-(.+)-ERROR\.json$') { & $add $Matches[2] 'env' }
        elseif ($f.Name -match $armRx) { $m = $Matches[1]; & $add $m 'sub'; & $add ($m -replace '_', ' ') 'sub' }
    }
    foreach ($s in @(Read-JsonQuiet (Join-Path $OutDir 'arm-subscriptions.json'))) { if ($s -and $s.displayName) { & $add "$($s.displayName)" 'sub'; & $add ("$($s.displayName)" -replace '[^A-Za-z0-9]', '_') 'sub' } }
    if ($sc -and $sc.azure) {
        foreach ($s in @($sc.azure.subscriptions) + @($sc.azure.selectedInvisible)) { & $add "$s" 'sub' }
        foreach ($g in @($sc.azure.resourceGroups) + @($sc.azure.resourceGroupsVisible) + @($sc.azure.resourceGroupsInvisible)) { & $add "$g" 'rg' }
        if ($sc.azure.resources) { foreach ($p in @($sc.azure.resources.PSObject.Properties)) { foreach ($n in @($p.Value)) { & $add "$n" 'res' } } }
    }
    # Azure resources, groups, rules.
    foreach ($f in @($files | Where-Object { $_.Name -like 'arm-*.json' -and $_.Name -notlike '*-ERROR.json' })) {
        $items = @(Read-JsonQuiet $f.FullName | Where-Object { $_ })
        foreach ($x in $items) {
            if ($x.name) { & $add "$($x.name)" 'res' }
            if ($x.resourceGroup) { & $add "$($x.resourceGroup)" 'rg' }
            if ($x.id -and "$($x.id)" -match '/resourceGroups/([^/]+)/') { & $add $Matches[1] 'rg' }
            if ($x.displayName) { & $add "$($x.displayName)" 'res' }
            if ($x.workspace) { & $add "$($x.workspace)" 'res' }
            foreach ($r in @($x.properties.securityRules)) { if ($r -and $r.name) { & $add "$($r.name)" 'res' } }
            foreach ($r in @($x._firewallRules)) { if ($r -and $r.name) { & $add "$($r.name)" 'res' } }
            foreach ($sn in @($x.subnets)) { if ($sn -and $sn.name) { & $add "$($sn.name)" 'res' } }
            foreach ($fn in @($x.functions)) { if ($fn -and $fn.name) { & $add "$($fn.name)" 'res' } }
            if ($x.config) { foreach ($ir in @($x.config.ipSecurityRestrictions)) { if ($ir -and $ir.name) { & $add "$($ir.name)" 'res' } } }
            foreach ($c in @($x.connections)) { if ($c -and $c.name) { & $add "$($c.name)" 'res' } }
            foreach ($rb in @($x.runbooks)) { if ($rb -and $rb.name) { & $add "$($rb.name)" 'res' } }
        }
    }
    # The organisation's own apps and the third-party apps it granted access to.
    foreach ($a in @(Read-JsonQuiet (Join-Path $OutDir 'applications.json'))) { if ($a -and $a.displayName) { & $add "$($a.displayName)" 'app' } }
    foreach ($sp in @(Read-JsonQuiet (Join-Path $OutDir 'servicePrincipals.json'))) {
        if (-not $sp -or -not $sp.displayName) { continue }
        if ($script:MsTenantIds -contains "$($sp.appOwnerOrganizationId)".ToLower()) { continue }
        & $add "$($sp.displayName)" 'app'
    }
    # Dataverse: application users, custom roles, unmanaged solutions, profiles.
    foreach ($f in @($files | Where-Object { $_.Name -match '^dv-.+-users\.json$' })) {
        foreach ($u in @(Read-JsonQuiet $f.FullName | Where-Object { $_ })) { if ($u.applicationid -or -not $u.domainname) { & $add "$($u.fullname)" 'name' } }
    }
    foreach ($f in @($files | Where-Object { $_.Name -match '^dv-.+-roles\.json$' })) {
        foreach ($r in @(Read-JsonQuiet $f.FullName | Where-Object { $_ })) { if ($r.ismanaged -eq $false) { & $add "$($r.name)" 'name' } }
    }
    foreach ($f in @($files | Where-Object { $_.Name -match '^dv-.+-solutions\.json$' })) {
        foreach ($s in @(Read-JsonQuiet $f.FullName | Where-Object { $_ })) { if ($s.ismanaged -eq $false) { & $add "$($s.friendlyname)" 'name'; & $add "$($s.uniquename)" 'name' } }
    }
    foreach ($f in @($files | Where-Object { $_.Name -match '^dv-.+-fieldsec\.json$' -or $_.Name -match '^dvplus-.+-emailprofiles\.json$' })) {
        foreach ($p in @(Read-JsonQuiet $f.FullName | Where-Object { $_ })) { if ($p.name) { & $add "$($p.name)" 'name' } }
    }
    $gd = Read-JsonQuiet (Join-Path $OutDir 'guests-by-domain.json')
    if ($gd) { foreach ($d in @($gd.byDomain)) { if ($d -and $d.domain) { & $add "$($d.domain)" 'domain' } } }
    return $map
}

# Pattern masks, then the dictionary (longest names first).
function Protect-Names([string]$Text, $Map) {
    $t = "$Text"
    if (-not $t) { return $t }
    $t = [regex]::Replace($t, '[^\s''"<>\[\]()]+#EXT#@[A-Za-z0-9.-]+', '<guest>')
    $t = [regex]::Replace($t, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<email>')
    $t = [regex]::Replace($t, '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '<guid>')
    $t = [regex]::Replace($t, '\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/\d{1,2})?\b', '<ip>')
    $t = [regex]::Replace($t, '\b[A-Za-z0-9-]+\.onmicrosoft\.com\b', '<domain>')
    if ($Map -and $Map.Count) {
        foreach ($k in @($Map.Keys | Sort-Object { $_.Length } -Descending)) {
            $t = [regex]::Replace($t, "(?<![A-Za-z0-9_])$([regex]::Escape($k))(?![A-Za-z0-9_])", $Map[$k], 'IgnoreCase')
        }
    }
    return $t
}
