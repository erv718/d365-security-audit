# _common.ps1 - shared helpers. Dot-source this from the sweep scripts.
# Read-only. No writes to any environment.
#
# Authentication: this tool signs in ONLY as a read-only app registration
# (client credentials from .env). It never performs an interactive sign-in,
# never shows a login prompt or device code, and never uses a person's account.

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Import-DotEnv {
    param([string]$Path)
    if (-not $Path) { $Path = Join-Path (Split-Path $PSScriptRoot -Parent) '.env' }
    $map = @{}
    if (Test-Path $Path) {
        foreach ($line in Get-Content $Path) {
            if ($line -match '^\s*#') { continue }
            if ($line -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.*)$') {
                $map[$Matches[1]] = $Matches[2].Trim().Trim('"').Trim("'")
            }
        }
    }
    return $map
}

$script:Conf = Import-DotEnv

function Get-Conf {
    param([string]$Key, [string]$Default = '')
    if ($script:Conf.ContainsKey($Key) -and $script:Conf[$Key]) { return $script:Conf[$Key] }
    $envVal = [Environment]::GetEnvironmentVariable($Key)
    if ($envVal) { return $envVal }
    return $Default
}

# Get an OAuth token for a resource, as the read-only app registration.
# Requires TENANT_ID + CLIENT_ID + CLIENT_SECRET in .env. There is deliberately no
# fallback: no interactive sign-in, no device codes, no CLI sessions. Returns $null
# (with a warning) if the app is not configured or the token request fails; every
# sweep fails soft on a null token.
function Get-Token {
    param([Parameter(Mandatory)][string]$Resource)
    $tenant = Get-Conf TENANT_ID
    $cid    = Get-Conf CLIENT_ID
    $sec    = Get-Conf CLIENT_SECRET
    if (-not ($tenant -and $cid -and $sec)) {
        Write-Warning "No app registration configured for $Resource. Set TENANT_ID, CLIENT_ID and CLIENT_SECRET in .env (see docs/permissions.md)."
        return $null
    }
    try {
        return (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Body @{
            client_id = $cid; client_secret = $sec
            grant_type = 'client_credentials'; scope = "$Resource/.default"
        }).access_token
    } catch {
        Write-Warning "App token for $Resource failed: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-Paged {
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][hashtable]$Headers, [string]$NextField = '@odata.nextLink')
    $items = @(); $next = $Url
    while ($next) {
        $r = Invoke-RestMethod -Uri $next -Headers $Headers
        if ($r.value) { $items += $r.value }
        $next = $r.$NextField
    }
    # Comma keeps this an array even when empty; a bare empty array collapses to $null
    # on return, which then blows up Save-Json downstream.
    return ,$items
}

# Message for a failed web call: the HTTP status text plus the response body when the
# service sent one. Graph, Dataverse and ARM put the actual reason there (the bad $select
# field, the missing permission, the licence gap); Exception.Message alone only says "403".
# Windows PowerShell exposes the body via ErrorDetails or the response stream, PowerShell 7
# via ErrorDetails only, so both are tried.
function Get-ErrorText {
    param($ErrorRecord)
    $msg = "$($ErrorRecord.Exception.Message)"
    $body = $null
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $body = $ErrorRecord.ErrorDetails.Message
    } elseif ($ErrorRecord.Exception.Response) {
        try {
            $stream = $ErrorRecord.Exception.Response.GetResponseStream()
            if ($stream) { $body = (New-Object IO.StreamReader($stream)).ReadToEnd() }
        } catch {}
    }
    if ($body) {
        $body = ($body -replace '\s+', ' ').Trim()
        if ($body.Length -gt 800) { $body = $body.Substring(0, 800) + '...' }
        return "$msg $body"
    }
    return $msg
}

function Get-OutDir {
    $dir = Join-Path (Split-Path $PSScriptRoot -Parent) 'output'
    New-Item -ItemType Directory -Force $dir | Out-Null
    return $dir
}

# Convert an API date value to a DateTimeOffset, or $null when it cannot be parsed.
# The same JSON date arrives as a string on Windows PowerShell 5.1 and as a DateTime on
# PowerShell 7 (its ConvertFrom-Json auto-converts ISO dates); DateTimeOffset accepts both
# on either edition and never throws on a value it does not recognise.
function ConvertTo-DateSafe($v) {
    if ($null -eq $v -or "$v" -eq '') { return $null }
    try { return [datetimeoffset]$v } catch { return $null }
}

function Save-Json {
    param($Data, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Data) { $Data = @() }   # never crash on an empty/absent result
    $path = Join-Path (Get-OutDir) $Name
    # -InputObject (not pipeline) so an empty array serialises to "[]" instead of nothing.
    ConvertTo-Json -Depth 12 -InputObject $Data | Out-File -Encoding utf8 $path
    return $path
}

# ---------------------------------------------------------------------------------------------
# Scope: which subscriptions, resource groups, resource readers and environments a run covers.
#
# Three layers, highest first: parameters (run-audit.ps1 -Scope, -Subscriptions,
# -ResourceGroups, -Environments, -Types, handed to the scripts as SECAUDIT_* process
# variables), then scope.json (next to .env, or the path in SECAUDIT_SCOPE_FILE), then the
# .env lists AZURE_SUBSCRIPTIONS and DATAVERSE_ENVIRONMENTS. A field set in a higher layer
# replaces that field from the layers below. A field empty everywhere means everything the app
# can discover, which is exactly the pre-scope behaviour. Identity (Graph) evidence is
# tenant-wide by nature and is never filtered.
#
# check-setup.ps1 resolves the selection, adds what the app can actually see, and writes
# output/scope-effective.json. The sweeps and the report read that file, or resolve the
# selection themselves when they run alone. Nothing in this section touches the tenant.
# Helpers return plain arrays; callers wrap results in @( ) (an empty plain return is nothing).
# ---------------------------------------------------------------------------------------------
$script:ScopeReaders          = @('sql', 'synapse', 'keyvault', 'nsg', 'loganalytics', 'logicapps')   # per-resource readers: scopeable by group, type and name
$script:ScopeSubscriptionWide = @('rbac', 'defender', 'diagnostics')                                  # always run for every selected subscription

# Non-null, non-empty items of a value that may be $null, one item or an array.
function Get-ScopeItems($v) { return @($v | Where-Object { $null -ne $_ -and "$_" -ne '' }) }

# A JSON array, a single string or a comma/semicolon list -> trimmed, non-empty, unique strings.
function ConvertTo-ScopeList($value) {
    $items = @()
    foreach ($v in @($value)) {
        if ($null -eq $v) { continue }
        $items += @(("$v" -split '[,;]') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    return @($items | Select-Object -Unique)
}

function Get-ScopeFilePath {
    $p = [Environment]::GetEnvironmentVariable('SECAUDIT_SCOPE_FILE')
    if ($p) { return $p }
    $default = Join-Path (Split-Path $PSScriptRoot -Parent) 'scope.json'
    if (Test-Path $default) { return $default }
    return $null
}

function New-ScopeObject {
    return [ordered]@{
        version = 1
        resolvedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        source = 'none'; sources = @(); scopeFile = $null; scopeFileHash = $null; strict = $false; partial = $false
        azure = [ordered]@{
            subscriptions = @(); resourceGroups = @(); types = @(); resources = [ordered]@{}; unknownTypes = @()
            readers = @($script:ScopeReaders); subscriptionWide = @($script:ScopeSubscriptionWide)
            discoveredSubscriptions = $null; selectedVisible = @(); selectedInvisible = @()
            discoveredResourceGroups = $null; resourceGroupsVisible = @(); resourceGroupsInvisible = @()
        }
        powerPlatform = [ordered]@{ environments = @(); discoveredEnvironments = $null; resolved = @(); unresolved = @() }
        identity = [ordered]@{ scopeable = $false; note = 'Identity evidence (Graph) is tenant-wide by nature and is never filtered.' }
    }
}

# Resolve the selection (no discovery, no network). Throws on an unreadable scope file: auditing
# the whole tenant when the user asked for part of it is the one thing this must never do quietly.
function Get-Scope {
    $s = New-ScopeObject
    $envSubs = @(ConvertTo-ScopeList (Get-Conf AZURE_SUBSCRIPTIONS))
    $envEnvs = @(ConvertTo-ScopeList (Get-Conf DATAVERSE_ENVIRONMENTS))
    if ($envSubs.Count -gt 0) { $s.azure.subscriptions = $envSubs }
    if ($envEnvs.Count -gt 0) { $s.powerPlatform.environments = $envEnvs }
    if ($envSubs.Count -gt 0 -or $envEnvs.Count -gt 0) { $s.sources += '.env'; $s.source = '.env' }

    $path = Get-ScopeFilePath
    if ($path) {
        if (-not (Test-Path $path)) { throw "scope file not found: $path" }
        $file = $null
        try { $file = Get-Content $path -Raw | ConvertFrom-Json } catch { throw "scope file $path is not valid JSON: $($_.Exception.Message)" }
        if ($null -eq $file) { throw "scope file $path is empty" }
        $s.scopeFile = (Resolve-Path $path).Path
        try { $s.scopeFileHash = (Get-FileHash -Algorithm SHA256 -Path $path).Hash.Substring(0, 8).ToLower() } catch {}
        $touched = $false
        if ($file.azure) {
            $v = @(ConvertTo-ScopeList $file.azure.subscriptions);  if ($v.Count -gt 0) { $s.azure.subscriptions = $v; $touched = $true }
            $v = @(ConvertTo-ScopeList $file.azure.resourceGroups); if ($v.Count -gt 0) { $s.azure.resourceGroups = $v; $touched = $true }
            $v = @(ConvertTo-ScopeList $file.azure.types);          if ($v.Count -gt 0) { $s.azure.types = $v; $touched = $true }
            if ($file.azure.resources) {
                foreach ($prop in @($file.azure.resources.PSObject.Properties)) {
                    $names = @(ConvertTo-ScopeList $prop.Value)
                    if ($names.Count -gt 0) { $s.azure.resources[$prop.Name.ToLower()] = $names; $touched = $true }
                }
            }
        }
        if ($file.powerPlatform) {
            $v = @(ConvertTo-ScopeList $file.powerPlatform.environments); if ($v.Count -gt 0) { $s.powerPlatform.environments = $v; $touched = $true }
        }
        $s.sources += 'scope.json'
        if ($touched) { $s.source = 'scope.json' }
    }

    $pSubs = @(ConvertTo-ScopeList ([Environment]::GetEnvironmentVariable('SECAUDIT_SUBSCRIPTIONS')))
    $pRgs  = @(ConvertTo-ScopeList ([Environment]::GetEnvironmentVariable('SECAUDIT_RESOURCE_GROUPS')))
    $pTyp  = @(ConvertTo-ScopeList ([Environment]::GetEnvironmentVariable('SECAUDIT_TYPES')))
    $pEnv  = @(ConvertTo-ScopeList ([Environment]::GetEnvironmentVariable('SECAUDIT_ENVIRONMENTS')))
    if ($pSubs.Count -gt 0) { $s.azure.subscriptions = $pSubs }
    if ($pRgs.Count -gt 0)  { $s.azure.resourceGroups = $pRgs }
    if ($pTyp.Count -gt 0)  { $s.azure.types = $pTyp }
    if ($pEnv.Count -gt 0)  { $s.powerPlatform.environments = $pEnv }
    if (($pSubs.Count + $pRgs.Count + $pTyp.Count + $pEnv.Count) -gt 0) { $s.sources += 'parameters'; $s.source = 'parameters' }
    $s.strict = ([Environment]::GetEnvironmentVariable('SECAUDIT_STRICT_SCOPE') -eq '1')

    $valid = @(); $unknown = @()
    foreach ($t in @($s.azure.types)) { if ($script:ScopeReaders -contains $t) { $valid += $t.ToLower() } else { $unknown += $t } }
    $s.azure.types = @($valid | Select-Object -Unique)
    $s.azure.unknownTypes = $unknown
    if ($unknown.Count -gt 0) {
        Write-Warning "Scope: unknown reader type(s) ignored: $($unknown -join ', '). Valid: $($script:ScopeReaders -join ', '). Subscription-wide readers ($($script:ScopeSubscriptionWide -join ', ')) always run."
    }
    $s.partial = (@($s.azure.subscriptions).Count -gt 0 -or @($s.azure.resourceGroups).Count -gt 0 -or @($s.azure.types).Count -gt 0 -or $s.azure.resources.Count -gt 0 -or @($s.powerPlatform.environments).Count -gt 0)
    return $s
}

# PSCustomObject form (what the JSON file holds), so every consumer reads and updates fields the same way.
function Get-ScopeObject { return ((ConvertTo-Json -Depth 12 -InputObject (Get-Scope)) | ConvertFrom-Json) }
function Get-ScopeEffectivePath { return (Join-Path (Get-OutDir) 'scope-effective.json') }

# The scope resolved for this run (written by check-setup.ps1), or a fresh resolution when a script runs alone.
function Read-ScopeEffective {
    $p = Get-ScopeEffectivePath
    if (Test-Path $p) {
        try { $o = Get-Content $p -Raw | ConvertFrom-Json; if ($o -and $o.version) { return $o } }
        catch { Write-Warning "scope-effective.json could not be read; resolving the scope again ($($_.Exception.Message))" }
    }
    return (Get-ScopeObject)
}
function Save-ScopeEffective($scope) {
    $p = Get-ScopeEffectivePath
    ConvertTo-Json -Depth 12 -InputObject $scope | Out-File -Encoding utf8 $p
    return $p
}
function Set-ScopeField($obj, [string]$name, $value) { $obj | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force }
# Read-modify-write of output/scope-effective.json; the scriptblock receives the object.
function Update-ScopeEffective([scriptblock]$Change) {
    $so = Read-ScopeEffective
    & $Change $so
    Save-ScopeEffective $so | Out-Null
    return $so
}

# Subscriptions: selection by id or display name (case-insensitive); no selection = all visible.
function Select-ScopedSubscriptions($scope, $allSubs) {
    $sel = @(Get-ScopeItems $scope.azure.subscriptions)
    if ($sel.Count -eq 0) { return @($allSubs) }
    $picked = @()
    foreach ($sub in @($allSubs)) { if ($sel -contains "$($sub.subscriptionId)" -or $sel -contains "$($sub.displayName)") { $picked += $sub } }
    return $picked
}
function Get-ScopeInvisibleSubscriptions($scope, $allSubs) {
    $known = @(@($allSubs) | ForEach-Object { "$($_.subscriptionId)"; "$($_.displayName)" })
    return @(@(Get-ScopeItems $scope.azure.subscriptions) | Where-Object { $known -notcontains $_ })
}
# Resource groups: $null = no group selection (subscription-wide list URLs); otherwise the selected
# groups that exist in this subscription. Returns with a leading comma so an empty match stays an
# empty array: assign the result, do not wrap the call in @( ). $groupNames = this subscription's groups.
function Select-ScopedResourceGroups($scope, $groupNames) {
    $sel = @(Get-ScopeItems $scope.azure.resourceGroups)
    if ($sel.Count -eq 0) { return $null }
    $hits = @(@($groupNames) | ForEach-Object { "$_" } | Where-Object { $sel -contains $_ })
    return ,$hits
}
# One list URL per selected group, or the subscription-wide URL.
function Get-ArmListUrls([string]$base, $groups, [string]$providerPath) {
    if ($null -eq $groups) { return @("$base/providers/$providerPath") }
    return @(@($groups) | ForEach-Object { "$base/resourceGroups/$_/providers/$providerPath" })
}
function Test-ScopedReader($scope, [string]$reader) {
    $t = @(Get-ScopeItems $scope.azure.types)
    if ($t.Count -eq 0) { return $true }
    return ($t -contains $reader)
}
# Pinned resource names per reader (scope azure.resources.<reader>); no names = every item.
function Select-ScopedResources($scope, [string]$reader, $items) {
    $list = @(Get-ScopeItems $items)
    $names = @()
    $res = $scope.azure.resources
    if ($res) { try { $names = @(Get-ScopeItems $res.$reader) } catch { $names = @() } }
    if ($names.Count -eq 0) { return $list }
    return @($list | Where-Object { $names -contains "$($_.name)" })
}
function Get-ScopeResourcePins($scope) {
    $n = 0; $res = $scope.azure.resources
    if ($null -eq $res) { return 0 }
    if ($res -is [System.Collections.IDictionary]) { foreach ($k in @($res.Keys)) { $n += @(Get-ScopeItems $res[$k]).Count } }
    else { foreach ($p in @($res.PSObject.Properties)) { $n += @(Get-ScopeItems $p.Value).Count } }
    return $n
}
function Test-ScopeAzureSelected($scope) {
    $a = $scope.azure
    return (@(Get-ScopeItems $a.subscriptions).Count -gt 0 -or @(Get-ScopeItems $a.resourceGroups).Count -gt 0 -or @(Get-ScopeItems $a.types).Count -gt 0 -or (Get-ScopeResourcePins $scope) -gt 0)
}

# The environment list both Dataverse sweeps iterate. A selection (scope.json, -Environments,
# DATAVERSE_ENVIRONMENTS) resolves to instance URLs: a URL as-is; an environment id or display
# name through the environment catalog (output/pp-environments.json, or -Catalog when the caller
# already holds the admin API response). No selection = every discovered Dataverse URL, the
# pre-scope union. Returns environments (selector, url, id, displayName), unresolved, discovered
# (count with a Dataverse URL) and selected (count).
function Resolve-ScopeEnvironments($scope, $Catalog = $null) {
    $out = Get-OutDir
    $cat = @()
    if ($null -ne $Catalog) { $cat = @(Get-ScopeItems $Catalog) }
    else {
        $catPath = Join-Path $out 'pp-environments.json'
        if (Test-Path $catPath) {
            try { $cat = @(Get-ScopeItems (Get-Content $catPath -Raw | ConvertFrom-Json)) }
            catch { Write-Warning "pp-environments.json could not be read for scope resolution ($($_.Exception.Message))" }
        }
    }
    $cat = @($cat | Where-Object { $_.properties })
    $discovered = @()
    if ($null -ne $Catalog) {
        $discovered = @($cat | ForEach-Object { "$($_.properties.linkedEnvironmentMetadata.instanceUrl)".Trim().TrimEnd('/') } | Where-Object { $_ })
    } else {
        $urlPath = Join-Path $out 'pp-environment-urls.json'
        if (Test-Path $urlPath) {
            try { $discovered = @((Get-Content $urlPath -Raw | ConvertFrom-Json) | ForEach-Object { "$_".Trim().TrimEnd('/') } | Where-Object { $_ }) }
            catch { Write-Warning "pp-environment-urls.json could not be read ($($_.Exception.Message))" }
        }
    }
    $sel = @(Get-ScopeItems $scope.powerPlatform.environments)
    $resolved = @(); $unresolved = @()
    if ($sel.Count -eq 0) {
        foreach ($u in $discovered) { $resolved += [pscustomobject]@{ selector = $u; url = $u; id = $null; displayName = $null } }
    } else {
        foreach ($s in $sel) {
            $key = "$s".Trim().TrimEnd('/')
            if ($key -match '^https?://') { $resolved += [pscustomobject]@{ selector = $s; url = $key; id = $null; displayName = $null }; continue }
            $hit = $null
            foreach ($e in $cat) { if ("$($e.name)" -eq $key -or "$($e.properties.displayName)" -eq $key) { $hit = $e; break } }
            $url = $null
            if ($hit) { $url = "$($hit.properties.linkedEnvironmentMetadata.instanceUrl)".Trim().TrimEnd('/') }
            if ($url) { $resolved += [pscustomobject]@{ selector = $s; url = $url; id = "$($hit.name)"; displayName = "$($hit.properties.displayName)" } }
            else { $unresolved += $s }
        }
    }
    $seen = @{}; $unique = @()
    foreach ($r in $resolved) { $k = $r.url.ToLower(); if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; $unique += $r } }
    return [pscustomobject]@{ environments = $unique; unresolved = $unresolved; discovered = $discovered.Count; selected = $sel.Count }
}

# Text pieces shared by check-setup, the report and the findings.
function Get-ScopeAzureText($scope) {
    $a = $scope.azure; $parts = @()
    $sel = @(Get-ScopeItems $a.subscriptions)
    if ($sel.Count -gt 0) {
        $vis = @(Get-ScopeItems $a.selectedVisible); $inv = @(Get-ScopeItems $a.selectedInvisible)
        if ($null -ne $a.discoveredSubscriptions) { $parts += "$($vis.Count) of $($a.discoveredSubscriptions) subscription(s)" } else { $parts += "$($sel.Count) selected subscription(s)" }
        if ($inv.Count -gt 0) { $parts[-1] += " ($($inv.Count) not visible to the app: $($inv -join ', '))" }
    } else { $parts += 'all visible subscriptions' }
    $rg = @(Get-ScopeItems $a.resourceGroups)
    if ($rg.Count -gt 0) {
        $rvis = @(Get-ScopeItems $a.resourceGroupsVisible); $rinv = @(Get-ScopeItems $a.resourceGroupsInvisible)
        if ($null -ne $a.discoveredResourceGroups) { $parts += "$($rvis.Count) of $($a.discoveredResourceGroups) resource group(s)" } else { $parts += "$($rg.Count) selected resource group(s)" }
        if ($rinv.Count -gt 0) { $parts[-1] += " ($($rinv.Count) not found: $($rinv -join ', '))" }
    }
    $t = @(Get-ScopeItems $a.types)
    if ($t.Count -gt 0) { $parts += "readers: $($t -join ', ') (subscription-wide readers $($script:ScopeSubscriptionWide -join ', ') always run)" }
    $pins = Get-ScopeResourcePins $scope
    if ($pins -gt 0) { $parts += "$pins pinned resource name(s)" }
    return ($parts -join ', ')
}
function Get-ScopeDataverseText($scope) {
    $pp = $scope.powerPlatform
    $sel = @(Get-ScopeItems $pp.environments)
    if ($sel.Count -eq 0) { return 'all discovered environments' }
    $res = @(Get-ScopeItems $pp.resolved); $unr = @(Get-ScopeItems $pp.unresolved)
    $text = "$($sel.Count) selected environment(s)"
    if ($null -ne $pp.discoveredEnvironments) { $text = "$($res.Count) of $($pp.discoveredEnvironments) environment(s)" }
    if ($unr.Count -gt 0) { $text += " ($($unr.Count) not resolved: $($unr -join ', '))" }
    return $text
}
function Get-ScopeSourceText($scope) {
    $src = "$($scope.source)"
    if ($scope.scopeFile) { $src += " ($(Split-Path $scope.scopeFile -Leaf)$(if($scope.scopeFileHash){", sha256 $($scope.scopeFileHash)"}))" }
    return $src
}
# One line for the console and the report header.
function Get-ScopeBanner($scope) {
    if (-not $scope.partial) { return 'Scope: FULL. No selection configured: everything the app can read, identity evidence tenant-wide.' }
    return "Scope: PARTIAL. Azure: $(Get-ScopeAzureText $scope). Dataverse: $(Get-ScopeDataverseText $scope). Identity: tenant-wide. Source: $(Get-ScopeSourceText $scope)."
}
# Row tag on a scoped run: which slice of the estate a verdict describes. $null on a full run.
function Get-ScopeTag($scope, [string]$plane) {
    if (-not $scope.partial) { return $null }
    switch ($plane) {
        'azure'     { if (Test-ScopeAzureSelected $scope) { return "scoped: $(Get-ScopeAzureText $scope)" }; return 'all visible subscriptions' }
        'dataverse' { if (@(Get-ScopeItems $scope.powerPlatform.environments).Count -gt 0) { return "scoped: $(Get-ScopeDataverseText $scope)" }; return 'all discovered environments' }
        default     { return 'tenant-wide' }
    }
}
