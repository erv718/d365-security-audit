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
        Write-Warning "App token for $Resource failed: $(Get-ErrorText $_)"
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
    $dir = Get-OutDir
    $path = Join-Path $dir $Name
    # -InputObject (not pipeline) so an empty array serialises to "[]" instead of nothing.
    ConvertTo-Json -Depth 12 -InputObject $Data | Out-File -Encoding utf8 $path
    # A pull writes <name>.json OR <name>-ERROR.json. The other one, left by an earlier run,
    # would be read as this run's evidence, so it goes.
    $sibling = if ($Name -like '*-ERROR.json') { Join-Path $dir ($Name -replace '-ERROR\.json$', '.json') } else { Join-Path $dir ($Name -replace '\.json$', '-ERROR.json') }
    if ($sibling -ne $path -and (Test-Path $sibling)) { Remove-Item $sibling -Force -ErrorAction SilentlyContinue }
    return $path
}

# Settings that may only come from .env, never from the process environment: the AI analysis
# switch and its endpoint, so a stray variable on a build agent can never send findings anywhere.
function Get-DotEnvValue {
    param([string]$Key, [string]$Default = '')
    if ($script:Conf.ContainsKey($Key) -and $script:Conf[$Key]) { return $script:Conf[$Key] }
    return $Default
}

# File-name-safe subscription names. Azure allows two subscriptions with the same display name
# (every pay-as-you-go one starts as 'Pay-As-You-Go'), so a repeat gets the first 8 characters of
# its id appended. Built from the full visible list, in id order, so every Azure script agrees.
function Get-SubscriptionSafeNames($allSubs) {
    $names = @{}; $used = @{}
    foreach ($s in @($allSubs | Where-Object { $_ } | Sort-Object { "$($_.subscriptionId)" })) {
        $safe = ("$($s.displayName)" -replace '[^A-Za-z0-9]', '_')
        if (-not $safe) { $safe = 'subscription' }
        if ($used.ContainsKey($safe.ToLower())) { $safe = "$safe-$("$($s.subscriptionId)".PadRight(8).Substring(0, 8).Trim())" }
        $used[$safe.ToLower()] = 1
        $names["$($s.subscriptionId)"] = $safe
    }
    return $names
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
$script:ScopeReaders          = @('sql', 'synapse', 'keyvault', 'nsg', 'loganalytics', 'logicapps', 'storage', 'vm', 'appservice', 'automation', 'apiconnections')   # per-resource readers: scopeable by group, type and name
$script:ScopeSubscriptionWide = @('rbac', 'defender', 'diagnostics', 'inventory')                     # always run for every selected subscription

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
        resolvedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [cultureinfo]::InvariantCulture)   # parsed back as invariant (Get-StaleEvidence)
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
    if (Test-Path -LiteralPath $p) {
        try { $o = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json; if ($o -and $o.version) { return $o } }
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

# The setup check marks each resolved environment reachable or not (WhoAmI). An environment it
# could not reach is skipped by both Dataverse sweeps; $null (no setup check ran) = try it.
# Merge-ScopeResolved keeps those marks when a sweep rewrites the resolved list.
function Merge-ScopeResolved($existing, $fresh) {
    $marks = @{}
    foreach ($re in @($existing)) { if ($re -and $re.url -and ($re.PSObject.Properties.Name -contains 'reachable')) { $marks["$($re.url)".TrimEnd('/').ToLower()] = $re } }
    $outList = @()
    foreach ($n in @($fresh)) {
        if (-not $n) { continue }
        $k = "$($n.url)".TrimEnd('/').ToLower()
        if ($marks.ContainsKey($k)) { Set-ScopeField $n 'reachable' $marks[$k].reachable; Set-ScopeField $n 'reason' "$($marks[$k].reason)" }
        $outList += $n
    }
    return ,$outList
}
function Get-ScopeEnvReachability($scope, [string]$url) {
    $u = "$url".TrimEnd('/')
    foreach ($re in @($scope.powerPlatform.resolved)) {
        if ($re -and "$($re.url)".TrimEnd('/') -eq $u -and ($re.PSObject.Properties.Name -contains 'reachable') -and $re.reachable -eq $false) {
            return [pscustomobject]@{ reachable = $false; reason = "$($re.reason)" }
        }
    }
    return [pscustomobject]@{ reachable = $true; reason = '' }
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
    # 'n of m' only when environments were discovered; 0 means the catalog could not be read.
    if ($null -ne $pp.discoveredEnvironments -and [int]$pp.discoveredEnvironments -gt 0) { $text = "$($res.Count) of $($pp.discoveredEnvironments) environment(s)" }
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
        # A row built from several planes (Graph, Azure, Dataverse) names every narrowed one.
        'mixed'     {
            $parts = @()
            if (Test-ScopeAzureSelected $scope) { $parts += "Azure $(Get-ScopeAzureText $scope)" }
            if (@(Get-ScopeItems $scope.powerPlatform.environments).Count -gt 0) { $parts += "Dataverse $(Get-ScopeDataverseText $scope)" }
            if ($parts.Count) { return "scoped: $($parts -join '; '); identity tenant-wide" }
            return 'tenant-wide'
        }
        default     { return 'tenant-wide' }
    }
}

# ---------------------------------------------------------------------------------------------
# Dataverse reads: every query the two Dataverse sweeps send, in one place, so the setup check
# probes exactly what the sweeps will ask for. Tables = the security-role rows that need Read
# (Organization level). A query that $expands into a second table needs Read on both, or
# Dataverse rejects the whole query (solutions -> Publisher, users -> Security Role).
# Probe = the same read cut to one row, set only where appending $top=1 would not work.
# ---------------------------------------------------------------------------------------------
$script:DvReads = [ordered]@{
    org           = @{ File = 'org';              Label = 'org settings';            Tables = 'Organization';           Path = 'organizations?$select=name,isauditenabled,isuseraccessauditenabled,auditretentionperiodv2' }
    orginfo       = @{ File = 'orginfo';          Label = 'environment type';        Tables = '';                       Path = "RetrieveCurrentOrganization(AccessType=@p1)?@p1=Microsoft.Dynamics.CRM.EndpointAccessType'Default'"; Probe = "RetrieveCurrentOrganization(AccessType=@p1)?@p1=Microsoft.Dynamics.CRM.EndpointAccessType'Default'" }
    entities      = @{ File = 'entities';         Label = 'table audit flags';       Tables = 'Entity (Customization group)'; Path = 'EntityDefinitions?$select=LogicalName,IsAuditEnabled,IsCustomEntity'; Probe = "EntityDefinitions(LogicalName='account')?`$select=LogicalName,IsAuditEnabled,IsCustomEntity" }
    roles         = @{ File = 'roles';            Label = 'security roles';          Tables = 'Security Role';          Path = 'roles?$select=name,ismanaged,iscustomizable,roleid' }
    solutions     = @{ File = 'solutions';        Label = 'solutions';               Tables = 'Solution, Publisher';    Path = 'solutions?$select=uniquename,friendlyname,version,ismanaged,isvisible&$expand=publisherid($select=friendlyname)' }
    fieldsec      = @{ File = 'fieldsec';         Label = 'field security profiles'; Tables = 'Field Security Profile'; Path = 'fieldsecurityprofiles?$select=name' }
    users         = @{ File = 'users';            Label = 'users and their roles';   Tables = 'User, Security Role';    Path = 'systemusers?$select=fullname,domainname,isdisabled,accessmode,applicationid,azureactivedirectoryobjectid&$filter=isdisabled eq false&$expand=systemuserroles_association($select=name,roleid)' }
    orgplus       = @{ File = 'org-settings';     Label = 'org security settings';   Tables = 'Organization';           Path = 'organizations?$select=name,isauditenabled,isuseraccessauditenabled,isreadauditenabled,auditretentionperiodv2,plugintracelogsetting' }
    emailprofiles = @{ File = 'emailprofiles';    Label = 'email server profiles';   Tables = 'Email Server Profile';   Path = 'emailserverprofiles?$select=name,servertype,statecode' }
    queues        = @{ File = 'queues';           Label = 'queues';                  Tables = 'Queue';                  Path = 'queues?$select=name&$top=5&$count=true' }
    mailboxes     = @{ File = 'mailboxes';        Label = 'mailboxes';               Tables = 'Mailbox';                Path = 'mailboxes?$select=name,statecode&$top=5&$count=true' }
    fieldperms    = @{ File = 'fieldpermissions'; Label = 'field permissions';       Tables = 'Field Security Profile'; Path = 'fieldpermissions?$select=attributelogicalname,fieldsecurityprofileid' }
    mailsync      = @{ File = 'mailflow';         Label = 'mailboxes syncing';       Tables = 'Mailbox';                Path = 'mailboxes?$select=mailboxid&$filter=statecode eq 0 and emailrouteraccessapproval eq 1 and (incomingemaildeliverymethod eq 2 or outgoingemaildeliverymethod eq 2)&$top=1&$count=true' }
    queuemail     = @{ File = 'mailflow';         Label = 'queues receiving email';  Tables = 'Queue';                  Path = 'queues?$select=queueid&$filter=statecode eq 0 and emailaddress ne null and incomingemaildeliverymethod eq 2&$top=1&$count=true' }
    ipfirewall    = @{ File = 'ipfirewall';       Label = 'IP firewall settings';    Tables = 'Organization';           Path = 'organizations?$select=name,enableipbasedfirewallrule,enableipbasedfirewallruleinauditmode,allowediprangeforfirewall,allowedservicetagsforfirewall,allowapplicationuseraccess,allowmicrosofttrustedservicetags' }
}
function Get-DvProbePath($read) {
    if ($read.Probe) { return $read.Probe }
    if ($read.Path -match '\$top=') { return $read.Path }
    $sep = if ($read.Path.Contains('?')) { '&' } else { '?' }
    return "$($read.Path)$sep`$top=1"
}

# Dataverse names a missing privilege in its 403 body, in one of two wordings: "... is missing
# prvReadPublisher privilege (Id=...) on OTC=7101 for entity 'publisher'", or "SecLib::CheckPrivilege
# failed. ... PrivilegeName: prvReadEntity, PrivilegeId: ..., Required Depth: Basic". Returns the
# table as the role editor shows it, or $null when the error is not a missing privilege. Entity and
# Field sit in the editor's Customization group, not with the other tables (Microsoft's privilege
# table: https://learn.microsoft.com/en-us/troubleshoot/power-platform/dataverse/d365-app-outlook/privilege-error-occurs-when-using-dynamics-365-app-for-outlook).
$script:DvPrivTables = @{
    prvReadOrganization = 'Organization'; prvReadSolution = 'Solution'; prvReadPublisher = 'Publisher'
    prvReadRole = 'Security Role'; prvReadUser = 'User'; prvReadFieldSecurityProfile = 'Field Security Profile'
    prvReadFieldPermission = 'Field Permission'; prvReadEmailServerProfile = 'Email Server Profile'
    prvReadMailbox = 'Mailbox'; prvReadQueue = 'Queue'; prvReadEntity = 'Entity (Customization group)'; prvReadAttribute = 'Field (Customization group)'
    prvReadTeam = 'Team'; prvReadBusinessUnit = 'Business Unit'
}
function Get-DvMissingTable([string]$ErrorText) {
    if ($ErrorText -match 'missing (prv\w+) privilege') { $priv = $Matches[1] }
    elseif ($ErrorText -match 'PrivilegeName:\s*(prv\w+)') { $priv = $Matches[1] }
    else { return $null }
    if ($script:DvPrivTables.ContainsKey($priv)) { return $script:DvPrivTables[$priv] }
    if ($ErrorText -match "for entity '([^']+)'") { return "$($Matches[1]) ($priv)" }
    return $priv
}

# Environment type (Production, Sandbox, ...). The Power Platform admin inventory has it; without
# that registration each Dataverse environment reports its own (RetrieveCurrentOrganization >
# OrganizationType, saved as dv-<env>-orginfo.json). Microsoft's enum: Customer = the primary
# organization and Secondary = production instances; CustomerTest and CustomerFreeTest = sandbox.
function ConvertTo-EnvSku($orgType) {
    switch ("$orgType") {
        { $_ -in 'Customer', 'Secondary', '0', '4' }                   { return 'Production' }
        { $_ -in 'CustomerTest', 'CustomerFreeTest', '5', '6' }        { return 'Sandbox' }
        { $_ -in 'Default', '12' }                                      { return 'Default' }
        { $_ -in 'Developer', '13' }                                    { return 'Developer' }
        { $_ -in 'Trial', 'TestDrive', 'EmailTrial', '9', '11', '14' } { return 'Trial' }
        { $_ -in 'Teams', '15' }                                        { return 'Teams' }
    }
    return $null
}
# Type per environment, keyed by the first label of its URL (the name in the dv-<env>-* files):
# @{ sku = @{ env = type }; source = @{ env = 'Power Platform admin API' or 'Dataverse' } }.
# The admin inventory wins; the environment's own report fills in the rest.
function Get-EnvSkuMap([string]$OutDir) {
    $sku = @{}; $src = @{}
    $p = Join-Path $OutDir 'pp-environments.json'
    if (Test-Path $p) {
        try {
            $all = Get-Content $p -Raw | ConvertFrom-Json
            foreach ($e in @($all)) {
                if (-not $e -or -not $e.properties -or -not $e.properties.linkedEnvironmentMetadata) { continue }
                $iu = "$($e.properties.linkedEnvironmentMetadata.instanceUrl)"; $t = "$($e.properties.environmentSku)"
                if (-not $iu -or -not $t) { continue }
                try { $k = ([Uri]$iu).Host.Split('.')[0].ToLower(); $sku[$k] = $t; $src[$k] = 'Power Platform admin API' } catch {}
            }
        } catch { Write-Warning "pp-environments.json could not be read for environment types ($($_.Exception.Message))" }
    }
    foreach ($f in @(Get-ChildItem $OutDir -Filter 'dv-*-orginfo.json' -ErrorAction SilentlyContinue)) {
        $k = ($f.BaseName -replace '^dv-' -replace '-orginfo$').ToLower()
        if ($sku.ContainsKey($k)) { continue }
        try {
            $t = ConvertTo-EnvSku (Get-Content $f.FullName -Raw | ConvertFrom-Json).OrganizationType
            if ($t) { $sku[$k] = $t; $src[$k] = 'Dataverse' }
        } catch {}
    }
    return @{ sku = $sku; source = $src }
}

# ---------------------------------------------------------------------------------------------
# IPv4 allowlist grading, shared by every reader that has an allowlist (SQL, Synapse, storage,
# NSG, App Service, Logic Apps, the Dataverse IP firewall). Get-IpRange turns '10.0.0.0/8',
# '1.2.3.4', '1.2.3.4-1.2.3.9', '*' / 'Internet' / 'Any' into @(start, end) as numbers; IPv6 and
# service tags return $null (listed, not graded). Get-IpBreadth: 'internet' for everything,
# 'broad' for wider than a /16 (65,536 addresses), else $null.
# ---------------------------------------------------------------------------------------------
function Get-IpNumber($ip) {
    $o = "$ip".Trim().Split('.')
    if ($o.Count -ne 4) { return $null }
    $n = [double]0
    foreach ($x in $o) { $v = 0; if (-not [int]::TryParse($x, [ref]$v) -or $v -lt 0 -or $v -gt 255) { return $null }; $n = $n * 256 + $v }
    return $n
}
function Get-IpRange([string]$Text) {
    $t = "$Text".Trim()
    if ($t -in '*', 'Any', 'Internet', '0.0.0.0/0') { return ,@([double]0, [double]4294967295) }
    if ($t -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        $a = Get-IpNumber $Matches[1]; $bits = [int]$Matches[2]
        if ($null -eq $a -or $bits -gt 32) { return $null }
        $size = [math]::Pow(2, 32 - $bits); $start = [math]::Floor($a / $size) * $size
        return ,@($start, ($start + $size - 1))
    }
    if ($t -match '^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$') {
        $b2 = $Matches[2]; $a = Get-IpNumber $Matches[1]; $b = Get-IpNumber $b2
        if ($null -eq $a -or $null -eq $b) { return $null }
        return ,@($a, $b)
    }
    $a = Get-IpNumber $t
    if ($null -ne $a) { return ,@($a, $a) }
    return $null
}
function Get-IpBreadth($Range, [switch]$IgnorePrivate) {
    if ($null -eq $Range -or @($Range).Count -ne 2) { return $null }
    if ($Range[0] -eq 0 -and $Range[1] -eq 4294967295) { return 'internet' }
    # -IgnorePrivate (NSG sources): 10/8, 172.16/12, 192.168/16 and 100.64/10 are internal space.
    if ($IgnorePrivate) {
        foreach ($pr in @(@(167772160, 184549375), @(2886729728, 2887778303), @(3232235520, 3232301055), @(1681915904, 1686110207))) {
            if ($Range[0] -ge $pr[0] -and $Range[1] -le $pr[1]) { return $null }
        }
    }
    if (($Range[1] - $Range[0] + 1) -gt 65536) { return 'broad' }
    return $null
}

# Private, loopback, link-local and carrier-grade NAT space, and the 0.0.0.0 "allow Azure services"
# marker: none of them is a public address somebody connects from.
function Test-IpRangeInternal($Range) {
    if ($null -eq $Range -or @($Range).Count -ne 2) { return $false }
    if ($Range[0] -eq 0 -and $Range[1] -eq 0) { return $true }
    foreach ($pr in @(@(167772160, 184549375), @(2886729728, 2887778303), @(3232235520, 3232301055), @(1681915904, 1686110207), @(2130706432, 2147483647), @(2851995648, 2852061183))) {
        if ($Range[0] -ge $pr[0] -and $Range[1] -le $pr[1]) { return $true }
    }
    return $false
}
# The organisation's documented office and VPN ranges: the IPv4 ranges of its Conditional Access IP
# named locations (ca-named-locations.json). $null when that file was not read; an empty list when
# it was read and holds no IP range. Each item is @(start, end, location name). Assign the result
# directly (no @( ) around the call): the leading comma keeps a one-range list a list.
function Get-NamedIpRanges([string]$OutDir) {
    $p = Join-Path $OutDir 'ca-named-locations.json'
    if (-not (Test-Path $p)) { return $null }
    $x = $null
    try { $raw = Get-Content $p -Raw; if ([string]::IsNullOrWhiteSpace($raw)) { return $null }; $x = $raw | ConvertFrom-Json } catch { return $null }
    $ranges = @()
    foreach ($loc in @($x)) {
        if (-not $loc) { continue }
        foreach ($ir in @($loc.ipRanges | Where-Object { $_ })) {
            $rg = Get-IpRange "$($ir.cidrAddress)"
            if ($null -ne $rg) { $ranges += , @($rg[0], $rg[1], "$($loc.displayName)", "$($loc.id)") }
        }
    }
    return , $ranges
}
# Microsoft Dynamics Lifecycle Services (LCS) management addresses. LCS reaches a cloud-hosted
# development VM on WinRM 5986 from these, so a rule that allows them is there by design. Copied
# from the table "Lifecycle Services regional instances and IPs" on Microsoft's page "Secure
# one-box development environments" (learn.microsoft.com/dynamics365/fin-ops-core/dev-itpro/
# dev-tools/secure-developer-vm); update this list when that table changes.
$script:LcsManagementIps = @('104.42.56.231', '20.125.130.131', '20.9.194.46', '4.255.162.39', '4.150.11.25', '13.89.189.103',
    '52.227.70.23', '51.54.161.13', '52.245.167.30', '20.141.241.11', '52.181.207.10', '52.180.251.93', '52.130.253.37', '52.131.87.112',
    '13.95.29.73', '20.223.210.22', '52.136.133.233', '20.199.103.168', '102.133.105.52', '20.87.209.137', '51.107.230.199', '20.199.186.150',
    '51.13.150.248', '20.100.201.172', '20.74.250.171')
# Every address the organisation or Microsoft documents: the Conditional Access IP named locations
# ("named location 'X'") except those a policy uses to block sign-ins (a list of attacker addresses
# is not an office), the organisation's own Azure public IPs, and the LCS management addresses.
# $BlockedIds: named-location ids to leave out; $OwnIps: @{ ip; name } items. Same shape as
# Get-NamedIpRanges; assign the result directly.
function Get-KnownIpRanges($NamedRanges, $BlockedIds, $OwnIps) {
    $known = @()
    if ($null -ne $NamedRanges) {
        foreach ($kr in $NamedRanges) {
            if ($null -eq $kr) { continue }
            if ($BlockedIds -and $BlockedIds.ContainsKey("$($kr[3])")) { continue }
            $known += , @($kr[0], $kr[1], "named location '$($kr[2])'")
        }
    }
    foreach ($o in @($OwnIps | Where-Object { $_ })) { $r = Get-IpRange "$($o.ip)"; if ($null -ne $r) { $known += , @($r[0], $r[1], "your own Azure public IP '$($o.name)'") } }
    foreach ($ip in $script:LcsManagementIps) { $r = Get-IpRange $ip; if ($null -ne $r) { $known += , @($r[0], $r[1], 'Microsoft Lifecycle Services management address, there by design') } }
    return , $known
}
# The name of the named location that holds the whole range, or $null.
function Get-KnownLocationName($Range, $NamedRanges) {
    if ($null -eq $Range -or $null -eq $NamedRanges) { return $null }
    foreach ($kr in $NamedRanges) { if ($Range[0] -ge $kr[0] -and $Range[1] -le $kr[1]) { return "$($kr[2])" } }
    return $null
}

# App permissions that let an app read or change data across the whole tenant (Microsoft Graph) or
# every mailbox (Exchange Online). analyze.ps1 reports the apps that hold them; graph-sweep.ps1
# reads those apps' owners, who can add a secret and act as the app.
$script:RiskyAppRoles = @('Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Directory.ReadWrite.All', 'Application.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'User.ReadWrite.All',
    'Files.ReadWrite.All', 'Sites.FullControl.All', 'full_access_as_app', 'Exchange.ManageAsApp', 'AppRoleAssignment.ReadWrite.All', 'RoleAssignmentSchedule.ReadWrite.Directory',
    'RoleEligibilitySchedule.ReadWrite.Directory', 'UserAuthenticationMethod.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess', 'Domain.ReadWrite.All')

# Azure roles that can change network rules (open a port, add an IP address), by role definition
# id, and the roles that can grant themselves one of those. Custom roles are checked by action.
$script:NetworkWriteRoles = @{ '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'; 'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'; '4d97b98b-1d4f-4787-a291-c67834d212e7' = 'Network Contributor' }
$script:RoleGrantRoles = @{ '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'; 'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator' }
function Test-RoleGrantsNetworkWrite($RoleDef) {
    if ($null -eq $RoleDef -or $null -eq $RoleDef.properties) { return $false }
    foreach ($target in 'Microsoft.Network/networkSecurityGroups/write', 'Microsoft.Network/networkSecurityGroups/securityRules/write') {
        foreach ($perm in @($RoleDef.properties.permissions | Where-Object { $_ })) {
            $allowed = @($perm.actions | Where-Object { $_ -and $target -like "$_" }).Count -gt 0
            $denied  = @($perm.notActions | Where-Object { $_ -and $target -like "$_" }).Count -gt 0
            if ($allowed -and -not $denied) { return $true }
        }
    }
    return $false
}

# The tool's version: the release tag from git when git is installed (for example v1.6.0, or
# v1.6.0-2-g1a2b3c4 between releases), else the commit read from .git directly.
function Get-ToolVersion([string]$RepoRoot) {
    if (-not $RepoRoot) { $RepoRoot = Split-Path $PSScriptRoot -Parent }
    try {
        if ((Test-Path (Join-Path $RepoRoot '.git')) -and (Get-Command git -ErrorAction SilentlyContinue)) {   # this folder's own clone, never an outer repository
            $d = & git -C $RepoRoot describe --tags --always 2>$null
            if ($LASTEXITCODE -eq 0 -and "$d".Trim()) { return "$d".Trim() }
        }
    } catch {}
    $g = Join-Path $RepoRoot '.git'
    if (-not (Test-Path (Join-Path $g 'HEAD'))) { return 'unknown (no .git folder; download or clone the latest release)' }
    try {
        $head = (Get-Content (Join-Path $g 'HEAD') -Raw).Trim()
        $sha = $head
        if ($head -match '^ref:\s*(.+)$') {
            $ref = $Matches[1]
            $refPath = Join-Path $g ($ref -replace '/', [IO.Path]::DirectorySeparatorChar)
            if (Test-Path $refPath) { $sha = (Get-Content $refPath -Raw).Trim() }
            else {
                $packed = Join-Path $g 'packed-refs'
                if (Test-Path $packed) { foreach ($l in Get-Content $packed) { if ($l -match "^([0-9a-f]{40}) $([regex]::Escape($ref))$") { $sha = $Matches[1]; break } } }
            }
        }
        $tags = @()
        $tagDir = Join-Path $g 'refs/tags'
        if (Test-Path $tagDir) { foreach ($tf in Get-ChildItem $tagDir -File) { if ((Get-Content $tf.FullName -Raw).Trim() -eq $sha) { $tags += $tf.Name } } }
        $packed = Join-Path $g 'packed-refs'
        if (Test-Path $packed) { foreach ($l in Get-Content $packed) { if ($l -match "^$sha refs/tags/(.+)$") { $tags += $Matches[1] } } }
        return "$($sha.Substring(0, [Math]::Min(8, $sha.Length)))$(if($tags.Count){" ($(($tags | Select-Object -Unique) -join ', '))"})"
    } catch { return 'unknown' }
}

# Security groups on environments: one rule for the sweep's console line and the report's 1.3/2.4.
# Eligible = backed by Dataverse and not Default, Developer or Teams (Microsoft allows no group on
# Default; a Teams environment is bound to its team automatically). Bound = a group id that is set
# and is not the all-zero GUID the API returns for "none".
function Test-EnvSecurityGroupEligible($e) {
    if ($null -eq $e -or $null -eq $e.properties -or $null -eq $e.properties.linkedEnvironmentMetadata) { return $false }
    return ("$($e.properties.environmentSku)" -notin 'Default', 'Developer', 'Teams')
}
function Test-EnvSecurityGroup($e) {
    if ($null -eq $e -or $null -eq $e.properties) { return $false }
    $sg = "$($e.properties.linkedEnvironmentMetadata.securityGroupId)"
    if (-not $sg) { $sg = "$($e.properties.securityGroupId)" }
    return [bool]($sg -and $sg -ne '00000000-0000-0000-0000-000000000000')
}

# Conditional Access targeting. A policy that requires MFA only protects D365 when it includes all
# users and all apps, or the Dynamics resource apps: Dataverse ('Common Data Service') and Dynamics
# 365 ERP (Finance and Operations). One for a pilot group or a single other app does not.
$script:D365ResourceAppIds = @('00000007-0000-0000-c000-000000000000', '00000015-0000-0000-c000-000000000000')
function Test-CaPolicyCoversD365($p) {
    $c = $p.conditions
    # Limited to risky sign-ins or users, some client apps, some platforms or some locations: the
    # policy does not apply to an ordinary sign-in, so it does not cover everyone.
    if (@(@($c.signInRiskLevels) + @($c.userRiskLevels) | Where-Object { $_ -and "$_" -ne 'none' }).Count) { return $false }
    if ($c.insiderRiskLevels) { return $false }
    $cat = @($c.clientAppTypes | Where-Object { $_ } | ForEach-Object { "$_" })
    if ($cat.Count -and $cat -notcontains 'all' -and -not ($cat -contains 'browser' -and $cat -contains 'mobileAppsAndDesktopClients')) { return $false }
    $plat = @($c.platforms.includePlatforms | Where-Object { $_ } | ForEach-Object { "$_" })
    if ($plat.Count -and $plat -notcontains 'all') { return $false }
    $locs = @($c.locations.includeLocations | Where-Object { $_ } | ForEach-Object { "$_" })
    if ($locs.Count -and $locs -notcontains 'All') { return $false }
    $users = @($p.conditions.users.includeUsers | ForEach-Object { "$_" })
    $apps  = @($p.conditions.applications.includeApplications | ForEach-Object { "$_".ToLower() })
    $excl  = @($p.conditions.applications.excludeApplications | ForEach-Object { "$_".ToLower() })
    $allUsers = ($users -contains 'All')
    # All apps counts only when no Dynamics resource app is excluded from it.
    $d365Apps = (($apps -contains 'all') -and -not @($excl | Where-Object { $script:D365ResourceAppIds -contains $_ }).Count) -or (@($apps | Where-Object { $script:D365ResourceAppIds -contains $_ }).Count -gt 0)
    return [bool]($allUsers -and $d365Apps)
}
# An MFA policy that also accepts another control ("require one of the selected controls", for
# example a compliant device) lets people through without MFA on that path. Microsoft's own
# templates use this; it is counted as MFA and named, not failed.
function Test-CaPolicyMfaOrOther($p) {
    $g = $p.grantControls
    $others = @(@($g.builtInControls) | Where-Object { $_ -and "$_" -ne 'mfa' }).Count + @(@($g.termsOfUse) | Where-Object { $_ }).Count
    return [bool]($others -gt 0 -and "$($g.operator)" -ne 'AND')
}
# Requires a compliant or hybrid-joined device: a device control, and no other way through ("require
# one of the selected controls" with MFA as an alternative lets an unmanaged device in with MFA).
function Test-CaPolicyRequiresDevice($p) {
    $g = $p.grantControls
    $b = @(@($g.builtInControls) | Where-Object { $_ } | ForEach-Object { "$_" })
    if (-not @($b | Where-Object { $_ -in 'compliantDevice', 'domainJoinedDevice' }).Count) { return $false }
    if ("$($g.operator)" -eq 'AND') { return $true }
    $others = @($b | Where-Object { $_ -notin 'compliantDevice', 'domainJoinedDevice' }).Count + @(@($g.termsOfUse) | Where-Object { $_ }).Count + $(if ($null -ne $g.authenticationStrength) { 1 } else { 0 })
    return ($others -eq 0)
}
function Test-CaPolicyHasExclusions($p) {
    $u = $p.conditions.users
    return [bool](@($u.excludeUsers | Where-Object { $_ }).Count -or @($u.excludeGroups | Where-Object { $_ }).Count -or @($u.excludeRoles | Where-Object { $_ }).Count -or $null -ne $u.excludeGuestsOrExternalUsers -or @($p.conditions.applications.excludeApplications | Where-Object { $_ }).Count -or @($p.conditions.locations.excludeLocations | Where-Object { $_ }).Count)
}

# How a Dataverse user record is marked in a list of people: a support user (accessmode 3), a
# non-interactive account (4), a delegated admin (5: how Microsoft's or a partner's support access
# appears) or a B2B guest. '' for an ordinary member of the organisation.
function Get-DvUserKind($u) {
    switch ("$($u.accessmode)") { '3' { return 'support user' } '4' { return 'non-interactive' } '5' { return 'delegated admin' } }
    if ("$($u.domainname)" -like '*#EXT#*') { return 'guest' }
    return ''
}

# Evidence files older than this run's setup check (scope.resolvedAt, 2 minutes of tolerance): a
# -Skip switch, a sweep that stopped early or a narrowed scope leaves them in place, and every
# reader of output/ says so. Returns file names; an unreadable timestamp returns none.
function Get-StaleEvidence([string]$OutDir, $Scope) {
    $stale = @()
    try {
        $runStart = [datetime]::Parse("$($Scope.resolvedAt)", [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)
        foreach ($f in @(Get-ChildItem -LiteralPath $OutDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            if ($f.Name -in 'scope-effective.json', 'assessment-report.json', 'FINDINGS-summary.json') { continue }
            if ($f.LastWriteTimeUtc -lt $runStart.AddMinutes(-2)) { $stale += $f.Name }
        }
    } catch {}
    return $stale   # enumerated: callers wrap the call in @( ) and get a true count, empty included
}

# ARM types that a security rule reads (directly, or as part of another reader). Everything else
# in the resource inventory is reported as inventory only (assessment report, inventory-check.ps1).
$script:CoveredArmTypes = @('microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.synapse/workspaces',
    'microsoft.synapse/workspaces/bigdatapools', 'microsoft.synapse/workspaces/sqlpools', 'microsoft.keyvault/vaults',
    'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses',
    'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts',
    'microsoft.web/sites', 'microsoft.web/connections', 'microsoft.logic/workflows', 'microsoft.automation/automationaccounts',
    'microsoft.automation/automationaccounts/runbooks', 'microsoft.operationalinsights/workspaces')
# Short but unambiguous label for an ARM type: the last segment alone collides (Log Analytics and
# Synapse are both 'workspaces'), so keep the provider and drop only the 'Microsoft.' prefix.
function Get-ArmTypeLabel([string]$Type) {
    $t = "$Type" -replace '^microsoft\.', ''
    if (-not $t) { return 'unknown' }
    return $t
}

# Dataverse stops counting at 5,000 rows ($count=true on a standard table) and says so in the
# totalrecordcountlimitexceeded annotation; such a count is shown as '5000+'. A file from an older
# run has no flag, so a count sitting exactly at the ceiling reads as capped too.
function Format-DvCount($Count, $Capped) {
    if ($null -eq $Count) { return '?' }
    $n = 0
    try { $n = [int]$Count } catch { return "$Count" }
    if ($Capped -eq $true -or ($null -eq $Capped -and $n -ge 5000)) { return "$n+" }
    return "$n"
}
