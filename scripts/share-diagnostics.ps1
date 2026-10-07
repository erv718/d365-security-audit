# share-diagnostics.ps1 - writes output/diagnostics-redacted.md: a description of the last run
# that is safe to paste to someone outside this machine (a colleague, a maintainer, an AI chat).
#
#   ./scripts/share-diagnostics.ps1
#
# What goes in: the tool version, PowerShell and OS versions, the scope as counts, the setup
# check and the warnings from output/run-log.txt (written by ./run-audit.ps1 -Log), the list of
# evidence files with sizes and row counts, each *-ERROR.json as HTTP status + error code +
# message, finding counts by severity and area, and the 29-check statuses.
# What never goes in: finding text, evidence text, names of people, apps, servers, environments,
# subscriptions or resource groups, URLs of your environments, IPs, GUIDs, emails, your tenant
# domain, the client secret or any token. Names the tool cannot avoid (file names, warnings) are
# replaced by placeholders such as <env-1>, <sub-1>, <rg-1>, <res-1>, <app-1>, <guid>, <ip>,
# <name>, using the names the evidence files themselves carry (_redact.ps1).
# Local files only: no sign-in, no network call. Review the file before you share it anyway.

. (Join-Path $PSScriptRoot '_common.ps1')
. (Join-Path $PSScriptRoot '_redact.ps1')
$ErrorActionPreference = 'Continue'
$repo = Split-Path $PSScriptRoot -Parent
$out = Get-OutDir
$rmap = New-RedactionMap $out

# --- Redaction -------------------------------------------------------------------------
$dvAreas  = @('org', 'orginfo', 'entities', 'roles', 'solutions', 'fieldsec', 'users', 'org-settings', 'emailprofiles', 'queues', 'mailboxes', 'fieldpermissions', 'ipfirewall')
$armAreas = @('rbac', 'sql', 'synapse', 'keyvaults', 'nsgs', 'defender-pricings', 'loganalytics', 'sentinel', 'diagnostic-settings', 'logicapps', 'resources', 'storage', 'vms', 'nics', 'publicips', 'vnets', 'appservice', 'automation', 'apiconnections')
$dvRx  = "^(dv|dvplus)-(.+)-($(($dvAreas  | ForEach-Object { [regex]::Escape($_) }) -join '|'))(-ERROR)?\.json$"
$armRx = "^arm-(.+)-($(($armAreas | ForEach-Object { [regex]::Escape($_) }) -join '|'))(-ERROR)?\.json$"
function Get-Placeholder([string]$name, [string]$fallback) { $k = "$name".Trim().ToLower(); if ($k -and $rmap.Contains($k)) { return $rmap[$k] }; return $fallback }
function Protect-Host([string]$h) {
    $hl = $h.ToLower()
    if ($hl -match '^([^.]+)\.(api\.)?crm\d*\.dynamics\.com$') { return "$(Get-Placeholder $Matches[1] '<env>').crm.dynamics.com" }
    if ($hl -match '\.(microsoft\.com|microsoftonline\.com|azure\.com|windows\.net|azure\.net|dynamics\.com|powerapps\.com|powerplatform\.com|github\.com)$') { return $h }
    return '<host>'
}
function Protect-Diag([string]$t) {
    if (-not $t) { return $t }
    $t = [regex]::Replace($t, 'https?://([^/\s''"<>)\],;]+)', { param($m) $m.Value.Replace($m.Groups[1].Value, (Protect-Host $m.Groups[1].Value)) })
    $t = [regex]::Replace($t, '/resourceGroups/[^/\s''"]+', '/resourceGroups/<rg>', 'IgnoreCase')
    $t = [regex]::Replace($t, '(/providers/[^/\s''"]+/[^/\s''"]+/)[^/\s''"]+', '$1<name>')
    $t = Protect-Names $t $rmap
    $t = [regex]::Replace($t, "'[^'\r\n]{1,120}'", "'<name>'")
    $t = [regex]::Replace($t, '(?m)^(\s*WARNING:\s*)\[(?!<)[^\]\r\n]{1,80}\]', '$1[<name>]')
    $t = [regex]::Replace($t, '(?m)^(\s*)\[(?!OK\]|--\]| X\]| !\]|<)[^\]\r\n]{1,80}\]', '$1[<name>]')
    $t = [regex]::Replace($t, "(user's role \()[^)\r\n]{1,200}(\))", '$1<names>$2')
    $t = [regex]::Replace($t, '(holds )[^:\r\n]{1,120}(: far more)', '$1<names>$2')
    $t = [regex]::Replace($t, '[A-Za-z]:\\[^\s"''<>]+', '<path>')
    $t = [regex]::Replace($t, '(?<![\w/])/(?:home|Users)/[^\s"''<>]+', '<path>')
    return $t
}
function Protect-FileName([string]$n) {
    if ($n -match $dvRx) { return "$($Matches[1])-$(Get-Placeholder $Matches[2] '<env>')-$($Matches[3])$($Matches[4]).json" }
    if ($n -match '^(dv|dvplus)-(.+)-ERROR\.json$') { return "$($Matches[1])-$(Get-Placeholder $Matches[2] '<env>')-ERROR.json" }
    if ($n -match $armRx) { return "arm-$(Get-Placeholder $Matches[1] '<sub>')-$($Matches[2])$($Matches[3]).json" }
    return $n
}

# --- Tool version from .git (no git executable needed) --------------------------------------
function Get-ToolVersion {
    $g = Join-Path $repo '.git'
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

# --- Scope and run start ---------------------------------------------------------------------
$scopeObj = Read-JsonQuiet (Join-Path $out 'scope-effective.json')
$runStart = $null
if ($scopeObj) { try { $runStart = [datetime]::Parse("$($scopeObj.resolvedAt)", [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) } catch {} }

# --- Run log (./run-audit.ps1 -Log): the setup check and every warning, nothing else -----
$logPath = Join-Path $out 'run-log.txt'
$setupLines = @(); $warnLines = @(); $logNote = 'No output/run-log.txt: run the audit with ./run-audit.ps1 -Log to include the setup check and the warnings here.'
if (Test-Path $logPath) {
    $raw = @(Get-Content $logPath)
    # Every Dataverse host named anywhere in the log gets a placeholder before any line is
    # redacted, so the plain 'Dataverse: <org>' lines mask the same way as the URL lines.
    $envN = @($rmap.Values | Where-Object { "$_" -like '<env-*' }).Count
    foreach ($m in [regex]::Matches(($raw -join "`n"), 'https?://([^./\s''"<>)\],;]+)\.(?:api\.)?crm\d*\.dynamics\.com', 'IgnoreCase')) {
        $k = $m.Groups[1].Value.ToLower()
        if (-not $rmap.Contains($k)) { $envN++; $rmap[$k] = "<env-$envN>" }
    }
    $inSetup = $false; $setupDone = $false; $inFindings = $false
    foreach ($line in $raw) {
        # The console findings table names resources and accounts: never copied.
        if ($line -match '^=+ FINDINGS') { $inFindings = $true; continue }
        if ($line -match '^=+ ASSESSMENT') { $inFindings = $false; continue }
        if ($inFindings) { continue }
        if ($line -match '^\*{10,}' -or $line -match '^(Windows PowerShell transcript|PowerShell transcript|Transcript started|Start time|End time|Username|RunAs User|Configuration Name|Machine|Host Application|Process ID|PSVersion|PSEdition|PSCompatibleVersions|BuildVersion|CLRVersion|WSManStackVersion|PSRemotingProtocolVersion|SerializationVersion):') { continue }
        if ($line -match '^(PS>|>> )?TerminatingError\(') { continue }
        if (-not $setupDone -and $line -match 'Checking your app registration setup') { $inSetup = $true }
        if ($inSetup) {
            $setupLines += $line
            if ($line -match '^(Setup looks complete|Setup incomplete|Cannot start)') { $inSetup = $false; $setupDone = $true }
            continue
        }
        if ($line -match 'WARNING|failed|ERROR|Exception|skipped|not read|not registered|Setup looks|Setup incomplete|Cannot start|^Scope:|^Timing:|sweep done\.|^Done\.|^Dataverse\+?: |^Azure|^Graph|^Power Platform|^\s+\[<?[a-z]') { $warnLines += $line }
    }
    $logNote = "From output/run-log.txt ($($raw.Count) lines; only the setup check and progress/warning lines are included, redacted)."
}

# --- Evidence files, errors, findings, checks ----------------------------------------------
function Get-ErrInfoFromFile($path) {
    $t = ''
    try { $t = "$((Get-Content $path -Raw | ConvertFrom-Json).error)" } catch { try { $t = (Get-Content $path -Raw) } catch { $t = '' } }
    $status = ''; $code = ''; $msg = ''
    if ($t -match '\b([45]\d\d)\b') { $status = $Matches[1] }
    if ($t -match '"code"\s*:\s*"([^"]+)"') { $code = $Matches[1] }
    if ($t -match '"message"\s*:\s*"((?:[^"\\]|\\.)*)"') { $msg = $Matches[1]; try { $msg = [regex]::Unescape($msg) } catch {}; if ($msg -match '"Message"\s*:\s*"([^"]+)"') { $msg = $Matches[1] } }
    if (-not $msg) { $msg = $t }
    $msg = ($msg -replace '\s+', ' ').Trim()
    if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + '...' }
    return [pscustomobject]@{ status = $status; code = $code; message = $msg }
}
$files = @(Get-ChildItem $out -Filter '*.json' -File | Sort-Object Name)
$fileRows = @(); $errRows = @(); $staleN = 0
foreach ($f in $files) {
    $shown = Protect-FileName $f.Name
    $stale = ($runStart -and $f.Name -notin 'scope-effective.json', 'assessment-report.json', 'FINDINGS-summary.json' -and $f.LastWriteTimeUtc -lt $runStart.AddMinutes(-2))
    if ($stale) { $staleN++ }
    if ($f.Name -like '*-ERROR.json') {
        $ei = Get-ErrInfoFromFile $f.FullName
        $errRows += "| $shown | $($ei.status) | $($ei.code) | $(Protect-Diag $ei.message) |"
        $fileRows += "| $shown | $($f.Length) | - | ERROR$(if($stale){' (earlier run)'}) |"
        continue
    }
    $count = '-'; $state = 'ok'
    try {
        $rawTxt = Get-Content $f.FullName -Raw
        if ([string]::IsNullOrWhiteSpace($rawTxt)) { $state = 'empty file' }
        else {
            $j = $rawTxt | ConvertFrom-Json
            if ($null -eq $j) { $count = 0 } elseif ($j -is [array]) { $count = $j.Count } elseif ($j.PSObject.Properties.Name -contains 'value') { $count = @($j.value).Count } else { $count = 'object' }
        }
    } catch { $state = 'not valid JSON' }
    if ($stale) { $state += ' (earlier run)' }
    $fileRows += "| $shown | $($f.Length) | $count | $state |"
}
$findRows = @(); $findTotal = 0
$fp = Join-Path $out 'FINDINGS-summary.json'
if (Test-Path $fp) {
    try {
        $fsRaw = Get-Content $fp -Raw | ConvertFrom-Json; $fs = @($fsRaw | Where-Object { $_ })
        $findTotal = $fs.Count
        foreach ($g in @($fs | Group-Object Severity, Area | Sort-Object Name)) { $findRows += "| $($g.Group[0].Severity) | $($g.Group[0].Area) | $($g.Count) |" }
    } catch { $findRows += '| (FINDINGS-summary.json could not be parsed) | | |' }
}
$checkRows = @(); $tally = ''
$ap = Join-Path $out 'assessment-report.json'
if (Test-Path $ap) {
    try {
        $csRaw = Get-Content $ap -Raw | ConvertFrom-Json; $cs = @($csRaw | Where-Object { $_ })
        foreach ($c in $cs) { $checkRows += "| $($c.No) | $($c.Check) | $($c.Status) |$(if($c.PSObject.Properties.Name -contains 'Scope'){" $(Protect-Diag "$($c.Scope)") |"})" }
        $tally = (@($cs | Where-Object { $_.No -ne '2.5' } | Group-Object Status | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.Count)" })) -join ', '
    } catch { $checkRows += '| (assessment-report.json could not be parsed) | | |' }
}
$scopeText = 'No output/scope-effective.json (the setup check did not run).'
if ($scopeObj) {
    $a = $scopeObj.azure; $pp = $scopeObj.powerPlatform
    $scopeText = "partial=$($scopeObj.partial); source=$($scopeObj.source); strict=$($scopeObj.strict). Azure: $(@(Get-ScopeItems $a.subscriptions).Count) subscription(s) selected, $(if($null -ne $a.discoveredSubscriptions){$a.discoveredSubscriptions}else{'?'}) visible, $(@(Get-ScopeItems $a.selectedInvisible).Count) selected but not visible; $(@(Get-ScopeItems $a.resourceGroups).Count) resource group(s) selected; readers: $(if(@(Get-ScopeItems $a.types).Count){(@(Get-ScopeItems $a.types)) -join ', '}else{'all'}). Dataverse: $(@(Get-ScopeItems $pp.environments).Count) environment(s) selected, $(@(Get-ScopeItems $pp.resolved).Count) resolved, $(@(Get-ScopeItems $pp.unresolved).Count) unresolved, $(if($null -ne $pp.discoveredEnvironments){$pp.discoveredEnvironments}else{'?'}) discovered$(if($runStart){"; setup check ran $($runStart.ToString('yyyy-MM-dd HH:mm')) UTC"})."
}

# --- Write ---------------------------------------------------------------------------------
$psv = "$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
$osv = if ($PSVersionTable.OS) { "$($PSVersionTable.OS)" } else { [Environment]::OSVersion.VersionString }
$md = @()
$md += '# d365-security-audit diagnostics (redacted)'
$md += ''
$md += "Generated $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC. Tool version: $(Get-ToolVersion). PowerShell $psv. OS: $osv."
$md += ''
$md += "Names, URLs, IPs, GUIDs and emails are replaced by placeholders (<env-n>, <sub-n>, <rg-n>, <res-n>, <app-n>, <name>, <guid>, <ip>, <email>, <guest>, <domain>, <path>; $($rmap.Count) name(s) taken from the evidence files). No finding or evidence text is included."
$md += ''
$md += '## Scope'
$md += ''
$md += $scopeText
$md += ''
$md += '## Setup check and run messages'
$md += ''
$md += $logNote
if ($setupLines.Count) { $md += ''; $md += '```'; $md += @($setupLines | ForEach-Object { Protect-Diag $_ }); $md += '```' }
if ($warnLines.Count) { $md += ''; $md += 'Progress and warning lines:'; $md += ''; $md += '```'; $md += @($warnLines | Select-Object -First 120 | ForEach-Object { Protect-Diag $_ }); if ($warnLines.Count -gt 120) { $md += "... ($($warnLines.Count - 120) more lines not shown)" }; $md += '```' }
$md += ''
$md += "## Evidence files ($($files.Count)$(if($staleN){"; $staleN from an earlier run"}))"
$md += ''
$md += '| File | Bytes | Rows | State |'
$md += '|---|---|---|---|'
$md += $fileRows
$md += ''
$md += "## Failed pulls ($($errRows.Count))"
$md += ''
if ($errRows.Count) { $md += '| File | HTTP | Code | Message |'; $md += '|---|---|---|---|'; $md += $errRows } else { $md += 'None.' }
$md += ''
$md += "## Findings by severity and area ($findTotal)"
$md += ''
if ($findRows.Count) { $md += '| Severity | Area | Count |'; $md += '|---|---|---|'; $md += $findRows } else { $md += 'No FINDINGS-summary.json (analyze.ps1 did not run).' }
$md += ''
$md += '## Assessment statuses'
$md += ''
if ($checkRows.Count) { $md += "Tally (28 unique): $tally"; $md += ''; $md += '| # | Check | Status | Scope |'; $md += '|---|---|---|---|'; $md += $checkRows } else { $md += 'No assessment-report.json (assessment-report.ps1 did not run).' }
$md += ''
$md += 'Share this file only. The raw files in output/ stay on this machine.'

$dest = Join-Path $out 'diagnostics-redacted.md'
$md -join "`n" | Out-File -Encoding utf8 $dest
Write-Host ''
Write-Host "Wrote $dest" -ForegroundColor Green
Write-Host "Read it once before sharing: $($files.Count) evidence file(s) listed, $($errRows.Count) failed pull(s), $findTotal finding(s) counted, $(if($setupLines.Count){'setup check included'}else{'no run log (use ./run-audit.ps1 -Log)'})." -ForegroundColor Yellow
Write-Host 'Nothing left this machine.' -ForegroundColor DarkGray
