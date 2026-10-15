# security-report.ps1 - the report for people: output/security-assessment.html.
#
#   ./scripts/security-report.ps1        (run-audit.ps1 runs it after assessment-report.ps1)
#
# One self-contained page that reads the same every run for the same evidence (no AI text): a
# summary, the issues to fix first, every issue as a card (what was found, why it matters, the
# steps to fix it and the Microsoft documentation behind those steps), Microsoft's 29-check
# review, the checks a person has to do by hand, and how the assessment was made. Open it in a
# browser; print it to PDF to hand it out.
# The facts come from analyze.ps1 (FINDINGS-summary.json) and assessment-report.ps1
# (assessment-report.json); the explanations, steps and links from finding-catalog.json, a fixed
# file in this folder. Local files only: no sign-in, no network call, and the page loads nothing
# from the internet. It holds your tenant's names, so keep it with the rest of output/.

. (Join-Path $PSScriptRoot '_common.ps1')
$ErrorActionPreference = 'Continue'
$out = Get-OutDir
$scope = Read-ScopeEffective
$inv = [cultureinfo]::InvariantCulture

# Missing, empty, unreadable or ok, per file, so a file that was not read never looks like a clean
# result. -NoEnumerate keeps arrays intact on return; callers assign first and only then wrap in @( ).
$readState = @{}
function Read-JsonFile([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) { $script:readState[$Label] = 'missing'; return $null }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { $script:readState[$Label] = 'empty'; return $null }
        $x = $raw | ConvertFrom-Json
        $script:readState[$Label] = 'ok'
        Write-Output -NoEnumerate $x
    } catch { $script:readState[$Label] = 'unreadable'; Write-Warning "security report: $(Split-Path $Path -Leaf) could not be read ($($_.Exception.Message))"; $null }
}
function Get-Prop($Obj, [string]$Name) {
    if ($null -eq $Obj -or -not $Name) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}
# Every piece of text from the evidence or the catalog goes through Esc (not H: that name is a
# built-in alias of Get-History). It escapes markup characters and both quotes; the page is
# written as UTF-8 with a charset declaration, so any other character is kept as it is.
function Esc($s) { if ($null -eq $s) { return '' }; return [System.Net.WebUtility]::HtmlEncode("$s") }
function Get-SafeUrl([string]$u) { if ("$u" -match '^https://[A-Za-z0-9.-]+(/[^\s"''<>]*)?\z') { return $u }; return $null }
function Get-Slug([string]$s) { $t = ("$s" -replace '[^A-Za-z0-9_-]+', '-').Trim('-'); if ($t) { return $t.ToLowerInvariant() }; return 'x' }

$catalog = Read-JsonFile (Join-Path $PSScriptRoot 'finding-catalog.json') 'catalog'
if (-not $catalog) { Write-Warning 'security report: finding-catalog.json is missing or unreadable; the report lists the findings without explanations.' }
$fPath = Join-Path $out 'FINDINGS-summary.json'; $cPath = Join-Path $out 'assessment-report.json'
$fAll = Read-JsonFile $fPath 'findings'
$cAll = Read-JsonFile $cPath 'checks'
$findings = @($fAll | Where-Object { $_ })
$checks = @($cAll | Where-Object { $_ })
$findingsOk = ($readState['findings'] -eq 'ok'); $checksOk = ($readState['checks'] -eq 'ok')
if (-not $findingsOk) { Write-Warning "security report: FINDINGS-summary.json is $($readState['findings']); run scripts/analyze.ps1 first. The page says so instead of showing zero issues." }

$sevRank  = @{ HIGH = 0; MEDIUM = 1; LOW = 2 }
$sevLabel = @{ HIGH = 'High'; MEDIUM = 'Medium'; LOW = 'Low' }
$sevClass = @{ HIGH = 'high'; MEDIUM = 'medium'; LOW = 'low' }
$unknownSev = @{}
# A severity the report does not know is shown as High (never hidden as Low) and named once.
function Get-Sev($s) {
    $t = "$s".Trim().ToUpperInvariant()
    if ($sevRank.ContainsKey($t)) { return $t }
    if (-not $script:unknownSev.ContainsKey($t)) { $script:unknownSev[$t] = $true; Write-Warning "security report: unknown severity '$s' shown as High" }
    return 'HIGH'
}

# --- One card per kind of finding (catalog key); several findings of one kind share a card ---
$cards = @{}; $cardOrder = New-Object System.Collections.ArrayList
foreach ($f in $findings) {
    $key = if ($f.Key) { "$($f.Key)" } elseif ($f.Area) { "area:$($f.Area)" } else { 'area:unclassified' }
    if (-not $cards.ContainsKey($key)) {
        $entry = Get-Prop (Get-Prop $catalog 'findings') $key
        $cards[$key] = [pscustomobject]@{ key = $key; id = "f-$(Get-Slug $key)-$($cardOrder.Count + 1)"; entry = $entry; sev = 'LOW'; items = (New-Object System.Collections.ArrayList); kinds = @{}; area = $(if ($f.Area) { "$($f.Area)" } else { 'Unclassified' }) }
        [void]$cardOrder.Add($key)
    }
    $c = $cards[$key]
    $sv = Get-Sev $f.Severity
    if ($sevRank[$sv] -lt $sevRank[$c.sev]) { $c.sev = $sv }
    [void]$c.items.Add($f)
    if ($f.Kind) { $c.kinds["$($f.Kind)"] = $true }
}
$missingKeys = @($cardOrder | Where-Object { -not $cards[$_].entry })
if ($missingKeys.Count) { Write-Warning "security report: no catalog entry for $($missingKeys -join ', '); those cards show the finding text only." }

# Catalog groups, one per id, in catalog order; 'other' is the report's own bucket.
$groups = @(@(Get-Prop $catalog 'groups') | Where-Object { $_ -and $_.id -and "$($_.id)" -ne 'other' } | Group-Object { "$($_.id)" } | ForEach-Object { $_.Group[0] })
$groupIds = @($groups | ForEach-Object { "$($_.id)" })
function Get-CardGroup($c) { $g = "$(Get-Prop $c.entry 'group')"; if ($g -and $groupIds -contains $g) { return $g }; return 'other' }
function Test-Info($c) { return ((Get-Prop $c.entry 'info') -eq $true) }
function Get-CardTitle($c) { $t = Get-Prop $c.entry 'title'; if ($t) { return "$t" }; if ($c.area -and $c.area -ne 'Unclassified') { return "$($c.area) finding" }; return 'Unclassified finding' }
$issueCards = @($cardOrder | ForEach-Object { $cards[$_] } | Where-Object { -not (Test-Info $_) })
$infoCards  = @($cardOrder | ForEach-Object { $cards[$_] } | Where-Object { Test-Info $_ })
function Sort-Cards($list) { @($list | Sort-Object @{ Expression = { $sevRank[$_.sev] } }, @{ Expression = { Get-CardTitle $_ } }) }

# Links for a card: its own, plus the page for each resource kind its findings name.
function Get-CardLinks($c) {
    $seen = @{}; $res = @()
    $all = @(@(Get-Prop $c.entry 'links') | Where-Object { $_ })
    $kl = Get-Prop $c.entry 'kindLinks'
    foreach ($k in @($c.kinds.Keys | Sort-Object)) { $all += @(@(Get-Prop $kl $k) | Where-Object { $_ }) }
    foreach ($l in $all) {
        $u = Get-SafeUrl "$($l.url)"
        if (-not $u -or $seen.ContainsKey($u)) { continue }
        $seen[$u] = $true; $res += [pscustomobject]@{ title = "$($l.title)"; url = $u }
    }
    return $res
}
function Get-LinksHtml($links) {
    $l = @($links | Where-Object { $_ -and $_.url })
    if (-not $l.Count) { return '' }
    $li = @($l | ForEach-Object { "<li><a href=""$(Esc $_.url)"">$(Esc $(if ($_.title) { $_.title } else { $_.url }))</a><span class=""url"">$(Esc $_.url)</span></li>" })
    return "<h4>Microsoft guidance</h4><ul class=""refs"">$($li -join '')</ul>"
}
function Get-CardHtml($c, [switch]$Compact) {
    $e = $c.entry; $cls = $sevClass[$c.sev]
    $mixed = @($c.items | ForEach-Object { Get-Sev $_.Severity } | Select-Object -Unique).Count -gt 1
    $h = New-Object System.Collections.ArrayList
    [void]$h.Add("<article class=""card $cls"" id=""$($c.id)"">")
    [void]$h.Add("<div class=""card-head""><span class=""sev $cls"">$($sevLabel[$c.sev])</span><h3>$(Esc (Get-CardTitle $c))</h3></div>")
    $meta = @((Esc $c.area)); $own = Get-Prop $e 'owner'; if ($own) { $meta += "Suggested owner: $(Esc $own)" }
    if ($c.items.Count -gt 1) { $meta += "$($c.items.Count) findings" }
    [void]$h.Add("<div class=""meta"">$($meta -join ' &middot; ')</div>")
    [void]$h.Add('<h4>What we found</h4><ul class="found">')
    foreach ($it in $c.items) {
        $sv = Get-Sev $it.Severity
        $chip = if ($mixed) { "<span class=""sev mini $($sevClass[$sv])"">$($sevLabel[$sv])</span> " } else { '' }
        $sc = if ($it.Scope) { "<span class=""scope"">Scope: $(Esc $it.Scope)</span>" } else { '' }
        [void]$h.Add("<li>$chip$(Esc $it.Finding)$sc</li>")
    }
    [void]$h.Add('</ul>')
    $why = Get-Prop $e 'why'; $steps = @(@(Get-Prop $e 'steps') | Where-Object { $_ })
    if ($why) { [void]$h.Add("<h4>Why it matters</h4><p>$(Esc $why)</p>") }
    if (-not $Compact -and $steps.Count) { [void]$h.Add("<h4>What to do</h4><ol class=""steps"">$((@($steps | ForEach-Object { "<li>$(Esc $_)</li>" })) -join '')</ol>") }
    [void]$h.Add((Get-LinksHtml (Get-CardLinks $c)))
    if (-not $e) { [void]$h.Add('<p class="meta">No explanation for this kind of finding in finding-catalog.json yet; the finding text says what to change.</p>') }
    [void]$h.Add('</article>')
    return ($h -join "`n")
}
# One muted line for the fix-first lists: area, suggested owner, how many findings.
function Get-ListMeta($c) {
    $m = @((Esc $c.area))
    $o = Get-Prop $c.entry 'owner'; if ($o) { $m += (Esc $o) }
    if ($c.items.Count -gt 1) { $m += "$($c.items.Count) findings" }
    return ('&middot; ' + ($m -join ' &middot; '))
}

# --- The 29 checks ---
$statusClass = @{ 'Gap' = 'gap'; 'Partial' = 'partial'; 'Aligned' = 'aligned'; 'Not checked' = 'notchecked'; 'MANUAL' = 'manual'; 'Not in use' = 'notinuse' }
$statusLabel = @{ 'MANUAL' = 'Manual' }
$unique = @($checks | Where-Object { "$($_.No)" -ne '2.5' })
$tally = [ordered]@{}
foreach ($s in 'Gap', 'Partial', 'Aligned', 'Not in use', 'Not checked', 'MANUAL') { $n = @($unique | Where-Object { "$($_.Status)" -eq $s }).Count; if ($n) { $tally[$s] = $n } }
$barColor = @{ 'Gap' = 'var(--high)'; 'Partial' = 'var(--med)'; 'Aligned' = 'var(--ok)'; 'Not in use' = '#98a2b3'; 'Not checked' = '#d0d5dd'; 'MANUAL' = 'var(--man)' }
function Get-StatusChip([string]$s) { $cl = $statusClass[$s]; if (-not $cl) { $cl = 'notchecked' }; $lb = if ($statusLabel[$s]) { $statusLabel[$s] } else { $s }; return "<span class=""st $cl"">$(Esc $lb)</span>" }

# --- Run facts ---
$stale = @(Get-StaleEvidence $out $scope)
# The report's own inputs: older than this run's setup check means analyze.ps1 or
# assessment-report.ps1 did not run again after the sweeps.
$inputStale = @()
try {
    $runStart = [datetime]::Parse("$($scope.resolvedAt)", $inv, [Globalization.DateTimeStyles]::AdjustToUniversal)
    foreach ($ip in @(@($fPath, 'FINDINGS-summary.json', 'analyze.ps1'), @($cPath, 'assessment-report.json', 'assessment-report.ps1'))) {
        if ((Test-Path -LiteralPath $ip[0]) -and (Get-Item -LiteralPath $ip[0]).LastWriteTimeUtc -lt $runStart.AddMinutes(-2)) { $inputStale += "$($ip[1]) (run $($ip[2]) again)" }
    }
} catch {}
$banner = Get-ScopeBanner $scope
$nowUtc = (Get-Date).ToUniversalTime()
$generated = $nowUtc.ToString('yyyy-MM-dd HH:mm', $inv)
$version = Get-ToolVersion
$sevCount = @{ HIGH = @($issueCards | Where-Object { $_.sev -eq 'HIGH' }).Count; MEDIUM = @($issueCards | Where-Object { $_.sev -eq 'MEDIUM' }).Count; LOW = @($issueCards | Where-Object { $_.sev -eq 'LOW' }).Count }
$issueLines = 0; foreach ($c in $issueCards) { $issueLines += $c.items.Count }
$infoLines = 0; foreach ($c in $infoCards) { $infoLines += $c.items.Count }
$notChecked = @($unique | Where-Object { "$($_.Status)" -eq 'Not checked' }).Count
# The Power Platform admin API answers only an app registered as a management app, which Microsoft
# treats like a Power Platform administrator (docs/permissions.md, section 5).
$ppAdminRead = (Test-Path -LiteralPath (Join-Path $out 'pp-environments.json')) -and -not (Test-Path -LiteralPath (Join-Path $out 'pp-environments-ERROR.json'))

# --- Page ---
$css = @'
:root{--ink:#1d2939;--muted:#5d6b7c;--line:#dfe3e8;--soft:#f7f8fa;--accent:#0b4a7a;--high:#b42318;--high-bg:#fef3f2;--med:#b54708;--med-bg:#fffaeb;--low:#175cd3;--low-bg:#eff8ff;--ok:#067647;--ok-bg:#ecfdf3;--gray:#475467;--gray-bg:#f2f4f7;--man:#5925dc;--man-bg:#f4f3ff}
*{box-sizing:border-box}
html{background:#fff}
body{margin:0;background:#fff;color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.wrap{max-width:980px;margin:0 auto;padding:0 24px}
.cover{background:var(--accent);color:#fff;padding:36px 0 30px}
.eyebrow{text-transform:uppercase;letter-spacing:.09em;font-size:12px;opacity:.85;margin:0 0 6px}
.cover h1{font-size:30px;line-height:1.2;margin:0 0 8px;font-weight:650}
.cover p{margin:3px 0;opacity:.93}
main{padding:8px 0 40px}
h2{font-size:22px;line-height:1.3;margin:42px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h2 small{font-size:14px;font-weight:400;color:var(--muted)}
h3{font-size:17px;line-height:1.35;margin:0}
p{margin:6px 0}
a{color:var(--accent)}
.toc{columns:2;column-gap:32px;padding-left:18px;margin:10px 0}
.toc li{margin:2px 0}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0 8px}
.tile{border:1px solid var(--line);border-radius:10px;padding:12px 14px;background:var(--soft)}
.tile .n{font-size:30px;font-weight:700;line-height:1.1}
.tile .l{font-size:13px;color:var(--muted)}
.tile.high .n{color:var(--high)}.tile.medium .n{color:var(--med)}.tile.low .n{color:var(--low)}.tile.checks .n{color:var(--accent)}
.bar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--gray-bg);margin:10px 0 6px}
.bar span{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:13px;color:var(--muted);margin-bottom:6px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:-1px}
.box{border:1px solid var(--line);border-radius:10px;padding:12px 18px;background:var(--soft);margin:14px 0}
.box ol,.box ul{margin:6px 0;padding-left:20px}
.note{border-left:4px solid var(--med);background:var(--med-bg);padding:10px 14px;border-radius:6px;margin:14px 0}
.fixfirst{padding-left:22px}
.fixfirst li{margin:5px 0}
.group-intro{color:var(--muted);margin:0 0 6px}
.card{border:1px solid var(--line);border-left:6px solid var(--gray);border-radius:10px;margin:14px 0;padding:14px 18px 10px;background:#fff}
.card.high{border-left-color:var(--high)}.card.medium{border-left-color:var(--med)}.card.low{border-left-color:var(--low)}
.card-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sev{font-size:12px;font-weight:700;padding:2px 10px;border-radius:999px;white-space:nowrap}
.sev.high{color:var(--high);background:var(--high-bg)}.sev.medium{color:var(--med);background:var(--med-bg)}.sev.low{color:var(--low);background:var(--low-bg)}
.sev.mini{font-size:11px;padding:1px 7px}
.meta{color:var(--muted);font-size:13px;margin:4px 0 2px}
.card h4{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:14px 0 4px}
.found{margin:4px 0;padding-left:20px}
.found li{margin:4px 0;overflow-wrap:anywhere}
.scope{display:block;color:var(--muted);font-size:12px}
.steps{margin:4px 0;padding-left:22px}
.steps li{margin:4px 0}
.refs{list-style:none;margin:4px 0 6px;padding:0}
.refs li{margin:5px 0}
.refs a{font-weight:600;text-decoration:none}
.refs .url{display:block;color:var(--muted);font-size:12px;overflow-wrap:anywhere}
.info .card{padding:10px 16px 6px}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin:10px 0}
th,td{border-bottom:1px solid var(--line);padding:8px 8px;text-align:left;vertical-align:top}
th{background:var(--soft);font-weight:600}
td.ev{overflow-wrap:anywhere}
td .plain{display:block;color:var(--muted);font-size:12.5px}
td .refs{margin:0}
.st{font-size:12px;font-weight:700;padding:2px 9px;border-radius:999px;white-space:nowrap}
.st.gap{color:var(--high);background:var(--high-bg)}.st.partial{color:var(--med);background:var(--med-bg)}.st.aligned{color:var(--ok);background:var(--ok-bg)}
.st.notchecked,.st.notinuse{color:var(--gray);background:var(--gray-bg)}.st.manual{color:var(--man);background:var(--man-bg)}
footer{color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);margin-top:36px;padding:12px 0 30px}
@media (max-width:720px){.tiles{grid-template-columns:repeat(2,1fr)}.toc{columns:1}.cover h1{font-size:25px}}
@media print{body{font-size:12px}.cover{padding:20px 0}.card,.tile,tr,.box{break-inside:avoid}h2,h3,h4{break-after:avoid}a{color:inherit;text-decoration:none}.pb{break-before:page}}
@page{margin:14mm}
'@

$p = New-Object System.Collections.ArrayList
[void]$p.Add('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
[void]$p.Add("<title>Security assessment $(Esc $nowUtc.ToString('yyyy-MM-dd', $inv))</title><style>$css</style></head><body>")
[void]$p.Add('<header class="cover"><div class="wrap">')
[void]$p.Add('<p class="eyebrow">Security assessment &middot; read-only</p>')
[void]$p.Add('<h1>Microsoft Entra ID, Dynamics 365, Power Platform and Azure</h1>')
[void]$p.Add("<p>Generated $(Esc $generated) UTC from the live configuration. Nothing was changed.</p>")
[void]$p.Add("<p>$(Esc $banner)</p>")
[void]$p.Add('</div></header><main><div class="wrap">')

# Contents
$toc = @('<li><a href="#summary">Summary</a></li>', '<li><a href="#fix-first">Fix first</a></li>')
$groupsWithCards = @()
foreach ($g in @($groups) + @([pscustomobject]@{ id = 'other'; title = 'Other findings'; intro = '' })) {
    $gc = @($issueCards | Where-Object { (Get-CardGroup $_) -eq "$($g.id)" })
    if ($gc.Count) { $groupsWithCards += [pscustomobject]@{ g = $g; slug = "g-$(Get-Slug $g.id)"; cards = (Sort-Cards $gc) }; $toc += "<li><a href=""#g-$(Get-Slug $g.id)"">$(Esc $g.title)</a> ($($gc.Count))</li>" }
}
$toc += '<li><a href="#checks">Microsoft''s security review: the 29 checks</a></li>', '<li><a href="#manual">Checks to do by hand</a></li>'
if ($infoCards.Count) { $toc += '<li><a href="#info">Checked and fine, or for information</a></li>' }
$toc += '<li><a href="#about">About this assessment</a></li>'

# Summary
[void]$p.Add('<h2 id="summary">Summary</h2>')
if (-not $findingsOk) { [void]$p.Add("<div class=""note""><strong>The findings were not read</strong> (FINDINGS-summary.json is $(Esc $readState['findings'])). Run scripts/analyze.ps1, or the whole audit with run-audit.ps1, and build this page again. The counts below are not a result.</div>") }
if ($inputStale.Count) { [void]$p.Add("<div class=""note""><strong>This page was built from older results.</strong> $(Esc ($inputStale -join '; ')) is older than this run's setup check, so it does not reflect this run.</div>") }
$tileN = { param($n) if ($findingsOk) { "$n" } else { '-' } }
[void]$p.Add('<div class="tiles">')
[void]$p.Add("<div class=""tile high""><div class=""n"">$(& $tileN $sevCount.HIGH)</div><div class=""l"">High: fix first</div></div>")
[void]$p.Add("<div class=""tile medium""><div class=""n"">$(& $tileN $sevCount.MEDIUM)</div><div class=""l"">Medium: fix soon</div></div>")
[void]$p.Add("<div class=""tile low""><div class=""n"">$(& $tileN $sevCount.LOW)</div><div class=""l"">Low: review and decide</div></div>")
if ($checksOk -and $unique.Count) { [void]$p.Add("<div class=""tile checks""><div class=""n"">$(if($tally['Gap']){$tally['Gap']}else{0})</div><div class=""l"">of Microsoft's $($unique.Count) checks read Gap</div></div>") }
else { [void]$p.Add("<div class=""tile checks""><div class=""n"">-</div><div class=""l"">Microsoft's checks: not read</div></div>") }
[void]$p.Add('</div>')
if ($unique.Count) {
    [void]$p.Add('<div class="bar">' + (@($tally.Keys | ForEach-Object { "<span style=""width:$(([Math]::Round(100 * $tally[$_] / $unique.Count, 2)).ToString($inv))%;background:$($barColor[$_])""></span>" }) -join '') + '</div>')
    [void]$p.Add('<div class="legend">' + (@($tally.Keys | ForEach-Object { "<span><span class=""dot"" style=""background:$($barColor[$_])""></span>$(Esc $(if ($statusLabel[$_]) { $statusLabel[$_] } else { $_ })): $($tally[$_])</span>" }) -join '') + '</div>')
}
if ($findingsOk) { [void]$p.Add("<p class=""meta"">Counts are issues: one card per kind of problem, from $issueLines finding line(s)$(if($infoLines){", plus $infoLines line(s) that are fine or for information"}). The bar is Microsoft's security review over its $($unique.Count) unique checks.</p>") }
if ($stale.Count) { [void]$p.Add("<div class=""note""><strong>Some evidence is from an earlier run.</strong> $($stale.Count) evidence file(s) were not refreshed by this run (a skipped area, a sweep that stopped early, or a narrower scope), so the findings built from them describe that earlier state. They are listed under About this assessment.</div>") }
if ($scope -and $scope.partial) { [void]$p.Add('<div class="note"><strong>This run covered part of the estate.</strong> Results describe the selected scope only (see the scope line at the top); do not present this as a complete assessment.</div>') }
[void]$p.Add('<div class="box"><strong>How to use this report</strong><ol>')
[void]$p.Add('<li>Start with <a href="#fix-first">Fix first</a>. Each item links to its card.</li>')
[void]$p.Add('<li>Each card says what was found, why it matters and what to do, with links to Microsoft''s own instructions. Hand it to the suggested owner.</li>')
[void]$p.Add('<li>Check before you change: some fixes can break a process that depends on the old setting. The steps say where.</li>')
[void]$p.Add('<li>After a fix, run the audit again. A fixed item no longer appears.</li>')
[void]$p.Add('</ol><p class="meta">High: exposed now or easy to abuse. Medium: a real weakness to fix soon. Low: review and decide; it may be fine on purpose.</p></div>')
[void]$p.Add("<p><strong>Contents</strong></p><ul class=""toc"">$($toc -join '')</ul>")

# Fix first
[void]$p.Add('<h2 id="fix-first" class="pb">Fix first <small>high-severity issues</small></h2>')
$high = @($groupsWithCards | ForEach-Object { $_.cards } | Where-Object { $_.sev -eq 'HIGH' })
if ($high.Count) {
    [void]$p.Add('<ul class="fixfirst">')
    foreach ($c in $high) { [void]$p.Add("<li><a href=""#$($c.id)"">$(Esc (Get-CardTitle $c))</a> <span class=""meta"">$(Get-ListMeta $c)</span></li>") }
    [void]$p.Add('</ul>')
} elseif ($findingsOk) { [void]$p.Add('<p>No high-severity issue was found in what this run could read.</p>') }
else { [void]$p.Add('<p>The findings were not read, so this list is empty. See the note in the summary.</p>') }
$med = @($groupsWithCards | ForEach-Object { $_.cards } | Where-Object { $_.sev -eq 'MEDIUM' })
if ($med.Count) {
    [void]$p.Add('<p><strong>Then fix soon:</strong></p><ul class="fixfirst">')
    foreach ($c in $med) { [void]$p.Add("<li><a href=""#$($c.id)"">$(Esc (Get-CardTitle $c))</a> <span class=""meta"">$(Get-ListMeta $c)</span></li>") }
    [void]$p.Add('</ul>')
}

# Issues by area
foreach ($gw in $groupsWithCards) {
    [void]$p.Add("<h2 id=""$($gw.slug)"" class=""pb"">$(Esc $gw.g.title)</h2>")
    if ($gw.g.intro) { [void]$p.Add("<p class=""group-intro"">$(Esc $gw.g.intro)</p>") }
    foreach ($c in $gw.cards) { [void]$p.Add((Get-CardHtml $c)) }
}

# The 29 checks
[void]$p.Add('<h2 id="checks" class="pb">Microsoft''s security review: the 29 checks</h2>')
if ($checks.Count) {
    [void]$p.Add('<p class="group-intro">Microsoft''s Power Platform and Dynamics 365 security review, answered from the live configuration. Gap: fix. Partial: partly in place. Aligned: in place. Not in use: the feature is not used, so the check does not apply. Not checked: the tool could not read it, and the evidence says what access would let it. Manual: no API can answer; the evidence gives the place to look. 2.5 repeats 2.4 in Microsoft''s template and is left out of the counts.</p>')
    [void]$p.Add('<table><thead><tr><th>#</th><th>Check</th><th>Status</th><th>What the evidence says</th><th>Microsoft guidance</th></tr></thead><tbody>')
    foreach ($ck in $checks) {
        $ce = Get-Prop (Get-Prop $catalog 'checks') "$($ck.No)"
        $plain = Get-Prop $ce 'plain'
        $links = @(@(Get-Prop $ce 'links') | Where-Object { $_ } | ForEach-Object { $u = Get-SafeUrl "$($_.url)"; if ($u) { "<li><a href=""$(Esc $u)"">$(Esc $(if ($_.title) { $_.title } else { $u }))</a></li>" } })
        [void]$p.Add("<tr><td>$(Esc $ck.No)</td><td><strong>$(Esc $ck.Check)</strong>$(if($plain){"<span class='plain'>$(Esc $plain)</span>"})</td><td>$(Get-StatusChip "$($ck.Status)")</td><td class=""ev"">$(Esc $ck.Evidence)</td><td>$(if($links.Count){"<ul class='refs'>$($links -join '')</ul>"})</td></tr>")
    }
    [void]$p.Add('</tbody></table>')
} else { [void]$p.Add("<p>assessment-report.json is $(Esc $readState['checks']): run assessment-report.ps1 (run-audit.ps1 does) to fill this section.</p>") }

# By hand
[void]$p.Add('<h2 id="manual">Checks to do by hand</h2>')
[void]$p.Add('<p class="group-intro">No API can answer these, so a person confirms them. Each says where to look.</p>')
$manualRows = @($checks | Where-Object { "$($_.Status)" -eq 'MANUAL' })
if ($manualRows.Count) {
    [void]$p.Add('<table><thead><tr><th>#</th><th>Check</th><th>Where to look</th></tr></thead><tbody>')
    foreach ($ck in $manualRows) { [void]$p.Add("<tr><td>$(Esc $ck.No)</td><td><strong>$(Esc $ck.Check)</strong></td><td class=""ev"">$(Esc $ck.Evidence)</td></tr>") }
    [void]$p.Add('</tbody></table>')
}
$mi = 0
foreach ($m in @(@(Get-Prop $catalog 'manual') | Where-Object { $_ -and $_.title })) {
    $mi++
    $mc = [pscustomobject]@{ key = "manual-$($m.key)"; entry = $m; sev = 'LOW'; items = @(); kinds = @{}; area = 'By hand' }
    $h = New-Object System.Collections.ArrayList
    [void]$h.Add("<article class=""card"" id=""m-$(Get-Slug $m.key)-$mi""><div class=""card-head""><h3>$(Esc $m.title)</h3></div>")
    if ($m.owner) { [void]$h.Add("<div class=""meta"">Suggested owner: $(Esc $m.owner)</div>") }
    if ($m.why) { [void]$h.Add("<h4>Why it matters</h4><p>$(Esc $m.why)</p>") }
    $ms = @(@($m.steps) | Where-Object { $_ })
    if ($ms.Count) { [void]$h.Add("<h4>What to do</h4><ol class=""steps"">$((@($ms | ForEach-Object { "<li>$(Esc $_)</li>" })) -join '')</ol>") }
    [void]$h.Add((Get-LinksHtml (Get-CardLinks $mc)))
    [void]$h.Add('</article>')
    [void]$p.Add(($h -join "`n"))
}

# For information
if ($infoCards.Count) {
    [void]$p.Add('<h2 id="info">Checked and fine, or for information</h2><div class="info">')
    foreach ($c in (Sort-Cards $infoCards)) { [void]$p.Add((Get-CardHtml $c -Compact)) }
    [void]$p.Add('</div>')
}

# About
[void]$p.Add('<h2 id="about" class="pb">About this assessment</h2>')
[void]$p.Add('<p>A tool that only reads signed in as a dedicated app registration and read the configuration through Microsoft''s own interfaces: Microsoft Graph (Entra ID), the Power Platform admin API and Dataverse, and Azure Resource Manager. It changed nothing in the tenant. It reads the configuration as it is today, not the history of who changed it.</p>')
if ($ppAdminRead) { [void]$p.Add('<p class="meta">The Power Platform admin API was read this run. It answers only an app registered as a Power Platform management app, which Microsoft treats like a Power Platform administrator; remove that registration when the assessment is done (docs/permissions.md, section 5).</p>') }
[void]$p.Add("<ul><li>$(Esc $banner)</li><li><strong>Generated:</strong> $(Esc $generated) UTC by d365-security-audit $(Esc $version).</li><li><strong>Checks not readable this run:</strong> $(if($checksOk){"$notChecked of $($unique.Count); the evidence column says what access would let the tool read each one"}else{'unknown: the checks file was not read'}).</li><li><strong>Raw evidence:</strong> the output folder on the machine that ran the audit. It holds your real configuration; keep it private.</li><li><strong>How the advice was written:</strong> each finding comes from a fixed rule in the tool. The explanations, steps and links come from a fixed catalog checked against Microsoft documentation; the links go to Microsoft Learn.</li></ul>")
if ($stale.Count) { [void]$p.Add("<p><strong>Evidence from an earlier run:</strong> $(Esc (($stale | Select-Object -First 40) -join ', '))$(if($stale.Count -gt 40){" (+$($stale.Count - 40) more)"}).</p>") }
[void]$p.Add('</div></main><footer><div class="wrap">Security assessment, generated from live configuration by a read-only tool. Contains your organization''s configuration: share it only with the people who need it.</div></footer></body></html>')

$path = Join-Path $out 'security-assessment.html'
try {
    [IO.File]::WriteAllText($path, ($p -join "`n"), (New-Object System.Text.UTF8Encoding($false)))
    # The v1.5.3 page this one replaces, so an old copy is never mistaken for this run's.
    Remove-Item -LiteralPath (Join-Path $out 'assessment-report.html') -Force -ErrorAction SilentlyContinue
    Write-Host ("Report for people: {0}  (open in a browser; print to PDF to hand it out)" -f $path) -ForegroundColor Green
} catch { Write-Warning "security report: could not write $path ($($_.Exception.Message))" }
