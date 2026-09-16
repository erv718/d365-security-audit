# ai-analysis.ps1 - OPTIONAL, OFF by default. Adds a mitigation-analysis section built from
# the findings. This is the ONLY part of the tool that can send data off-machine, and only
# when AI_ANALYSIS=api is explicitly set in .env. It reads ./output; it never touches the tenant.
#
# Modes (AI_ANALYSIS in .env):
#   off   (default) - do nothing.
#   local - write output/ai-analysis-prompt.md (findings + a ready prompt) for you to hand to
#           your own Claude Code / Kimi / Codex session. No network call, zero egress.
#   api   - POST the scoped findings to the OpenAI-compatible endpoint in .env and write
#           output/ai-analysis.md.
# Scope (AI_ANALYSIS_SCOPE): redacted (default) | named | full.

. (Join-Path $PSScriptRoot '_common.ps1')

$mode = "$(Get-Conf 'AI_ANALYSIS')".ToLower().Trim()
if ($mode -ne 'local' -and $mode -ne 'api') { return }   # off / unset: nothing to do

$scope = "$(Get-Conf 'AI_ANALYSIS_SCOPE')".ToLower().Trim(); if (-not $scope) { $scope = 'redacted' }
if ($scope -notin 'redacted', 'named', 'full') { Write-Warning "ai-analysis: unknown AI_ANALYSIS_SCOPE '$scope'; using 'redacted'."; $scope = 'redacted' }
$out = Get-OutDir

# --- gather the summaries (the small, high-signal files) ---
$reportMd = ''
$rp = Join-Path $out 'assessment-report.md'
if (Test-Path $rp) { $reportMd = Get-Content $rp -Raw }
$findingsText = ''
$fp = Join-Path $out 'FINDINGS-summary.json'
if (Test-Path $fp) {
    try { $findingsText = ((Get-Content $fp -Raw | ConvertFrom-Json) | ForEach-Object { "- [$($_.Severity)] $($_.Area): $($_.Finding)" }) -join "`n" } catch {}
}
if (-not $reportMd -and -not $findingsText) {
    Write-Warning 'ai-analysis: no assessment-report.md / FINDINGS-summary.json in output/. Run the audit first.'
    return
}
$material = "# Assessment report`n`n$reportMd`n`n# Ranked findings`n`n$findingsText"

# --- full scope: also inline the raw evidence, skipping the huge catalogue files ---
if ($scope -eq 'full') {
    $skip = @('servicePrincipals.json', 'appRoleDefinitions-graph.json', 'appRoleDefinitions-exo.json', 'FINDINGS-summary.json', 'assessment-report.json')
    $used = 0
    foreach ($f in (Get-ChildItem $out -Filter '*.json' | Sort-Object Length)) {
        if ($f.Name -in $skip) { continue }
        if ($f.Length -gt 200KB) { continue }
        if ($used + $f.Length -gt 500KB) { break }
        $material += "`n`n## output/$($f.Name)`n``````json`n$(Get-Content $f.FullName -Raw)`n``````"
        $used += $f.Length
    }
}

# --- redaction (default scope) ---
# Best effort over the report and findings text: emails, IPs, GUIDs, tenant domains, quoted
# names, and the name lists the report prints unquoted (environments without a security group,
# SQL servers on old TLS, guest home domains, apps holding risky permissions, and the
# [environment] prefix on the Dataverse findings).
function Protect-Text([string]$t) {
    $ml = [System.Text.RegularExpressions.RegexOptions]::Multiline
    $t = [regex]::Replace($t, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<email>')
    $t = [regex]::Replace($t, '\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b', '<ip>')
    $t = [regex]::Replace($t, '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '<guid>')
    $t = [regex]::Replace($t, "'[^']{1,80}'", "'<name>'")
    $t = [regex]::Replace($t, '\b[A-Za-z0-9-]+\.onmicrosoft\.com\b', '<domain>')
    $t = [regex]::Replace($t, '(Without one: ).*?(\. Fix:)', '$1<names>$2')
    $t = [regex]::Replace($t, '(older TLS still accepted on: ).*?(\. Not verified)', '$1<names>$2')
    $t = [regex]::Replace($t, '(top 3: ).*?(\. Confirm)', '$1<domains>$2')
    $t = [regex]::Replace($t, '(\(tenant-wide\): ).*$', '$1<names>', $ml)
    $t = [regex]::Replace($t, '\[[^\]\r\n]{1,80}\] (Dataverse auditing is OFF|Zero custom security roles)', '[<name>] $1')
    return $t
}
if ($scope -eq 'redacted') { $material = Protect-Text $material }

$prompt = @'
You are a Microsoft cloud security advisor. Below is the output of a READ-ONLY audit of a
Dynamics 365 / Power Platform / Azure tenant, mapped to Microsoft's Power Platform & Dynamics
365 Security Review (8 domains, 29 checks) plus ranked technical findings.

Give the reader a short, ranked action plan, not a restatement of the data. Rank by:
  1) things that blind you (auditing off, no logs, MFA the platform cannot see, legacy protocols),
  2) internet-exposed or high-blast-radius access (open RDP/SSH, public SQL, too many admins, standing admin, expiring privileged credentials),
  3) over-permissioned identities (apps with tenant-wide write or all-mail, no MFA/Conditional Access, broad guests, no DLP),
  4) least-privilege and hygiene.

For each item give four things: WHAT it is (one sentence), WHY it matters, the FIX (the exact
Microsoft setting or admin-center path), and EFFORT (quick config change vs a project). Then
stop and offer to go deeper on any one.

Rules: explain the fix, do not perform it. A finding is a gap, not a proven breach. Prefer the
smallest change that closes the gap. Treat "Not checked" as unknown, never as fine.
'@

# --- local mode: write a ready bundle, no network ---
if ($mode -eq 'local') {
    $p = Join-Path $out 'ai-analysis-prompt.md'
    Set-Content -Path $p -Value "$prompt`n`n---`n`n$material`n" -Encoding utf8
    Write-Host ""
    Write-Host "AI analysis (local): wrote $p  (scope: $scope, nothing left this machine)." -ForegroundColor Green
    Write-Host "Hand it to your own Claude Code / Kimi / Codex session - AGENTS.md tells it how to analyze safely." -ForegroundColor DarkGray
    return
}

# --- api mode: send to the configured OpenAI-compatible endpoint ---
$url = Get-Conf 'AI_API_URL'; $key = Get-Conf 'AI_API_KEY'; $model = Get-Conf 'AI_MODEL'
if (-not ($url -and $key -and $model)) {
    Write-Warning "ai-analysis: AI_ANALYSIS=api needs AI_API_URL, AI_API_KEY and AI_MODEL in .env. Skipping."
    return
}
$apiHost = try { ([Uri]$url).Host } catch { $url }
Write-Host ""
Write-Host "AI analysis (api): sending the '$scope' findings to $apiHost." -ForegroundColor Yellow
Write-Host "This is the ONLY thing the tool sends off-machine, and only because AI_ANALYSIS=api is set." -ForegroundColor Yellow
$maxTok = "$(Get-Conf 'AI_MAX_TOKENS')".Trim(); if ($maxTok -notmatch '^\d+$') { $maxTok = '4000' }
$body = @{ model = $model; max_tokens = [int]$maxTok; messages = @(
    @{ role = 'system'; content = $prompt }, @{ role = 'user'; content = $material }
) } | ConvertTo-Json -Depth 8
try {
    $resp = Invoke-RestMethod -Method Post -Uri $url -Headers @{ Authorization = "Bearer $key" } -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
    $answer = $resp.choices[0].message.content
    if (-not $answer) { Write-Warning "ai-analysis: empty response from $apiHost."; return }
    $p = Join-Path $out 'ai-analysis.md'
    Set-Content -Path $p -Value "# AI analysis (mitigation guidance)`n`n_Model: $model via $apiHost. Scope: $scope._`n`n$answer`n" -Encoding utf8
    Write-Host "Wrote $p" -ForegroundColor Green
} catch {
    Write-Warning "ai-analysis: API call to $apiHost failed: $($_.Exception.Message)"
}
