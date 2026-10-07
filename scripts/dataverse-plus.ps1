# dataverse-plus.ps1 - extra read-only per-environment Dataverse checks.
# Covers: broader org security settings (auditing + read-log auditing + user-access
# auditing + plugin trace), the IP firewall, email server profiles, queue + mailbox surface
# (server-side sync), and field-level security usage (fieldpermissions).
#
# Environments: the same resolved list as dataverse-sweep.ps1 (run-audit.ps1 -Environments >
# scope.json > DATAVERSE_ENVIRONMENTS in .env, as URLs, environment ids or display names).
# With no selection, every environment the Power Platform sweep discovered with a Dataverse
# URL (output/pp-environment-urls.json). The app must be an Application User with a read-only
# role in each environment. Read-only. GET/paged reads only. Every environment and every query
# is isolated in its own try/catch so one failure (missing license / no access) never stops
# the sweep.
#
# $select column names are verified against the Dataverse table references
# (organization, emailserverprofile). One invalid column 400s the whole query and the
# *-ERROR.json keeps the OData message that names it. A 403 names the missing privilege, or
# means no Application User. The queries live in _common.ps1 ($DvReads), shared with the setup
# check that probes each one before the sweep runs.

. (Join-Path $PSScriptRoot '_common.ps1')

# --- The environment list in scope (shared resolution with dataverse-sweep.ps1) ----
$scope = Read-ScopeEffective
$res = Resolve-ScopeEnvironments $scope
$envs = @(@($res.environments) | ForEach-Object { $_.url })
if (@($res.unresolved).Count -gt 0) {
    Write-Warning "Dataverse+: $(@($res.unresolved).Count) selected environment(s) could not be resolved to a URL: $(@($res.unresolved) -join ', '). Use the instance URL, or run the Power Platform sweep first so ids and display names resolve."
}
if ($envs.Count -eq 0) {
    Write-Warning 'No Dataverse environments selected or discovered (DATAVERSE_ENVIRONMENTS, scope.json, -Environments, or the Power Platform sweep) - skipping dataverse-plus.'
    return
}
Write-Host "Dataverse+: $($envs.Count) environment(s) to check$(if($res.selected -gt 0){' (selected by scope)'}else{' (discovered)'})." -ForegroundColor Cyan
Update-ScopeEffective {
    param($x)
    Set-ScopeField $x.powerPlatform 'discoveredEnvironments' $res.discovered
    Set-ScopeField $x.powerPlatform 'resolved' @($res.environments)
    Set-ScopeField $x.powerPlatform 'unresolved' @($res.unresolved)
} | Out-Null

# Short, filesystem-safe name from the host (first DNS label).
function Get-SafeName($url) {
    try { $h = ([Uri]$url).Host } catch { $h = $null }
    if (-not $h) { $h = ($url -replace 'https?://', '') }
    $name = ($h -split '\.')[0]
    $name = $name -replace '[^A-Za-z0-9_-]', '-'
    if (-not $name) { $name = 'env' }
    return $name
}

foreach ($url in $envs) {
    $safe = Get-SafeName $url
    Write-Host "Dataverse+: $safe ($url)" -ForegroundColor Cyan
    try {
        $tok = Get-Token $url
        if (-not $tok) {
            Write-Warning "  [$safe] no token for $url - skipping."
        } else {
            $H    = @{ Authorization = "Bearer $tok"; Accept = 'application/json'; 'OData-Version' = '4.0' }
            $Hc   = @{ Authorization = "Bearer $tok"; Accept = 'application/json'; 'OData-Version' = '4.0'; Prefer = 'odata.include-annotations="*"' }
            $base = "$url/api/data/v9.2/"

            # one-line summary accumulators
            $sumAudit    = '?'
            $sumProfiles = '?'
            $sumQueues   = '?'
            $sumMailbox  = '?'
            $sumFieldPrm = '?'

            # --- Org security settings (broader) ---------------------------------
            try {
                $org = Invoke-Paged "$base$($script:DvReads.orgplus.Path)" $H
                Save-Json $org "dvplus-$safe-org-settings.json" | Out-Null
                $o = @($org)[0]
                if ($o) { $sumAudit = $o.isauditenabled }
            } catch {
                $e = Get-ErrorText $_
                Write-Warning "  [$safe] org-settings failed: $e"
                Save-Json @{ error = $e } "dvplus-$safe-org-settings-ERROR.json" | Out-Null
            }

            # --- IP firewall (a Managed Environments feature) -----------------------
            try {
                $fwo = Invoke-Paged "$base$($script:DvReads.ipfirewall.Path)" $H
                Save-Json $fwo "dvplus-$safe-ipfirewall.json" | Out-Null
            } catch {
                $e = Get-ErrorText $_
                Write-Warning "  [$safe] IP firewall settings failed: $e"
                Save-Json @{ error = $e } "dvplus-$safe-ipfirewall-ERROR.json" | Out-Null
            }

            # --- Email server profiles -------------------------------------------
            try {
                # servertype + statecode are the documented columns (there is no 'type' column,
                # which is what 400'd this query before). Annotations add the display labels.
                $profiles = Invoke-Paged "$base$($script:DvReads.emailprofiles.Path)" $Hc
                Save-Json $profiles "dvplus-$safe-emailprofiles.json" | Out-Null
                $sumProfiles = @($profiles).Count
            } catch {
                $e = Get-ErrorText $_
                Write-Warning "  [$safe] emailprofiles failed: $e"
                Save-Json @{ error = $e } "dvplus-$safe-emailprofiles-ERROR.json" | Out-Null
            }

            # --- Queues (count + small sample) -----------------------------------
            try {
                $r = Invoke-RestMethod -Uri "$base$($script:DvReads.queues.Path)" -Headers $Hc
                $cnt = $r.'@odata.count'
                Save-Json ([ordered]@{ '@odata.count' = $cnt; sample = @($r.value) }) "dvplus-$safe-queues.json" | Out-Null
                if ($null -ne $cnt) { $sumQueues = $cnt } else { $sumQueues = @($r.value).Count }
            } catch {
                $e = Get-ErrorText $_
                Write-Warning "  [$safe] queues failed: $e"
                Save-Json @{ error = $e } "dvplus-$safe-queues-ERROR.json" | Out-Null
            }

            # --- Mailboxes (count + small sample) --------------------------------
            try {
                $r = Invoke-RestMethod -Uri "$base$($script:DvReads.mailboxes.Path)" -Headers $Hc
                $cnt = $r.'@odata.count'
                Save-Json ([ordered]@{ '@odata.count' = $cnt; sample = @($r.value) }) "dvplus-$safe-mailboxes.json" | Out-Null
                if ($null -ne $cnt) { $sumMailbox = $cnt } else { $sumMailbox = @($r.value).Count }
            } catch {
                $e = Get-ErrorText $_
                Write-Warning "  [$safe] mailboxes failed: $e"
                Save-Json @{ error = $e } "dvplus-$safe-mailboxes-ERROR.json" | Out-Null
            }

            # --- Field permissions (field-level security in use) -----------------
            try {
                $fp = Invoke-Paged "$base$($script:DvReads.fieldperms.Path)" $H
                Save-Json $fp "dvplus-$safe-fieldpermissions.json" | Out-Null
                $sumFieldPrm = @($fp).Count
            } catch {
                $e = Get-ErrorText $_
                Write-Warning "  [$safe] fieldpermissions failed: $e"
                Save-Json @{ error = $e } "dvplus-$safe-fieldpermissions-ERROR.json" | Out-Null
            }

            Write-Host "  [$safe] audit=$sumAudit emailProfiles=$sumProfiles queues=$sumQueues mailboxes=$sumMailbox fieldPerms=$sumFieldPrm" -ForegroundColor Yellow
        }
    } catch {
        $e = Get-ErrorText $_
        Write-Warning "  [$safe] failed: $e"
        Save-Json @{ error = $e } "dvplus-$safe-ERROR.json" | Out-Null
    }
}

Write-Host 'Dataverse+ sweep done.' -ForegroundColor Green
