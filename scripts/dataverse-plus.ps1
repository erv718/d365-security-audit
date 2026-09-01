# dataverse-plus.ps1 - extra read-only per-environment Dataverse checks.
# Covers: broader org security settings (auditing + user-access auditing + plugin trace),
# email server profiles, queue + mailbox surface (server-side sync), and field-level
# security usage (fieldpermissions).
#
# Environment URLs come from DATAVERSE_ENVIRONMENTS in .env (comma-separated) AND, if
# present, from output/pp-environment-urls.json (auto-discovered by the Power Platform
# sweep). The app (or your az login identity) must have a read role in each environment.
# Read-only. GET/paged reads only. Every environment and every query is isolated in its
# own try/catch so one failure (missing license / no access) never stops the sweep.

. (Join-Path $PSScriptRoot '_common.ps1')

# --- Gather environment URLs: .env list + auto-discovered file ----------------
$envs = @()
$envs += (Get-Conf DATAVERSE_ENVIRONMENTS) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

$discovered = Join-Path (Get-OutDir) 'pp-environment-urls.json'
if (Test-Path $discovered) {
    try {
        $fromFile = Get-Content $discovered -Raw | ConvertFrom-Json
        $envs += @($fromFile) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }
        Write-Host "Dataverse+: picked up auto-discovered URLs from $discovered" -ForegroundColor Cyan
    } catch {
        Write-Warning "Could not read $discovered : $($_.Exception.Message)"
    }
}

# Normalise (drop trailing slash) and de-duplicate (case-insensitive).
$envs = @($envs | ForEach-Object { $_.TrimEnd('/') } | Select-Object -Unique)
if (-not $envs) {
    Write-Warning 'No Dataverse environment URLs (DATAVERSE_ENVIRONMENTS / pp-environment-urls.json) - skipping dataverse-plus.'
    return
}
Write-Host "Dataverse+: $(@($envs).Count) environment(s) to check." -ForegroundColor Cyan

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
                $org = Invoke-Paged "${base}organizations?`$select=name,isauditenabled,isuseraccessauditenabled,auditretentionperiodv2,plugintracelogsetting,ismailboxforfeaturesenabled" $H
                Save-Json $org "dvplus-$safe-org-settings.json" | Out-Null
                $o = @($org)[0]
                if ($o) { $sumAudit = $o.isauditenabled }
            } catch {
                Write-Warning "  [$safe] org-settings failed: $($_.Exception.Message)"
                Save-Json @{ error = $_.Exception.Message } "dvplus-$safe-org-settings-ERROR.json" | Out-Null
            }

            # --- Email server profiles -------------------------------------------
            try {
                $profiles = Invoke-Paged "${base}emailserverprofiles?`$select=name,type" $H
                Save-Json $profiles "dvplus-$safe-emailprofiles.json" | Out-Null
                $sumProfiles = @($profiles).Count
            } catch {
                Write-Warning "  [$safe] emailprofiles failed: $($_.Exception.Message)"
                Save-Json @{ error = $_.Exception.Message } "dvplus-$safe-emailprofiles-ERROR.json" | Out-Null
            }

            # --- Queues (count + small sample) -----------------------------------
            try {
                $r = Invoke-RestMethod -Uri "${base}queues?`$select=name&`$top=5&`$count=true" -Headers $Hc
                $cnt = $r.'@odata.count'
                Save-Json ([ordered]@{ '@odata.count' = $cnt; sample = @($r.value) }) "dvplus-$safe-queues.json" | Out-Null
                if ($null -ne $cnt) { $sumQueues = $cnt } else { $sumQueues = @($r.value).Count }
            } catch {
                Write-Warning "  [$safe] queues failed: $($_.Exception.Message)"
                Save-Json @{ error = $_.Exception.Message } "dvplus-$safe-queues-ERROR.json" | Out-Null
            }

            # --- Mailboxes (count + small sample) --------------------------------
            try {
                $r = Invoke-RestMethod -Uri "${base}mailboxes?`$select=name,statecode&`$top=5&`$count=true" -Headers $Hc
                $cnt = $r.'@odata.count'
                Save-Json ([ordered]@{ '@odata.count' = $cnt; sample = @($r.value) }) "dvplus-$safe-mailboxes.json" | Out-Null
                if ($null -ne $cnt) { $sumMailbox = $cnt } else { $sumMailbox = @($r.value).Count }
            } catch {
                Write-Warning "  [$safe] mailboxes failed: $($_.Exception.Message)"
                Save-Json @{ error = $_.Exception.Message } "dvplus-$safe-mailboxes-ERROR.json" | Out-Null
            }

            # --- Field permissions (field-level security in use) -----------------
            try {
                $fp = Invoke-Paged "${base}fieldpermissions?`$select=attributelogicalname,fieldsecurityprofileid" $H
                Save-Json $fp "dvplus-$safe-fieldpermissions.json" | Out-Null
                $sumFieldPrm = @($fp).Count
            } catch {
                Write-Warning "  [$safe] fieldpermissions failed: $($_.Exception.Message)"
                Save-Json @{ error = $_.Exception.Message } "dvplus-$safe-fieldpermissions-ERROR.json" | Out-Null
            }

            Write-Host "  [$safe] audit=$sumAudit emailProfiles=$sumProfiles queues=$sumQueues mailboxes=$sumMailbox fieldPerms=$sumFieldPrm" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "  [$safe] failed: $($_.Exception.Message)"
        Save-Json @{ error = $_.Exception.Message } "dvplus-$safe-ERROR.json" | Out-Null
    }
}

Write-Host 'Dataverse+ sweep done.' -ForegroundColor Green
