# azure-plus.ps1 - extra read-only Azure resource-plane (ARM) checks for monitoring + integrations.
# Covers: Defender for Cloud pricing plans (Standard vs Free), Log Analytics workspaces and
# per-workspace Microsoft Sentinel onboarding, subscription activity-log diagnostic settings,
# and Logic Apps (integration workflows).
# Read-only. GET/paged reads only. Every area is isolated so one failure never stops the sweep.

. (Join-Path $PSScriptRoot '_common.ps1')

$tok = Get-Token 'https://management.azure.com'
if (-not $tok) { throw 'No Azure ARM token.' }
$H = @{ Authorization = "Bearer $tok" }
function Get-Arm($url) { $i=@(); $n=$url; while($n){ $r=Invoke-RestMethod -Uri $n -Headers $H; if($r.value){$i+=$r.value}; $n=$r.nextLink }; return $i }

$subsConf = (Get-Conf AZURE_SUBSCRIPTIONS) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$allSubs = Get-Arm 'https://management.azure.com/subscriptions?api-version=2022-12-01'
$subs = if ($subsConf) { $allSubs | Where-Object { $subsConf -contains $_.subscriptionId } } else { $allSubs }
Write-Host "Azure+: auditing $(@($subs).Count) subscription(s)" -ForegroundColor Cyan

foreach ($s in $subs) {
    $sid = $s.subscriptionId; $base = "https://management.azure.com/subscriptions/$sid"
    $safe = ($s.displayName -replace '[^A-Za-z0-9]','_')
    Write-Host "  $($s.displayName)" -ForegroundColor Cyan

    $defenderStandard = 0; $sentinelOn = 0; $logicCount = 0

    # --- Defender for Cloud pricing plans -------------------------------------
    Write-Host '    Defender for Cloud pricing plans...' -ForegroundColor Cyan
    try {
        $pricings = Get-Arm "$base/providers/Microsoft.Security/pricings?api-version=2023-01-01"
        $defenderStandard = @($pricings | Where-Object { $_.properties.pricingTier -eq 'Standard' }).Count
        Save-Json $pricings "arm-$safe-defender-pricings.json" | Out-Null
        Write-Host "      $defenderStandard of $(@($pricings).Count) plan(s) on Standard tier" -ForegroundColor Yellow
    } catch {
        Write-Warning "    Defender pricings failed: $($_.Exception.Message)"
        Save-Json @{ error = $_.Exception.Message } "arm-$safe-defender-pricings-ERROR.json" | Out-Null
    }

    # --- Log Analytics workspaces ---------------------------------------------
    $ws = @()
    Write-Host '    Log Analytics workspaces...' -ForegroundColor Cyan
    try {
        $ws = Get-Arm "$base/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01"
        Save-Json $ws "arm-$safe-loganalytics.json" | Out-Null
        Write-Host "      $(@($ws).Count) workspace(s)" -ForegroundColor Yellow
    } catch {
        Write-Warning "    Log Analytics failed: $($_.Exception.Message)"
        Save-Json @{ error = $_.Exception.Message } "arm-$safe-loganalytics-ERROR.json" | Out-Null
    }

    # --- Microsoft Sentinel onboarding (per workspace) ------------------------
    Write-Host '    Microsoft Sentinel onboarding...' -ForegroundColor Cyan
    try {
        $sentinel = foreach ($w in $ws) {
            $enabled = $false; $err = $null
            try {
                Invoke-RestMethod -Uri "https://management.azure.com$($w.id)/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01" -Headers $H | Out-Null
                $enabled = $true
            } catch {
                $code = $null
                try { $code = [int]$_.Exception.Response.StatusCode } catch {}
                if ($code -ne 404) { $err = $_.Exception.Message }
            }
            [pscustomobject]@{ workspace = $w.name; workspaceId = $w.id; location = $w.location; sentinelEnabled = $enabled; error = $err }
        }
        $sentinel = @($sentinel)
        $sentinelOn = @($sentinel | Where-Object { $_.sentinelEnabled }).Count
        Save-Json $sentinel "arm-$safe-sentinel.json" | Out-Null
        Write-Host "      Sentinel enabled on $sentinelOn of $(@($ws).Count) workspace(s)" -ForegroundColor Yellow
    } catch {
        Write-Warning "    Sentinel onboarding failed: $($_.Exception.Message)"
        Save-Json @{ error = $_.Exception.Message } "arm-$safe-sentinel-ERROR.json" | Out-Null
    }

    # --- Subscription activity-log diagnostic settings ------------------------
    Write-Host '    Activity-log diagnostic settings...' -ForegroundColor Cyan
    try {
        $diag = Get-Arm "$base/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
        Save-Json $diag "arm-$safe-diagnostic-settings.json" | Out-Null
        Write-Host "      $(@($diag).Count) diagnostic setting(s)" -ForegroundColor Yellow
    } catch {
        Write-Warning "    Diagnostic settings failed: $($_.Exception.Message)"
        Save-Json @{ error = $_.Exception.Message } "arm-$safe-diagnostic-settings-ERROR.json" | Out-Null
    }

    # --- Logic Apps (integration workflows) -----------------------------------
    Write-Host '    Logic Apps...' -ForegroundColor Cyan
    try {
        $logic = Get-Arm "$base/providers/Microsoft.Logic/workflows?api-version=2016-06-01"
        $logicInfo = foreach ($la in $logic) {
            $rg = if ($la.id -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { $null }
            [pscustomobject]@{ name = $la.name; location = $la.location; resourceGroup = $rg; state = $la.properties.state; id = $la.id }
        }
        $logicInfo = @($logicInfo)
        $logicCount = $logicInfo.Count
        Save-Json $logicInfo "arm-$safe-logicapps.json" | Out-Null
        Write-Host "      $logicCount logic app workflow(s)" -ForegroundColor Yellow
    } catch {
        Write-Warning "    Logic Apps failed: $($_.Exception.Message)"
        Save-Json @{ error = $_.Exception.Message } "arm-$safe-logicapps-ERROR.json" | Out-Null
    }

    Write-Host "    Summary: Sentinel on $sentinelOn workspace(s); $defenderStandard Defender plan(s) Standard; $logicCount logic app(s)" -ForegroundColor Magenta
}

Write-Host 'Azure+ sweep done.' -ForegroundColor Green