# azure-plus.ps1 - extra read-only Azure resource-plane (ARM) checks for monitoring + integrations.
# Covers: Defender for Cloud pricing plans (Standard vs Free), Log Analytics workspaces and
# per-workspace Microsoft Sentinel onboarding, subscription activity-log diagnostic settings,
# and Logic Apps (integration workflows).
# Read-only. GET/paged reads only. Every area is isolated so one failure never stops the sweep.
#
# Scope: the same resolved selection as azure-sweep.ps1. Log Analytics (with Sentinel) and Logic
# Apps are resource readers: listed per selected resource group, skippable by type. Defender
# plans and diagnostic settings are subscription-wide and always run for every selected subscription.

. (Join-Path $PSScriptRoot '_common.ps1')

$tok = Get-Token 'https://management.azure.com'
if (-not $tok) { Write-Warning 'No Azure ARM token - skipping the Azure+ sweep; other steps still run.'; return }
$H = @{ Authorization = "Bearer $tok" }
function Get-Arm($url) { $i=@(); $n=$url; while($n){ $r=Invoke-RestMethod -Uri $n -Headers $H; if($r.value){$i+=$r.value}; $n=$r.nextLink }; return $i }
function Get-ArmScoped($base, $groups, $providerPath) { $items = @(); foreach ($u in @(Get-ArmListUrls $base $groups $providerPath)) { $items += @(Get-Arm $u) }; return $items }

$scope = Read-ScopeEffective
try { $allSubs = @(Get-Arm 'https://management.azure.com/subscriptions?api-version=2022-12-01') }
catch { $why = Get-ErrorText $_; Write-Warning "Could not list subscriptions: $why"; Save-Json @{ error = $why } 'arm-subscriptions-ERROR.json' | Out-Null; return }
$subs = @(Select-ScopedSubscriptions $scope $allSubs)
$invisible = @(Get-ScopeInvisibleSubscriptions $scope $allSubs)
if ($invisible.Count -gt 0) { Write-Warning "Azure+: $($invisible.Count) selected subscription(s) not visible to the app: $($invisible -join ', ')" }
Write-Host "Azure+: auditing $($subs.Count) of $($allSubs.Count) visible subscription(s)" -ForegroundColor Cyan
$rgSelected = @(Get-ScopeItems $scope.azure.resourceGroups)
$safeNames = Get-SubscriptionSafeNames $allSubs

foreach ($s in $subs) {
    $sid = $s.subscriptionId; $base = "https://management.azure.com/subscriptions/$sid"
    $safe = $safeNames["$sid"]
    Write-Host "  $($s.displayName)" -ForegroundColor Cyan

    $groups = $null
    if ($rgSelected.Count -gt 0) {
        $names = @()
        try { $names = @(@(Get-Arm "$base/resourcegroups?api-version=2021-04-01") | ForEach-Object { "$($_.name)" }) }
        catch { Write-Warning "    resource groups could not be listed: $(Get-ErrorText $_)" }
        $groups = Select-ScopedResourceGroups $scope $names
        Write-Host "    resource groups in scope here: $(@($groups).Count) of $($names.Count) (Defender plans and diagnostic settings are subscription-wide)" -ForegroundColor Yellow
    }

    $defenderStandard = 0; $sentinelOn = 0; $logicCount = 0

    # --- Defender for Cloud pricing plans (subscription-wide) -------------------
    Write-Host '    Defender for Cloud pricing plans...' -ForegroundColor Cyan
    try {
        $pricings = Get-Arm "$base/providers/Microsoft.Security/pricings?api-version=2023-01-01"
        $defenderStandard = @($pricings | Where-Object { $_.properties.pricingTier -eq 'Standard' }).Count
        Save-Json $pricings "arm-$safe-defender-pricings.json" | Out-Null
        Write-Host "      $defenderStandard of $(@($pricings).Count) plan(s) on Standard tier" -ForegroundColor Yellow
    } catch {
        $why = Get-ErrorText $_
        if ($why -match '\b404\b') {
            # The Microsoft.Security provider is not registered: Defender for Cloud was never turned on here.
            Save-Json @() "arm-$safe-defender-pricings.json" | Out-Null
            Write-Host '      Defender for Cloud has never been enabled on this subscription (no plans; the Microsoft.Security provider is not registered).' -ForegroundColor Yellow
        } else {
            Write-Warning "    Defender pricings failed: $why"
            Save-Json @{ error = $why } "arm-$safe-defender-pricings-ERROR.json" | Out-Null
        }
    }

    # --- Log Analytics workspaces + Sentinel onboarding (resource reader) --------
    $ws = @()
    if (Test-ScopedReader $scope 'loganalytics') {
        Write-Host '    Log Analytics workspaces...' -ForegroundColor Cyan
        try {
            $ws = @(Select-ScopedResources $scope 'loganalytics' (Get-ArmScoped $base $groups 'Microsoft.OperationalInsights/workspaces?api-version=2022-10-01'))
            Save-Json $ws "arm-$safe-loganalytics.json" | Out-Null
            Write-Host "      $($ws.Count) workspace(s)" -ForegroundColor Yellow
        } catch {
            Write-Warning "    Log Analytics failed: $(Get-ErrorText $_)"
            Save-Json @{ error = (Get-ErrorText $_) } "arm-$safe-loganalytics-ERROR.json" | Out-Null
        }

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
                    if ($code -ne 404) { $err = (Get-ErrorText $_) }
                }
                [pscustomobject]@{ workspace = $w.name; workspaceId = $w.id; location = $w.location; sentinelEnabled = $enabled; error = $err }
            }
            $sentinel = @($sentinel)
            $sentinelOn = @($sentinel | Where-Object { $_.sentinelEnabled }).Count
            Save-Json $sentinel "arm-$safe-sentinel.json" | Out-Null
            Write-Host "      Sentinel enabled on $sentinelOn of $($ws.Count) workspace(s)" -ForegroundColor Yellow
        } catch {
            Write-Warning "    Sentinel onboarding failed: $(Get-ErrorText $_)"
            Save-Json @{ error = (Get-ErrorText $_) } "arm-$safe-sentinel-ERROR.json" | Out-Null
        }
    } else { Write-Host '    Log Analytics / Sentinel: skipped by scope (types)' -ForegroundColor DarkGray }

    # --- Subscription activity-log diagnostic settings (subscription-wide) ------
    Write-Host '    Activity-log diagnostic settings...' -ForegroundColor Cyan
    try {
        $diag = Get-Arm "$base/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
        Save-Json $diag "arm-$safe-diagnostic-settings.json" | Out-Null
        Write-Host "      $(@($diag).Count) diagnostic setting(s)" -ForegroundColor Yellow
    } catch {
        Write-Warning "    Diagnostic settings failed: $(Get-ErrorText $_)"
        Save-Json @{ error = (Get-ErrorText $_) } "arm-$safe-diagnostic-settings-ERROR.json" | Out-Null
    }

    # --- Logic Apps (integration workflows; resource reader) ---------------------
    if (Test-ScopedReader $scope 'logicapps') {
        Write-Host '    Logic Apps...' -ForegroundColor Cyan
        try {
            $logic = @(Select-ScopedResources $scope 'logicapps' (Get-ArmScoped $base $groups 'Microsoft.Logic/workflows?api-version=2016-06-01'))
            # Triggers (type 'Request' = callable over HTTP) and who may call them: no
            # accessControl = any IP; an empty allowedCallerIpAddresses list = only other Logic
            # Apps; a list = those ranges. An Entra ID authorization policy is noted separately.
            $logicInfo = foreach ($la in $logic) {
                $rg = if ($la.id -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { $null }
                $trig = @()
                $defT = $la.properties.definition.triggers
                if ($defT) { foreach ($tp in @($defT.PSObject.Properties)) { $trig += [pscustomobject]@{ name = $tp.Name; type = "$($tp.Value.type)"; kind = "$($tp.Value.kind)" } } }
                $ac = $la.properties.accessControl.triggers
                $callers = 'any'; $ips = @()
                if ($ac -and ($ac.PSObject.Properties.Name -contains 'allowedCallerIpAddresses')) {
                    $ips = @(@($ac.allowedCallerIpAddresses) | Where-Object { $_ } | ForEach-Object { "$($_.addressRange)" })
                    $callers = if ($ips.Count) { 'ip-list' } else { 'logic-apps-only' }
                }
                $entra = [bool]($ac -and $ac.openAuthenticationPolicies -and $ac.openAuthenticationPolicies.policies -and @($ac.openAuthenticationPolicies.policies.PSObject.Properties).Count)
                $sasOff = [bool]($ac -and $ac.sasAuthenticationPolicy -and "$($ac.sasAuthenticationPolicy.state)" -eq 'Disabled')
                [pscustomobject]@{ name = $la.name; location = $la.location; resourceGroup = $rg; state = $la.properties.state; id = $la.id; triggers = $trig; callers = $callers; allowedCallerIps = $ips; entraAuthPolicy = $entra; sasDisabled = $sasOff }
            }
            $logicInfo = @($logicInfo)
            $logicCount = $logicInfo.Count
            Save-Json $logicInfo "arm-$safe-logicapps.json" | Out-Null
            Write-Host "      $logicCount logic app workflow(s)" -ForegroundColor Yellow
        } catch {
            Write-Warning "    Logic Apps failed: $(Get-ErrorText $_)"
            Save-Json @{ error = (Get-ErrorText $_) } "arm-$safe-logicapps-ERROR.json" | Out-Null
        }
    } else { Write-Host '    Logic Apps: skipped by scope (types)' -ForegroundColor DarkGray }

    Write-Host "    Summary: Sentinel on $sentinelOn workspace(s); $defenderStandard Defender plan(s) Standard; $logicCount logic app(s)" -ForegroundColor Magenta
}

Write-Host 'Azure+ sweep done.' -ForegroundColor Green
