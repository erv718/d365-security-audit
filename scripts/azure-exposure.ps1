# azure-exposure.ps1 - read-only pull of what the Azure estate exposes, per subscription.
# Covers: the full resource inventory (coverage, and the cross-check against a portal inventory
# export), storage accounts (network rules, anonymous blob access, TLS, shared keys), virtual
# machines with their network interfaces, public IPs and subnets (which VM is on the internet,
# and whether any NSG covers it), App Service and Function Apps (HTTPS, TLS, FTP, remote
# debugging, access restrictions, HTTP functions that need no key), Automation accounts
# (runbooks, retired Run As connections) and API connections (which account each one signs in as).
#
# The Reader role on the subscriptions (or on the selected resource groups) covers every read.
# GET only: no keys, no app settings, no connection secrets are ever requested. Scope: the same
# resolved selection as azure-sweep.ps1; the inventory is subscription-wide (or per selected
# group), the rest are resource readers skippable by type. Every area is isolated: a failure
# leaves arm-<sub>-<area>-ERROR.json and the sweep carries on.

. (Join-Path $PSScriptRoot '_common.ps1')

$tok = Get-Token 'https://management.azure.com'
if (-not $tok) { Write-Warning 'No Azure ARM token - skipping the Azure exposure sweep; other steps still run.'; return }
$H = @{ Authorization = "Bearer $tok" }
$Arm = 'https://management.azure.com'
function Get-Arm($url) { $i=@(); $n=$url; while($n){ $r=Invoke-RestMethod -Uri $n -Headers $H; if($r.value){$i+=$r.value}; $n=$r.nextLink }; return $i }
function Get-ArmScoped($base, $groups, $providerPath) { $items = @(); foreach ($u in @(Get-ArmListUrls $base $groups $providerPath)) { $items += @(Get-Arm $u) }; return $items }
function Get-RgName($id) { if ("$id" -match '/resourceGroups/([^/]+)/') { return $Matches[1] }; return $null }
# One area = one try/catch and one file. Returns the saved items (an array), or $null on failure.
function Save-Area($safe, $area, [scriptblock]$Read) {
    try {
        $data = @(& $Read)
        Save-Json $data "arm-$safe-$area.json" | Out-Null
        return ,$data
    } catch {
        $why = Get-ErrorText $_
        Write-Warning "    $area failed: $why"
        Save-Json @{ error = $why } "arm-$safe-$area-ERROR.json" | Out-Null
        return $null
    }
}
function N($x) { if ($null -eq $x) { return '?' }; return @($x).Count }

$scope = Read-ScopeEffective
try { $allSubs = @(Get-Arm "$Arm/subscriptions?api-version=2022-12-01") }
catch { $why = Get-ErrorText $_; Write-Warning "Could not list subscriptions: $why"; Save-Json @{ error = $why } 'arm-subscriptions-ERROR.json' | Out-Null; return }
$subs = @(Select-ScopedSubscriptions $scope $allSubs)
Write-Host "Azure exposure: auditing $($subs.Count) of $($allSubs.Count) visible subscription(s)" -ForegroundColor Cyan
$rgSelected = @(Get-ScopeItems $scope.azure.resourceGroups)
$safeNames = Get-SubscriptionSafeNames $allSubs

foreach ($s in $subs) {
    $sid = $s.subscriptionId; $base = "$Arm/subscriptions/$sid"
    $safe = $safeNames["$sid"]
    Write-Host "  $($s.displayName)" -ForegroundColor Cyan

    $groups = $null
    if ($rgSelected.Count -gt 0) {
        $names = @()
        try { $names = @(@(Get-Arm "$base/resourcegroups?api-version=2021-04-01") | ForEach-Object { "$($_.name)" }) }
        catch { Write-Warning "    resource groups could not be listed: $($_.Exception.Message)" }
        $groups = Select-ScopedResourceGroups $scope $names
    }

    # --- Resource inventory (every resource the app can see in scope) ---------------
    $inv = Save-Area $safe 'resources' {
        $urls = if ($null -eq $groups) { @("$base/resources?api-version=2021-04-01") } else { @(@($groups) | ForEach-Object { "$base/resourceGroups/$_/resources?api-version=2021-04-01" }) }
        foreach ($u in $urls) {
            foreach ($r in @(Get-Arm $u)) { [pscustomobject]@{ name = $r.name; type = $r.type; kind = $r.kind; location = $r.location; resourceGroup = (Get-RgName $r.id); id = $r.id } }
        }
    }
    Write-Host "    inventory: $(N $inv) resource(s)" -ForegroundColor Yellow

    # --- Storage accounts --------------------------------------------------------------
    if (Test-ScopedReader $scope 'storage') {
        $st = Save-Area $safe 'storage' {
            foreach ($a in @(Select-ScopedResources $scope 'storage' (Get-ArmScoped $base $groups 'Microsoft.Storage/storageAccounts?api-version=2023-05-01'))) {
                $p = $a.properties
                [pscustomobject]@{
                    id = $a.id; name = $a.name; kind = $a.kind; location = $a.location
                    publicNetworkAccess = $p.publicNetworkAccess; defaultAction = "$($p.networkAcls.defaultAction)"; bypass = "$($p.networkAcls.bypass)"
                    ipRules = @(@($p.networkAcls.ipRules) | Where-Object { $_ } | ForEach-Object { "$($_.value)" })
                    vnetRules = @($p.networkAcls.virtualNetworkRules | Where-Object { $_ }).Count; privateEndpoints = @($p.privateEndpointConnections | Where-Object { $_ }).Count
                    allowBlobPublicAccess = $p.allowBlobPublicAccess; allowSharedKeyAccess = $p.allowSharedKeyAccess
                    minimumTlsVersion = $p.minimumTlsVersion; supportsHttpsTrafficOnly = $p.supportsHttpsTrafficOnly
                }
            }
        }
        Write-Host "    storage accounts: $(N $st)" -ForegroundColor Yellow
    } else { Write-Host '    Storage: skipped by scope (types)' -ForegroundColor DarkGray }

    # --- Virtual machines, network interfaces, public IPs, subnets ---------------------
    if (Test-ScopedReader $scope 'vm') {
        $vms = Save-Area $safe 'vms' {
            foreach ($v in @(Select-ScopedResources $scope 'vm' (Get-ArmScoped $base $groups 'Microsoft.Compute/virtualMachines?api-version=2024-03-01'))) {
                [pscustomobject]@{ id = $v.id; name = $v.name; location = $v.location; vmSize = $v.properties.hardwareProfile.vmSize; osType = $v.properties.storageProfile.osDisk.osType; identity = "$($v.identity.type)"; nics = @(@($v.properties.networkProfile.networkInterfaces) | ForEach-Object { "$($_.id)" }) }
            }
        }
        $nics = Save-Area $safe 'nics' {
            foreach ($n in @(Get-ArmScoped $base $groups 'Microsoft.Network/networkInterfaces?api-version=2023-09-01')) {
                [pscustomobject]@{ id = $n.id; name = $n.name; vm = "$($n.properties.virtualMachine.id)"; nsg = "$($n.properties.networkSecurityGroup.id)"
                    ipConfigs = @(@($n.properties.ipConfigurations) | ForEach-Object { [pscustomobject]@{ subnet = "$($_.properties.subnet.id)"; publicIp = "$($_.properties.publicIPAddress.id)"; privateIp = "$($_.properties.privateIPAddress)" } }) }
            }
        }
        $pips = Save-Area $safe 'publicips' {
            foreach ($p in @(Get-ArmScoped $base $groups 'Microsoft.Network/publicIPAddresses?api-version=2023-09-01')) {
                [pscustomobject]@{ id = $p.id; name = $p.name; ipAddress = "$($p.properties.ipAddress)"; attachedTo = "$($p.properties.ipConfiguration.id)"; sku = "$($p.sku.name)" }
            }
        }
        $vnets = Save-Area $safe 'vnets' {
            foreach ($v in @(Get-ArmScoped $base $groups 'Microsoft.Network/virtualNetworks?api-version=2023-09-01')) {
                [pscustomobject]@{ id = $v.id; name = $v.name; subnets = @(@($v.properties.subnets) | ForEach-Object { [pscustomobject]@{ id = "$($_.id)"; name = $_.name; nsg = "$($_.properties.networkSecurityGroup.id)" } }) }
            }
        }
        Write-Host "    VMs: $(N $vms); network interfaces: $(N $nics); public IPs: $(N $pips); virtual networks: $(N $vnets)" -ForegroundColor Yellow
    } else { Write-Host '    VMs: skipped by scope (types)' -ForegroundColor DarkGray }

    # --- App Service and Function Apps ---------------------------------------------------
    # The site list, its web config (TLS, FTP, remote debugging, access restrictions) and, for
    # Function Apps, the function list (HTTP triggers and their authorization level). Per-site
    # failures are kept on the site (errors) so one locked-down app never hides the others.
    if (Test-ScopedReader $scope 'appservice') {
        $sites = Save-Area $safe 'appservice' {
            foreach ($site in @(Select-ScopedResources $scope 'appservice' (Get-ArmScoped $base $groups 'Microsoft.Web/sites?api-version=2023-12-01'))) {
                $p = $site.properties
                $o = [ordered]@{ id = $site.id; name = $site.name; kind = "$($site.kind)"; location = $site.location; state = $p.state; httpsOnly = $p.httpsOnly
                    publicNetworkAccess = $p.publicNetworkAccess; clientCertEnabled = $p.clientCertEnabled; vnetSubnet = $p.virtualNetworkSubnetId; config = $null; easyAuth = $null; functions = $null; errors = @() }
                try {
                    $c = (Invoke-RestMethod -Uri "$Arm$($site.id)/config/web?api-version=2023-12-01" -Headers $H).properties
                    $o.config = [pscustomobject]@{
                        minTlsVersion = $c.minTlsVersion; ftpsState = $c.ftpsState; remoteDebuggingEnabled = $c.remoteDebuggingEnabled; publicNetworkAccess = $c.publicNetworkAccess
                        ipSecurityRestrictionsDefaultAction = $c.ipSecurityRestrictionsDefaultAction
                        ipSecurityRestrictions = @(@($c.ipSecurityRestrictions) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ name = $_.name; action = $_.action; ipAddress = $_.ipAddress; tag = $_.tag; vnetSubnetResourceId = $_.vnetSubnetResourceId; priority = $_.priority } })
                        scmIpSecurityRestrictionsUseMain = $c.scmIpSecurityRestrictionsUseMain; scmRestrictionCount = @($c.scmIpSecurityRestrictions | Where-Object { $_ }).Count
                    }
                } catch { $o.errors += "config: $(Get-ErrorText $_)" }
                # App Service authentication (Easy Auth): on, and not letting anonymous callers through.
                try {
                    $au = (Invoke-RestMethod -Uri "$Arm$($site.id)/config/authsettingsV2?api-version=2023-12-01" -Headers $H).properties
                    $o.easyAuth = [bool]($au.platform.enabled -eq $true -and "$($au.globalValidation.unauthenticatedClientAction)" -ne 'AllowAnonymous')
                } catch { $o.errors += "authsettings: $(Get-ErrorText $_)" }
                if ($o.kind -match 'functionapp') {
                    try {
                        $o.functions = @(@(Get-Arm "$Arm$($site.id)/functions?api-version=2023-12-01") | ForEach-Object {
                            $fp = $_.properties
                            $http = @(@($fp.config.bindings) | Where-Object { $_ -and "$($_.type)" -eq 'httpTrigger' })
                            [pscustomobject]@{ name = ("$($_.name)" -split '/')[-1]; disabled = $fp.isDisabled; httpTrigger = ($http.Count -gt 0); authLevel = $(if ($http.Count) { "$($http[0].authLevel)" } else { $null }) }
                        })
                    } catch { $o.errors += "functions: $(Get-ErrorText $_)" }
                }
                [pscustomobject]$o
            }
        }
        Write-Host "    App Service / Function Apps: $(N $sites)" -ForegroundColor Yellow
    } else { Write-Host '    App Service: skipped by scope (types)' -ForegroundColor DarkGray }

    # --- Automation accounts (runbooks, Run As connections) --------------------------------
    if (Test-ScopedReader $scope 'automation') {
        $aa = Save-Area $safe 'automation' {
            foreach ($acct in @(Select-ScopedResources $scope 'automation' (Get-ArmScoped $base $groups 'Microsoft.Automation/automationAccounts?api-version=2023-11-01'))) {
                $o = [ordered]@{ id = $acct.id; name = $acct.name; location = $acct.location; identity = "$($acct.identity.type)"
                    publicNetworkAccess = $acct.properties.publicNetworkAccess; disableLocalAuth = $acct.properties.disableLocalAuth; connections = $null; runbooks = $null; errors = @() }
                try { $o.connections = @(@(Get-Arm "$Arm$($acct.id)/connections?api-version=2023-11-01") | ForEach-Object { [pscustomobject]@{ name = $_.name; type = "$($_.properties.connectionType.name)" } }) }
                catch { $o.errors += "connections: $(Get-ErrorText $_)" }
                try { $o.runbooks = @(@(Get-Arm "$Arm$($acct.id)/runbooks?api-version=2023-11-01") | ForEach-Object { [pscustomobject]@{ name = $_.name; type = "$($_.properties.runbookType)"; state = "$($_.properties.state)"; lastModified = $_.properties.lastModifiedTime } }) }
                catch { $o.errors += "runbooks: $(Get-ErrorText $_)" }
                [pscustomobject]$o
            }
        }
        Write-Host "    Automation accounts: $(N $aa)" -ForegroundColor Yellow
    } else { Write-Host '    Automation: skipped by scope (types)' -ForegroundColor DarkGray }

    # --- API connections (Logic Apps / Power Automate managed connectors) ------------------
    # Only the identity a connection signs in as and its status; parameter values are not kept.
    if (Test-ScopedReader $scope 'apiconnections') {
        $conns = Save-Area $safe 'apiconnections' {
            foreach ($c in @(Select-ScopedResources $scope 'apiconnections' (Get-ArmScoped $base $groups 'Microsoft.Web/connections?api-version=2016-06-01'))) {
                $p = $c.properties
                [pscustomobject]@{ id = $c.id; name = $c.name; api = "$($p.api.name)"; apiDisplayName = "$($p.api.displayName)"; displayName = "$($p.displayName)"
                    authenticatedUser = "$($p.authenticatedUser.name)"; status = (@(@($p.statuses) | Where-Object { $_ } | ForEach-Object { "$($_.status)" }) -join ','); createdTime = $p.createdTime }
            }
        }
        Write-Host "    API connections: $(N $conns)" -ForegroundColor Yellow
    } else { Write-Host '    API connections: skipped by scope (types)' -ForegroundColor DarkGray }
}

Write-Host 'Azure exposure sweep done.' -ForegroundColor Green
