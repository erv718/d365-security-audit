# azure-sweep.ps1 - read-only pull of the Azure resource plane (ARM).
# Covers: role assignments (Owners/UAA), SQL firewalls + public access, Synapse firewalls,
# Key Vaults (RBAC vs access policy, public network), NSGs (RDP/SSH open to the internet).
#
# The app registration needs the Reader role on the target subscriptions. Scope: the resolved
# selection (run-audit.ps1 parameters > scope.json > AZURE_SUBSCRIPTIONS in .env); blank means
# every subscription the app can read. With resource groups selected, the SQL, Synapse, Key
# Vault and NSG lists are read per group (Reader on the group is enough for those); with types
# selected, the other readers are skipped. Role assignments are always read at subscription
# scope, where the Owner/UAA count is taken. GET only.

. (Join-Path $PSScriptRoot '_common.ps1')

$tok = Get-Token 'https://management.azure.com'
if (-not $tok) { Write-Warning 'No Azure ARM token - skipping the Azure sweep; other steps still run.'; return }
$H = @{ Authorization = "Bearer $tok" }
function Get-Arm($url) { $i=@(); $n=$url; while($n){ $r=Invoke-RestMethod -Uri $n -Headers $H; if($r.value){$i+=$r.value}; $n=$r.nextLink }; return $i }
# One reader's items over every list URL in scope (one per selected group, or the subscription-wide one).
function Get-ArmScoped($base, $groups, $providerPath) { $items = @(); foreach ($u in @(Get-ArmListUrls $base $groups $providerPath)) { $items += @(Get-Arm $u) }; return $items }

$scope = Read-ScopeEffective
try { $allSubs = @(Get-Arm 'https://management.azure.com/subscriptions?api-version=2022-12-01') }
catch { Write-Warning "Could not list subscriptions: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } 'arm-subscriptions-ERROR.json' | Out-Null; return }
$subs = @(Select-ScopedSubscriptions $scope $allSubs)
Save-Json @($allSubs | ForEach-Object { [pscustomobject]@{ subscriptionId = $_.subscriptionId; displayName = $_.displayName; state = $_.state } }) 'arm-subscriptions.json' | Out-Null
$invisible = @(Get-ScopeInvisibleSubscriptions $scope $allSubs)
if ($invisible.Count -gt 0) { Write-Warning "Azure: $($invisible.Count) selected subscription(s) not visible to the app (no Reader role, or a typo): $($invisible -join ', ')" }
Write-Host "Azure: auditing $($subs.Count) of $($allSubs.Count) visible subscription(s)" -ForegroundColor Cyan
$rgSelected = @(Get-ScopeItems $scope.azure.resourceGroups); $rgSeen = @{}; $rgTotal = 0
$safeNames = Get-SubscriptionSafeNames $allSubs

$wellKnown = @{
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
    'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
}

foreach ($s in $subs) {
    $sid = $s.subscriptionId; $base = "https://management.azure.com/subscriptions/$sid"
    $safe = $safeNames["$sid"]
    Write-Host "  $($s.displayName)" -ForegroundColor Cyan

    # Resource-group scoping, only when groups were selected: the group list is one GET.
    $groups = $null
    if ($rgSelected.Count -gt 0) {
        $names = @()
        try { $names = @(@(Get-Arm "$base/resourcegroups?api-version=2021-04-01") | ForEach-Object { "$($_.name)" }) }
        catch { Write-Warning "    resource groups could not be listed: $(Get-ErrorText $_)" }
        $rgTotal += $names.Count
        $groups = Select-ScopedResourceGroups $scope $names
        foreach ($g in @($groups)) { $rgSeen[$g.ToLower()] = $g }
        Write-Host "    resource groups in scope here: $(@($groups).Count) of $($names.Count)$(if(@($groups).Count -eq 0){' (resource readers read nothing; role assignments still read)'})" -ForegroundColor Yellow
    }

    try {
        $ra = Get-Arm "$base/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        $highCount = @($ra | Where-Object { $wellKnown[$_.properties.roleDefinitionId.Split('/')[-1]] -in 'Owner','User Access Administrator' -and $_.properties.scope -eq "/subscriptions/$sid" }).Count
        Save-Json $ra "arm-$safe-rbac.json" | Out-Null
        Write-Host "    RBAC: $($ra.Count) assignments; $highCount Owner/UAA at subscription scope" -ForegroundColor Yellow
    } catch { Write-Warning "    RBAC failed: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } "arm-$safe-rbac-ERROR.json" | Out-Null }

    if (Test-ScopedReader $scope 'sql') {
        try {
            $sql = @(Select-ScopedResources $scope 'sql' (Get-ArmScoped $base $groups 'Microsoft.Sql/servers?api-version=2021-11-01'))
            foreach ($srv in $sql) {
                $fw = Get-Arm "https://management.azure.com$($srv.id)/firewallRules?api-version=2021-11-01"
                $srv | Add-Member -NotePropertyName _firewallRules -NotePropertyValue $fw -Force
            }
            Save-Json $sql "arm-$safe-sql.json" | Out-Null
        } catch { Write-Warning "    SQL failed: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } "arm-$safe-sql-ERROR.json" | Out-Null }
    } else { Write-Host '    SQL: skipped by scope (types)' -ForegroundColor DarkGray }

    if (Test-ScopedReader $scope 'synapse') {
        try {
            $syn = @(Select-ScopedResources $scope 'synapse' (Get-ArmScoped $base $groups 'Microsoft.Synapse/workspaces?api-version=2021-06-01'))
            foreach ($w in $syn) {
                $fw = Get-Arm "https://management.azure.com$($w.id)/firewallRules?api-version=2021-06-01"
                $w | Add-Member -NotePropertyName _firewallRules -NotePropertyValue $fw -Force
            }
            Save-Json $syn "arm-$safe-synapse.json" | Out-Null
        } catch { Write-Warning "    Synapse failed: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } "arm-$safe-synapse-ERROR.json" | Out-Null }
    } else { Write-Host '    Synapse: skipped by scope (types)' -ForegroundColor DarkGray }

    if (Test-ScopedReader $scope 'keyvault') {
        try { Save-Json @(Select-ScopedResources $scope 'keyvault' (Get-ArmScoped $base $groups 'Microsoft.KeyVault/vaults?api-version=2022-07-01')) "arm-$safe-keyvaults.json" | Out-Null }
        catch { Write-Warning "    Key Vaults failed: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } "arm-$safe-keyvaults-ERROR.json" | Out-Null }
    } else { Write-Host '    Key Vaults: skipped by scope (types)' -ForegroundColor DarkGray }

    if (Test-ScopedReader $scope 'nsg') {
        try { Save-Json @(Select-ScopedResources $scope 'nsg' (Get-ArmScoped $base $groups 'Microsoft.Network/networkSecurityGroups?api-version=2023-05-01')) "arm-$safe-nsgs.json" | Out-Null }
        catch { Write-Warning "    NSGs failed: $(Get-ErrorText $_)"; Save-Json @{ error = (Get-ErrorText $_) } "arm-$safe-nsgs-ERROR.json" | Out-Null }
    } else { Write-Host '    NSGs: skipped by scope (types)' -ForegroundColor DarkGray }
}

# What the app saw, and which selections it could not find, for the report's scope banner.
Update-ScopeEffective {
    param($x)
    Set-ScopeField $x.azure 'discoveredSubscriptions' $allSubs.Count
    Set-ScopeField $x.azure 'selectedVisible' @($subs | ForEach-Object { "$($_.subscriptionId)" })
    Set-ScopeField $x.azure 'selectedInvisible' $invisible
    if ($rgSelected.Count -gt 0) {
        Set-ScopeField $x.azure 'discoveredResourceGroups' $rgTotal
        Set-ScopeField $x.azure 'resourceGroupsVisible' @($rgSeen.Values)
        Set-ScopeField $x.azure 'resourceGroupsInvisible' @($rgSelected | Where-Object { -not $rgSeen.ContainsKey($_.ToLower()) })
    }
} | Out-Null
Write-Host 'Azure sweep done.' -ForegroundColor Green
