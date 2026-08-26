# azure-sweep.ps1 - read-only pull of the Azure resource plane (ARM).
# Covers: role assignments (Owners/UAA), SQL firewalls + public access, Synapse firewalls,
# Key Vaults (RBAC vs access policy, public network), NSGs (RDP/SSH open to the internet).
#
# Needs Reader on the target subscriptions. Set AZURE_SUBSCRIPTIONS in .env (comma-separated),
# or leave blank to audit every subscription the identity can read.

. (Join-Path $PSScriptRoot '_common.ps1')

$tok = Get-Token 'https://management.azure.com'
if (-not $tok) { throw 'No Azure ARM token.' }
$H = @{ Authorization = "Bearer $tok" }
function Get-Arm($url) { $i=@(); $n=$url; while($n){ $r=Invoke-RestMethod -Uri $n -Headers $H; if($r.value){$i+=$r.value}; $n=$r.nextLink }; return $i }

$subsConf = (Get-Conf AZURE_SUBSCRIPTIONS) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$allSubs = Get-Arm 'https://management.azure.com/subscriptions?api-version=2022-12-01'
$subs = if ($subsConf) { $allSubs | Where-Object { $subsConf -contains $_.subscriptionId } } else { $allSubs }
Write-Host "Azure: auditing $($subs.Count) subscription(s)" -ForegroundColor Cyan

$wellKnown = @{
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
    'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
}

foreach ($s in $subs) {
    $sid = $s.subscriptionId; $base = "https://management.azure.com/subscriptions/$sid"
    $safe = ($s.displayName -replace '[^A-Za-z0-9]','_')
    Write-Host "  $($s.displayName)" -ForegroundColor Cyan

    try {
        $ra = Get-Arm "$base/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        $highCount = @($ra | Where-Object { $wellKnown[$_.properties.roleDefinitionId.Split('/')[-1]] -in 'Owner','User Access Administrator' -and $_.properties.scope -eq "/subscriptions/$sid" }).Count
        Save-Json $ra "arm-$safe-rbac.json" | Out-Null
        Write-Host "    RBAC: $($ra.Count) assignments; $highCount Owner/UAA at subscription scope" -ForegroundColor Yellow
    } catch { Write-Warning "    RBAC failed: $($_.Exception.Message)" }

    try {
        $sql = Get-Arm "$base/providers/Microsoft.Sql/servers?api-version=2021-11-01"
        foreach ($srv in $sql) {
            $fw = Get-Arm "https://management.azure.com$($srv.id)/firewallRules?api-version=2021-11-01"
            $srv | Add-Member -NotePropertyName _firewallRules -NotePropertyValue $fw -Force
        }
        Save-Json $sql "arm-$safe-sql.json" | Out-Null
    } catch { Write-Warning "    SQL failed: $($_.Exception.Message)" }

    try {
        $syn = Get-Arm "$base/providers/Microsoft.Synapse/workspaces?api-version=2021-06-01"
        foreach ($w in $syn) {
            $fw = Get-Arm "https://management.azure.com$($w.id)/firewallRules?api-version=2021-06-01"
            $w | Add-Member -NotePropertyName _firewallRules -NotePropertyValue $fw -Force
        }
        Save-Json $syn "arm-$safe-synapse.json" | Out-Null
    } catch { Write-Warning "    Synapse failed: $($_.Exception.Message)" }

    try { Save-Json (Get-Arm "$base/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01") "arm-$safe-keyvaults.json" | Out-Null }
    catch { Write-Warning "    Key Vaults failed: $($_.Exception.Message)" }

    try { Save-Json (Get-Arm "$base/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01") "arm-$safe-nsgs.json" | Out-Null }
    catch { Write-Warning "    NSGs failed: $($_.Exception.Message)" }
}
Write-Host 'Azure sweep done.' -ForegroundColor Green
