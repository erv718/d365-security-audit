# _common.ps1 - shared helpers. Dot-source this from the sweep scripts.
# Read-only. No writes to any environment.

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Import-DotEnv {
    param([string]$Path)
    if (-not $Path) { $Path = Join-Path (Split-Path $PSScriptRoot -Parent) '.env' }
    $map = @{}
    if (Test-Path $Path) {
        foreach ($line in Get-Content $Path) {
            if ($line -match '^\s*#') { continue }
            if ($line -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.*)$') {
                $map[$Matches[1]] = $Matches[2].Trim().Trim('"').Trim("'")
            }
        }
    }
    return $map
}

$script:Conf = Import-DotEnv

function Get-Conf {
    param([string]$Key, [string]$Default = '')
    if ($script:Conf.ContainsKey($Key) -and $script:Conf[$Key]) { return $script:Conf[$Key] }
    $envVal = [Environment]::GetEnvironmentVariable($Key)
    if ($envVal) { return $envVal }
    return $Default
}

# Get an OAuth token for a resource.
# If CLIENT_ID + CLIENT_SECRET are set, uses the app registration (client credentials).
# Otherwise falls back to Azure CLI (runs as the signed-in user - run `az login` first).
function Get-Token {
    param([Parameter(Mandatory)][string]$Resource)
    $tenant = Get-Conf TENANT_ID
    $cid    = Get-Conf CLIENT_ID
    $sec    = Get-Conf CLIENT_SECRET
    if ($cid -and $sec -and $tenant) {
        try {
            return (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Body @{
                client_id = $cid; client_secret = $sec
                grant_type = 'client_credentials'; scope = "$Resource/.default"
            }).access_token
        } catch {
            Write-Warning "App token for $Resource failed: $($_.Exception.Message)"
            return $null
        }
    }
    # delegated fallback
    $t = az account get-access-token --resource $Resource --query accessToken -o tsv 2>$null
    if (-not $t) { Write-Warning "No token for $Resource. Set CLIENT_ID/SECRET in .env or run 'az login'." }
    return $t
}

function Invoke-Paged {
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][hashtable]$Headers, [string]$NextField = '@odata.nextLink')
    $items = @(); $next = $Url
    while ($next) {
        $r = Invoke-RestMethod -Uri $next -Headers $Headers
        if ($r.value) { $items += $r.value }
        $next = $r.$NextField
    }
    return $items
}

function Get-OutDir {
    $dir = Join-Path (Split-Path $PSScriptRoot -Parent) 'output'
    New-Item -ItemType Directory -Force $dir | Out-Null
    return $dir
}

function Save-Json {
    param([Parameter(Mandatory)]$Data, [Parameter(Mandatory)][string]$Name)
    $path = Join-Path (Get-OutDir) $Name
    $Data | ConvertTo-Json -Depth 12 | Out-File -Encoding utf8 $path
    return $path
}
