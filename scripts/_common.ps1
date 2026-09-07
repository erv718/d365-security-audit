# _common.ps1 - shared helpers. Dot-source this from the sweep scripts.
# Read-only. No writes to any environment.
#
# Authentication: this tool signs in ONLY as a read-only app registration
# (client credentials from .env). It never performs an interactive sign-in,
# never shows a login prompt or device code, and never uses a person's account.

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

# Get an OAuth token for a resource, as the read-only app registration.
# Requires TENANT_ID + CLIENT_ID + CLIENT_SECRET in .env. There is deliberately no
# fallback: no interactive sign-in, no device codes, no CLI sessions. Returns $null
# (with a warning) if the app is not configured or the token request fails; every
# sweep fails soft on a null token.
function Get-Token {
    param([Parameter(Mandatory)][string]$Resource)
    $tenant = Get-Conf TENANT_ID
    $cid    = Get-Conf CLIENT_ID
    $sec    = Get-Conf CLIENT_SECRET
    if (-not ($tenant -and $cid -and $sec)) {
        Write-Warning "No app registration configured for $Resource. Set TENANT_ID, CLIENT_ID and CLIENT_SECRET in .env (see docs/permissions.md)."
        return $null
    }
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

function Invoke-Paged {
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][hashtable]$Headers, [string]$NextField = '@odata.nextLink')
    $items = @(); $next = $Url
    while ($next) {
        $r = Invoke-RestMethod -Uri $next -Headers $Headers
        if ($r.value) { $items += $r.value }
        $next = $r.$NextField
    }
    # Comma keeps this an array even when empty; a bare empty array collapses to $null
    # on return, which then blows up Save-Json downstream.
    return ,$items
}

function Get-OutDir {
    $dir = Join-Path (Split-Path $PSScriptRoot -Parent) 'output'
    New-Item -ItemType Directory -Force $dir | Out-Null
    return $dir
}

function Save-Json {
    param($Data, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Data) { $Data = @() }   # never crash on an empty/absent result
    $path = Join-Path (Get-OutDir) $Name
    # -InputObject (not pipeline) so an empty array serialises to "[]" instead of nothing.
    ConvertTo-Json -Depth 12 -InputObject $Data | Out-File -Encoding utf8 $path
    return $path
}
