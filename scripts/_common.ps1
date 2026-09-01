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

# --- Interactive Microsoft Graph sign-in (OAuth 2.0 device-code flow) ---------
# Well-known Microsoft first-party PUBLIC client "Microsoft Graph Command Line Tools"
# (the same client Connect-MgGraph uses under the hood). No app registration, no
# client secret, no module - just two HTTPS POSTs you can read top to bottom.
$script:GraphCliClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'

# Least-privilege delegated Graph read scopes this audit needs. Each was verified
# against its own Microsoft Learn reference page. offline_access -> refresh token.
$script:GraphScopes = @(
    'offline_access', 'openid',
    'Application.Read.All', 'RoleManagement.Read.Directory', 'User.Read.All',
    'Policy.Read.All', 'AuditLog.Read.All',
    'DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All'
) -join ' '

# Read the error body from a failed Invoke-RestMethod across PowerShell 7 and 5.1.
function Get-HttpErrorBody($e) {
    if ($e.ErrorDetails -and $e.ErrorDetails.Message) { return $e.ErrorDetails.Message }
    try {
        $reader = New-Object System.IO.StreamReader($e.Exception.Response.GetResponseStream())
        return $reader.ReadToEnd()
    } catch { return '' }
}

# Get a delegated Graph token via the device-code flow. Signs the user in once per run
# (cached in a process-global so both graph scripts share one sign-in), refreshes
# silently, and returns a raw bearer string. Returns $null (never throws) on decline,
# timeout, or a needs-admin-consent response.
function Get-GraphTokenInteractive {
    $tenant = Get-Conf TENANT_ID; if (-not $tenant) { $tenant = 'organizations' }
    $cid = $script:GraphCliClientId
    $authority = "https://login.microsoftonline.com/$tenant/oauth2/v2.0"

    # 1) reuse a still-valid cached token (survives across graph-sweep + graph-identity-plus)
    $c = $Global:D365AuditGraphTok
    if ($c -and $c.Expiry -gt (Get-Date)) { return $c.AccessToken }

    # 2) silent refresh if we still hold a refresh token
    if ($c -and $c.RefreshToken) {
        try {
            $r = Invoke-RestMethod -Method Post -Uri "$authority/token" -Body @{
                grant_type = 'refresh_token'; client_id = $cid
                refresh_token = $c.RefreshToken; scope = $script:GraphScopes
            }
            $Global:D365AuditGraphTok = @{ AccessToken = $r.access_token; RefreshToken = $r.refresh_token; Expiry = (Get-Date).AddSeconds([int]$r.expires_in - 300) }
            return $r.access_token
        } catch { $Global:D365AuditGraphTok = $null }   # fall through to a fresh sign-in
    }

    # 3) full device-code sign-in
    try {
        $dc = Invoke-RestMethod -Method Post -Uri "$authority/devicecode" -Body @{ client_id = $cid; scope = $script:GraphScopes }
    } catch {
        Write-Warning "Could not start the Graph sign-in: $($_.Exception.Message)"
        return $null
    }
    Write-Host ''
    Write-Host 'Sign-in 1 of 2 - Identity (Entra ID). Read-only, nothing is changed.' -ForegroundColor Cyan
    Write-Host "  $($dc.message)" -ForegroundColor Yellow
    Write-Host '  Use your Global Reader or admin account. No app registration or secret is needed.' -ForegroundColor DarkGray

    $interval = [int]$dc.interval; if ($interval -lt 5) { $interval = 5 }
    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        $tok = $null
        try {
            $tok = Invoke-RestMethod -Method Post -Uri "$authority/token" -Body @{
                grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
                client_id = $cid; device_code = $dc.device_code
            }
        } catch {
            $body = Get-HttpErrorBody $_
            $err = ''
            try { $err = ($body | ConvertFrom-Json).error } catch { $err = '' }
            if ($err -eq 'authorization_pending') { continue }
            if ($err -eq 'slow_down') { $interval += 5; continue }
            if ($err -eq 'authorization_declined') { Write-Warning 'Sign-in was declined. Skipping the identity checks; the rest of the audit still runs.'; return $null }
            if ($err -eq 'expired_token' -or $err -eq 'bad_verification_code') { Write-Warning 'Sign-in timed out. Skipping the identity checks; the rest of the audit still runs.'; return $null }
            if ($body -match 'AADSTS65001' -or $body -match 'consent') {
                Write-Warning "This sign-in needs a one-time admin approval. Ask a Global Administrator to sign in once and approve the app 'Microsoft Graph Command Line Tools', then re-run. Skipping identity checks for now."
            } else {
                Write-Warning "Graph sign-in failed: $body"
            }
            return $null
        }
        if ($tok) {
            $Global:D365AuditGraphTok = @{ AccessToken = $tok.access_token; RefreshToken = $tok.refresh_token; Expiry = (Get-Date).AddSeconds([int]$tok.expires_in - 300) }
            Write-Host '  Signed in. Reading identity configuration...' -ForegroundColor Green
            return $tok.access_token
        }
    }
    Write-Warning 'Sign-in window expired. Skipping the identity checks; the rest of the audit still runs.'
    return $null
}

# Get an OAuth token for a resource. Three sources, in order:
#   1. App registration (client credentials) when CLIENT_ID + CLIENT_SECRET + TENANT_ID are set.
#   2. Microsoft Graph with no app registration: interactive device-code sign-in (no secret, no module).
#   3. ARM / Dataverse / Power Platform: the Azure CLI token for the signed-in user (run `az login`).
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
    # Microsoft Graph with no app registration: sign in interactively (device-code flow).
    if ($Resource -like 'https://graph.microsoft.com*') { return (Get-GraphTokenInteractive) }
    # ARM / Dataverse / Power Platform (BAP): use the Azure CLI token for the signed-in user.
    # (These resources reject the Graph client's token, so this is a separate sign-in by design.)
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
