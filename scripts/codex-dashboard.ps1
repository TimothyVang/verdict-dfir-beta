param(
    [int]$Port = 3000,
    [switch]$NoOpen
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$CodexUrl = "http://localhost:$Port/codex"
$StateDir = Join-Path $RepoRoot ".project-local\state"
$CapabilityFile = Join-Path $StateDir "dashboard-capability"
$ExchangeFile = Join-Path $StateDir "dashboard-exchange"
$LaunchFile = Join-Path $StateDir "dashboard-launch.html"
$LogDir = Join-Path $env:LOCALAPPDATA "Temp\opencode"
$OutLog = Join-Path $LogDir "findevil-codex-dashboard.out"
$ErrLog = Join-Path $LogDir "findevil-codex-dashboard.err"

New-Item -ItemType Directory -Force $LogDir | Out-Null
New-Item -ItemType Directory -Force $StateDir | Out-Null

function Protect-OperatorPath([string]$Path) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($rule) }
    $inheritance = if ((Get-Item $Path).PSIsContainer) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [System.Security.AccessControl.InheritanceFlags]::None }
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity,
        "FullControl",
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($rule)
    Set-Acl -Path $Path -AclObject $acl
}

Protect-OperatorPath $StateDir

function Test-CodexDashboard {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $CodexUrl -TimeoutSec 3
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

if (-not (Test-CodexDashboard)) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $DashboardCapability = -join ($bytes | ForEach-Object { $_.ToString("x2") })
    Set-Content -Path $CapabilityFile -Value $DashboardCapability -Encoding Ascii -NoNewline
    Protect-OperatorPath $CapabilityFile
    $env:FINDEVIL_CODEX_UI_ENABLE = "1"
    $env:FINDEVIL_DASHBOARD_CAPABILITY = $DashboardCapability
    $env:FINDEVIL_DASHBOARD_EXCHANGE_FILE = $ExchangeFile
    $DashboardEd25519Pin = ([string]$env:FINDEVIL_ED25519_EXPECTED_FINGERPRINT).Trim().ToLowerInvariant()
    if (-not $DashboardEd25519Pin) {
        $AgentDir = Join-Path $RepoRoot "services\agent"
        $FingerprintOutput = & uv run --quiet --directory $AgentDir python -c `
            "from findevil_agent.crypto.signer import LocalEd25519Signer; print(LocalEd25519Signer().public_fingerprint())"
        $DashboardEd25519Pin = ($FingerprintOutput -join "").Trim().ToLowerInvariant()
    }
    if ($DashboardEd25519Pin -notmatch '^[0-9a-f]{64}$') {
        throw "The trusted Ed25519 dashboard pin is missing or invalid."
    }
    $env:FINDEVIL_ED25519_EXPECTED_FINGERPRINT = $DashboardEd25519Pin
    Start-Process `
        -FilePath "pnpm" `
        -ArgumentList @("--filter", "@findevil/web", "dev", "--", "--hostname", "127.0.0.1", "--port", "$Port") `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $OutLog `
        -RedirectStandardError $ErrLog `
        -WindowStyle Hidden | Out-Null

    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if (Test-CodexDashboard) { break }
        Start-Sleep -Milliseconds 500
    }
} else {
    if (-not (Test-Path -PathType Leaf $CapabilityFile)) {
        throw "Dashboard is running without this operator session capability; refusing access."
    }
    $DashboardCapability = (Get-Content -Raw $CapabilityFile).Trim()
}

if ($DashboardCapability -notmatch '^[0-9a-f]{64}$') {
    throw "Dashboard capability is invalid; stop the dashboard and relaunch it."
}

if (-not (Test-CodexDashboard)) {
    Write-Error "Find Evil dashboard did not start. Logs: $OutLog $ErrLog"
}

try {
    $probe = Invoke-WebRequest -UseBasicParsing `
        -Uri "http://127.0.0.1:$Port/api/cases" `
        -Headers @{ Cookie = "verdict_dashboard_session=$DashboardCapability" } `
        -TimeoutSec 3
    if ($probe.StatusCode -ne 200) { throw "unexpected status" }
} catch {
    throw "Dashboard did not accept this operator capability; refusing access."
}

$exchangeBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($exchangeBytes)
$DashboardExchange = -join ($exchangeBytes | ForEach-Object { $_.ToString("x2") })
Set-Content -Path $ExchangeFile -Value $DashboardExchange -Encoding Ascii -NoNewline
Protect-OperatorPath $ExchangeFile
$BrowserBase = "http://verdict-$($DashboardExchange.Substring(0, 16)).localhost:$Port"
$encodedBase = [System.Net.WebUtility]::HtmlEncode($BrowserBase)
$encodedToken = [System.Net.WebUtility]::HtmlEncode($DashboardExchange)
$launchHtml = @"
<!doctype html><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; form-action $encodedBase">
<title>Open VERDICT dashboard</title>
<form id="session" method="post" action="$encodedBase/api/session">
<input type="hidden" name="token" value="$encodedToken">
<input type="hidden" name="next" value="/codex">
<button type="submit">Open private VERDICT dashboard</button>
</form><script>document.getElementById('session').submit()</script>
"@
Set-Content -Path $LaunchFile -Value $launchHtml -Encoding UTF8 -NoNewline
Protect-OperatorPath $LaunchFile

if (-not $NoOpen) {
    Start-Process $LaunchFile | Out-Null
}

Write-Output "Dashboard is running:"
Write-Output "- Codex cockpit: $BrowserBase/codex (private browser session opened)"
Write-Output "- Audit dashboard: $BrowserBase/"
Write-Output "- Debug stream: $BrowserBase/debug"
Write-Output "- Logs: $OutLog $ErrLog"
