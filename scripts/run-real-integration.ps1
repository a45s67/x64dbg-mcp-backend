[CmdletBinding()]
param(
    [ValidateSet('x32', 'x64')]
    [string]$Backend,
    [string]$IntegrationRoot,
    [string]$ServerPath,
    [string]$FixtureName = 'mcp-debuggee-fixture.exe'
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($IntegrationRoot)) {
    $IntegrationRoot = Join-Path $PSScriptRoot '..\artifacts\integration'
}
if ([string]::IsNullOrWhiteSpace($ServerPath)) {
    $ServerPath = Join-Path $PSScriptRoot '..\target\debug\x64dbg-mcp-server.exe'
}
if ([string]::IsNullOrWhiteSpace($FixtureName) -or
    $FixtureName -ne [System.IO.Path]::GetFileName($FixtureName) -or
    [System.IO.Path]::GetExtension($FixtureName) -ine '.exe') {
    throw 'FixtureName must be an .exe leaf filename.'
}
$backendRoot = (Resolve-Path -LiteralPath (Join-Path $IntegrationRoot $Backend)).Path
$server = (Resolve-Path -LiteralPath $ServerPath).Path
$debuggerName = if ($Backend -eq 'x32') { 'x32dbg-unsigned.exe' } else { 'x64dbg.exe' }
$debugger = Join-Path $backendRoot $debuggerName
$fixture = Join-Path $backendRoot $FixtureName
$dllFixture = Join-Path $backendRoot 'mcp-debuggee-dll-fixture.dll'
$argumentObservation = Join-Path $backendRoot 'mcp-argv-observed.bin'
if (!(Test-Path -LiteralPath $debugger) -or !(Test-Path -LiteralPath $fixture) -or
    !(Test-Path -LiteralPath $dllFixture)) {
    throw 'The isolated debugger tree or fixture is missing. Run prepare-integration.ps1 first.'
}
$plugins = Get-ChildItem -LiteralPath (Join-Path $backendRoot 'plugins') -File
$expectedExtension = if ($Backend -eq 'x32') { '.dp32' } else { '.dp64' }
if ($plugins.Count -ne 1 -or $plugins[0].Name -ine "x64dbg-mcp-backend$expectedExtension") {
    throw 'Isolation invariant failed: the debugger plugins directory must contain only this project plugin.'
}

. (Join-Path $PSScriptRoot 'python-test-runtime.ps1')
$python = Get-TestPython
$pythonArgs = @($python.Arguments)
$scenario = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\tests\python\real_integration.py')).Path

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$tokenBytes = New-Object byte[] 32
$random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($tokenBytes) } finally { $random.Dispose() }
$token = [Convert]::ToBase64String($tokenBytes)
$baseUri = "http://127.0.0.1:$port"
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }

$previous = @{
    Port = $env:X64DBG_MCP_PORT
    Token = $env:X64DBG_MCP_TOKEN
    Server = $env:X64DBG_MCP_SERVER_PATH
    Rate = $env:X64DBG_MCP_MAX_REQUESTS_PER_SECOND
}
$debuggerProcess = $null
try {
    Write-Verbose "Launching isolated debugger: $debugger"
    Remove-Item -LiteralPath $argumentObservation -Force -ErrorAction SilentlyContinue
    $env:X64DBG_MCP_PORT = [string]$port
    $env:X64DBG_MCP_TOKEN = $token
    $env:X64DBG_MCP_SERVER_PATH = $server
    # This qualification intentionally performs more than 100 calls in a
    # second on fast hosts. Keep the production default unchanged while using
    # the documented hard-bounded test ceiling for this isolated instance.
    $env:X64DBG_MCP_MAX_REQUESTS_PER_SECOND = '1000'
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $debugger
    $startInfo.Arguments = ''
    $startInfo.WorkingDirectory = $backendRoot
    $startInfo.UseShellExecute = $false
    $debuggerProcess = [System.Diagnostics.Process]::Start($startInfo)
    Write-Verbose "Started $Backend debugger process $($debuggerProcess.Id)"

    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 100
        try {
            $ready = Invoke-RestMethod -UseBasicParsing -Uri "$baseUri/health/ready" `
                -Headers $headers -TimeoutSec 2
        } catch {
            $ready = $null
        }
    } until ($ready.status -eq 'ready' -or [DateTime]::UtcNow -ge $deadline -or $debuggerProcess.HasExited)
    if ($ready.status -ne 'ready') {
        throw 'Sidecar did not become ready through the isolated debugger plugin.'
    }
    Write-Verbose 'Sidecar is ready'

    $pythonArgs += @(
        $scenario, '--base-url', $baseUri, '--backend', $Backend,
        '--backend-root', $backendRoot, "--fixture-name=$FixtureName",
        '--debugger-pid', [string]$debuggerProcess.Id
    )
    # Readiness assertions and every HTTP scenario live in Python. The bearer
    # token is inherited through X64DBG_MCP_TOKEN, never exposed in argv.
    $reportJson = & $python.Source @pythonArgs
    if ($LASTEXITCODE -ne 0) { throw "Real integration Python scenario failed (exit $LASTEXITCODE)." }
    $report = ($reportJson -join "`n") | ConvertFrom-Json
    if ($null -eq $report) { throw 'Real integration scenario completed without a result summary.' }
    $report | ConvertTo-Json -Depth 5
} finally {
    Write-Verbose 'Entering integration cleanup'
    if ($debuggerProcess -and !$debuggerProcess.HasExited) {
        $null = $debuggerProcess.CloseMainWindow()
        if (!$debuggerProcess.WaitForExit(7000)) {
            Stop-Process -Id $debuggerProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    $env:X64DBG_MCP_PORT = $previous.Port
    $env:X64DBG_MCP_TOKEN = $previous.Token
    $env:X64DBG_MCP_SERVER_PATH = $previous.Server
    $env:X64DBG_MCP_MAX_REQUESTS_PER_SECOND = $previous.Rate
    Remove-Item -LiteralPath $argumentObservation -Force -ErrorAction SilentlyContinue
    Write-Verbose 'Integration cleanup finished'
}
