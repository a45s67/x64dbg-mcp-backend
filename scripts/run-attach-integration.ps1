[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x32', 'x64')]
    [string]$Backend,
    [Parameter(Mandatory)]
    [string]$IntegrationRoot,
    [string]$ServerPath = (Join-Path $PSScriptRoot '..\target\debug\x64dbg-mcp-server.exe'),
    [string]$FixtureName = 'mcp-debuggee-fixture.exe'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'python-test-runtime.ps1')
$python = Get-TestPython
$backendRoot = (Resolve-Path -LiteralPath (Join-Path $IntegrationRoot $Backend)).Path
$server = (Resolve-Path -LiteralPath $ServerPath).Path
$fixture = (Resolve-Path -LiteralPath (Join-Path $backendRoot $FixtureName)).Path
$debuggerName = if ($Backend -eq 'x32') { 'x32dbg-unsigned.exe' } else { 'x64dbg.exe' }
$debugger = (Resolve-Path -LiteralPath (Join-Path $backendRoot $debuggerName)).Path
$plugins = @(Get-ChildItem -LiteralPath (Join-Path $backendRoot 'plugins') -File)
$extension = if ($Backend -eq 'x32') { '.dp32' } else { '.dp64' }
if ($plugins.Count -ne 1 -or $plugins[0].Name -ine "x64dbg-mcp-backend$extension") {
    throw 'Attach isolation requires exactly this project plugin.'
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$tokenBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($tokenBytes) } finally { $random.Dispose() }
$token = [Convert]::ToBase64String($tokenBytes)
$baseUri = "http://127.0.0.1:$port"
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }
$previous = @{
    Port = [Environment]::GetEnvironmentVariable('X64DBG_MCP_PORT', 'Process')
    Token = [Environment]::GetEnvironmentVariable('X64DBG_MCP_TOKEN', 'Process')
    Server = [Environment]::GetEnvironmentVariable('X64DBG_MCP_SERVER_PATH', 'Process')
}
$env:X64DBG_MCP_PORT = $port.ToString()
$env:X64DBG_MCP_TOKEN = $token
$env:X64DBG_MCP_SERVER_PATH = $server

function Start-OwnedProcess([string]$FilePath, [string]$WorkingDirectory) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (!$process.Start()) { throw "Process launch returned false: $FilePath" }
        return $process
    } catch {
        $process.Dispose()
        throw
    }
}

$fixtureProcess = $null
$debuggerProcess = $null
try {
    $fixtureProcess = Start-OwnedProcess $fixture $backendRoot
    Start-Sleep -Milliseconds 150
    if ($fixtureProcess.HasExited) { throw 'Independent fixture exited before attach.' }
    $debuggerProcess = Start-OwnedProcess $debugger $backendRoot

    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 100
        try {
            $ready = Invoke-RestMethod -UseBasicParsing -Uri "$baseUri/health/ready" `
                -Headers $headers -TimeoutSec 2
        } catch { $ready = $null }
    } until ($ready.status -eq 'ready' -or [DateTime]::UtcNow -ge $deadline -or
        $debuggerProcess.HasExited)
    if ($ready.status -ne 'ready' -or $ready.debugger_state -ne 'absent') {
        throw 'Isolated debugger did not become ready without a debuggee.'
    }
    $instanceId = ([Guid]::Parse([string]$ready.instance_id)).ToString()
    $pythonArgs = @($python.Arguments)
    $pythonArgs += @(
        (Join-Path $PSScriptRoot '..\tests\python\attach_integration.py'),
        '--base-url', $baseUri, '--instance-id', $instanceId, '--backend', $Backend,
        '--debugger-pid', [string]$debuggerProcess.Id,
        '--fixture-pid', [string]$fixtureProcess.Id, "--fixture-name=$FixtureName",
        '--port', [string]$port
    )
    # The bearer token is inherited through X64DBG_MCP_TOKEN, never argv.
    $reportJson = & $python.Source @pythonArgs
    if ($LASTEXITCODE -ne 0) { throw "Attach Python scenario failed (exit $LASTEXITCODE)." }
    $report = ($reportJson -join "`n") | ConvertFrom-Json
    if ($null -eq $report) { throw 'Attach scenario completed without a result summary.' }
    $report | ConvertTo-Json -Depth 4
} finally {
    if ($debuggerProcess -and !$debuggerProcess.HasExited) {
        $null = $debuggerProcess.CloseMainWindow()
        if (!$debuggerProcess.WaitForExit(7000)) {
            Stop-Process -Id $debuggerProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    if ($fixtureProcess -and !$fixtureProcess.HasExited) {
        Stop-Process -Id $fixtureProcess.Id -Force -ErrorAction SilentlyContinue
        $null = $fixtureProcess.WaitForExit(3000)
    }
    $env:X64DBG_MCP_PORT = $previous.Port
    $env:X64DBG_MCP_TOKEN = $previous.Token
    $env:X64DBG_MCP_SERVER_PATH = $previous.Server
    $token = $null
    $headers = $null
}
