[CmdletBinding()]
param(
    [ValidateSet('x32', 'x64')]
    [string]$Backend,
    [string]$IntegrationRoot,
    [string]$ServerPath,
    [string]$ControllerPath,
    [int]$TimeoutMs = 30000
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($IntegrationRoot)) {
    $IntegrationRoot = Join-Path $PSScriptRoot '..\artifacts\integration'
}
if ([string]::IsNullOrWhiteSpace($ServerPath)) {
    $ServerPath = Join-Path $PSScriptRoot '..\target\release\x64dbg-mcp-server.exe'
}
if ([string]::IsNullOrWhiteSpace($ControllerPath)) {
    $ControllerPath = Join-Path $PSScriptRoot '..\build\windows-x64\x96dbg-mcp-control.exe'
}
if ($TimeoutMs -lt 1000 -or $TimeoutMs -gt 60000) {
    throw 'TimeoutMs must be from 1000 through 60000.'
}

$root = (Resolve-Path -LiteralPath $IntegrationRoot).Path
$server = (Resolve-Path -LiteralPath $ServerPath).Path
$controller = (Resolve-Path -LiteralPath $ControllerPath).Path
foreach ($directory in @('x32', 'x64')) {
    if (!(Test-Path -LiteralPath (Join-Path $root $directory) -PathType Container)) {
        throw 'Prepare the isolated integration tree before running host control tests.'
    }
}

$mcpDirectory = Join-Path $root 'mcp'
New-Item -ItemType Directory -Path $mcpDirectory -Force | Out-Null
Copy-Item -LiteralPath $server -Destination (Join-Path $mcpDirectory 'x96dbg-mcp-server.exe') -Force
Copy-Item -LiteralPath $controller -Destination (Join-Path $mcpDirectory 'x96dbg-mcp-control.exe') -Force

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$tokenBytes = New-Object byte[] 32
$generator = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $generator.GetBytes($tokenBytes) } finally { $generator.Dispose() }
$token = [Convert]::ToBase64String($tokenBytes)
$config = Join-Path $mcpDirectory "x64dbg-mcp-server-$Backend.toml"
@"
bind = "127.0.0.1"
port = $port
bearer_token = "$token"
"@ | Set-Content -LiteralPath $config -Encoding ASCII -NoNewline

$installedController = Join-Path $mcpDirectory 'x96dbg-mcp-control.exe'
function Invoke-Control([string]$Action, [switch]$Force) {
    $arguments = @($Action, '--backend', $Backend, '--root', $root,
        '--timeout-ms', [string]$TimeoutMs)
    if ($Force) { $arguments += '--force' }
    $output = & $installedController @arguments
    $exitCode = $LASTEXITCODE
    if ($output.Count -ne 1) { throw "Controller returned an invalid line count for $Action." }
    $result = $output | ConvertFrom-Json
    if ($exitCode -ne 0 -or $result.status -ne 'ok') {
        throw "Controller $Action failed ($exitCode): $output"
    }
    return $result
}

try {
    $initial = Invoke-Control status
    if ($initial.host_state -ne 'stopped') { throw 'Isolated debugger was already running.' }
    $started = Invoke-Control start
    $running = Invoke-Control status
    if ($running.host_state -ne 'running' -or $running.mcp_state -ne 'ready' -or
        $running.process_id -ne $started.process_id -or
        $running.instance_id -ne $started.instance_id) {
        throw 'Start/status postcondition failed.'
    }
    $restarted = Invoke-Control restart
    if ($restarted.previous_process_id -ne $started.process_id -or
        $restarted.process_id -eq $started.process_id -or
        $restarted.instance_id -eq $started.instance_id) {
        throw 'Restart did not produce a distinct debugger/backend instance.'
    }
    $stopped = Invoke-Control stop
    $final = Invoke-Control status
    if ($stopped.process_id -ne $restarted.process_id -or $final.host_state -ne 'stopped') {
        throw 'Stop/status postcondition failed.'
    }
    Write-Output "host control integration passed for $Backend"
} finally {
    try { & $installedController stop --backend $Backend --root $root --timeout-ms $TimeoutMs --force | Out-Null } catch {}
}
