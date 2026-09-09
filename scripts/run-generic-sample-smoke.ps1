[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x32', 'x64')]
    [string]$Backend,
    [Parameter(Mandatory)]
    [string]$IntegrationRoot,
    [Parameter(Mandatory)]
    [string]$SamplePath,
    [string]$ServerPath,
    [ValidateLength(1, 64)]
    [string]$ExpectedAsciiPattern
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'python-test-runtime.ps1')
$python = Get-TestPython
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$integration = [IO.Path]::GetFullPath($IntegrationRoot)
$build = Get-Item -LiteralPath (Join-Path $workspace 'build') -ErrorAction SilentlyContinue
$physicalBuild = if ($build -and $build.Target) {
    [IO.Path]::GetFullPath([string]@($build.Target)[0]).TrimEnd('\')
} else { Join-Path $workspace 'build' }
if (!$integration.StartsWith($workspace + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase) -and
    !$integration.StartsWith($physicalBuild + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'IntegrationRoot must remain inside the repository workspace.'
}
$sample = (Resolve-Path -LiteralPath $SamplePath).Path
if ([string]::IsNullOrWhiteSpace($ServerPath)) {
    $ServerPath = Join-Path $workspace 'target\release\x64dbg-mcp-server.exe'
}
$server = (Resolve-Path -LiteralPath $ServerPath).Path
$backendRoot = (Resolve-Path -LiteralPath (Join-Path $integration $Backend)).Path
$debuggerName = if ($Backend -eq 'x32') { 'x32dbg-unsigned.exe' } else { 'x64dbg.exe' }
$debugger = Join-Path $backendRoot $debuggerName

$bytes = [IO.File]::ReadAllBytes($sample)
if ($bytes.Length -lt 256 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
    throw 'Sample is not a bounded PE file.'
}
$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
if ($peOffset -lt 0 -or $peOffset + 26 -gt $bytes.Length -or
    $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45) {
    throw 'Sample has an invalid PE header.'
}
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
$expectedMachine = if ($Backend -eq 'x32') { 0x014c } else { 0x8664 }
if ($machine -ne $expectedMachine) {
    throw ('Sample machine 0x{0:x4} does not match {1}.' -f $machine, $Backend)
}
$backendProcessNames = if ($Backend -eq 'x32') {
    @('x32dbg', 'x32dbg-unsigned')
} else {
    @('x64dbg', 'x64dbg-unsigned')
}
$existingDebuggers = @(Get-Process -Name $backendProcessNames -ErrorAction SilentlyContinue)
if ($existingDebuggers.Count -gt 0) {
    $processList = ($existingDebuggers | ForEach-Object {
        '{0} (PID {1})' -f $_.ProcessName, $_.Id
    }) -join ', '
    throw ("A $Backend debugger instance is already running: $processList. " +
        'Close it before starting an isolated single-instance smoke test.')
}
$sampleLeaf = [IO.Path]::GetFileName($sample)
$stagedSample = Join-Path $backendRoot $sampleLeaf
Copy-Item -LiteralPath $sample -Destination $stagedSample -Force

$plugins = @(Get-ChildItem -LiteralPath (Join-Path $backendRoot 'plugins') -File)
$expectedExtension = if ($Backend -eq 'x32') { '.dp32' } else { '.dp64' }
if ($plugins.Count -ne 1 -or
    $plugins[0].Name -ine "x64dbg-mcp-backend$expectedExtension") {
    throw 'Isolation invariant failed: exactly this project plugin must be present.'
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$tokenBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tokenBytes)
$token = [Convert]::ToBase64String($tokenBytes)
$baseUri = "http://127.0.0.1:$port"
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }

$previous = @{
    Port = $env:X64DBG_MCP_PORT
    Token = $env:X64DBG_MCP_TOKEN
    Server = $env:X64DBG_MCP_SERVER_PATH
}
$debuggerProcess = $null
$summary = $null
try {
    $env:X64DBG_MCP_PORT = [string]$port
    $env:X64DBG_MCP_TOKEN = $token
    $env:X64DBG_MCP_SERVER_PATH = $server
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $debugger
    $startInfo.WorkingDirectory = $backendRoot
    $startInfo.UseShellExecute = $false
    $debuggerProcess = [Diagnostics.Process]::Start($startInfo)

    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 100
        try {
            $ready = Invoke-RestMethod -UseBasicParsing -Uri "$baseUri/health/ready" `
                -Headers $headers -TimeoutSec 2
        } catch {
            $ready = $null
        }
    } until ($ready.status -eq 'ready' -or [DateTime]::UtcNow -ge $deadline -or
        $debuggerProcess.HasExited)
    if ($ready.status -ne 'ready') {
        throw 'Isolated debugger MCP sidecar did not become ready.'
    }
    $instanceId = ([Guid]::Parse([string]$ready.instance_id)).ToString()
    $endpoint = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction Stop)
    $sidecar = @(Get-CimInstance Win32_Process | Where-Object {
        $_.ProcessId -in $endpoint.OwningProcess -and
        $_.ParentProcessId -eq $debuggerProcess.Id -and $_.ExecutablePath -ieq $server
    })
    if ($sidecar.Count -ne 1) { throw 'MCP endpoint is not owned by the launched debugger sidecar.' }
    $pythonArgs = @($python.Arguments)
    $pythonArgs += @(
        (Join-Path $PSScriptRoot '..\tests\python\generic_sample_smoke.py'),
        '--base-url', $baseUri, '--instance-id', $instanceId, '--backend', $Backend,
        '--sample', $sample, '--staged-sample', $stagedSample, '--backend-root', $backendRoot,
        '--debugger-pid', [string]$debuggerProcess.Id,
        '--sidecar-pid', [string]$sidecar[0].ProcessId, '--port', [string]$port
    )
    if (![string]::IsNullOrEmpty($ExpectedAsciiPattern)) {
        # Windows PowerShell native argv handling strips embedded double quotes.
        $patternBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ExpectedAsciiPattern))
        $pythonArgs += "--expected-ascii-pattern-base64=$patternBase64"
    }
    # The bearer token is inherited through X64DBG_MCP_TOKEN, never argv.
    $reportJson = & $python.Source @pythonArgs
    if ($LASTEXITCODE -ne 0) { throw "Generic sample Python scenario failed (exit $LASTEXITCODE)." }
    $summary = ($reportJson -join "`n") | ConvertFrom-Json
} finally {
    if ($debuggerProcess -and !$debuggerProcess.HasExited) {
        $null = $debuggerProcess.CloseMainWindow()
        if (!$debuggerProcess.WaitForExit(7000)) {
            Stop-Process -Id $debuggerProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    $env:X64DBG_MCP_PORT = $previous.Port
    $env:X64DBG_MCP_TOKEN = $previous.Token
    $env:X64DBG_MCP_SERVER_PATH = $previous.Server
    $token = $null
    $headers = $null
}

if ($debuggerProcess -and !$debuggerProcess.HasExited) {
    throw 'Isolated debugger process remained active after teardown.'
}
$closeDeadline = [DateTime]::UtcNow.AddSeconds(5)
$listenerOpen = $false
do {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync('127.0.0.1', $port)
        $listenerOpen = $connect.Wait(250) -and $client.Connected
    } catch {
        $listenerOpen = $false
    } finally {
        $client.Dispose()
    }
    if ($listenerOpen) {
        Start-Sleep -Milliseconds 100
    }
} until (!$listenerOpen -or [DateTime]::UtcNow -ge $closeDeadline)
if ($listenerOpen) {
    throw 'MCP sidecar listener remained active after debugger teardown.'
}
if ($null -eq $summary) {
    throw 'Smoke test completed without a result summary.'
}
$summary | ConvertTo-Json -Depth 6
