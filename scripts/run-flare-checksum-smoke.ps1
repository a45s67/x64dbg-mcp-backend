[CmdletBinding()]
param(
    [string]$X64dbgRoot = 'C:\tools\x64dbg',
    [Parameter(Mandatory)]
    [string]$SamplePath,
    [string]$MainRva = '0xa78a0'
)

$ErrorActionPreference = 'Stop'
# x64dbg can forward a launch to an existing single-instance host, even in another tree.
if (@(Get-Process -Name 'x64dbg', 'x64dbg-unsigned' -ErrorAction SilentlyContinue).Count) {
    throw 'An x64 debugger is already running. Close it before installed Flare qualification.'
}
. (Join-Path $PSScriptRoot 'python-test-runtime.ps1')
$python = Get-TestPython
$releaseRoot = Join-Path (Resolve-Path -LiteralPath $X64dbgRoot).Path 'release'
$debugger = Join-Path $releaseRoot 'x64\x64dbg.exe'
$configPath = Join-Path $releaseRoot 'mcp\x64dbg-mcp-server-x64.toml'
$server = Join-Path $releaseRoot 'mcp\x96dbg-mcp-server.exe'
$sample = (Resolve-Path -LiteralPath $SamplePath).Path
foreach ($required in @($debugger, $server, $configPath, $sample)) {
    if (!(Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required file is missing: $required"
    }
}

$config = Get-Content -LiteralPath $configPath -Raw
$portMatch = [regex]::Match($config, '(?m)^port = ([0-9]+)\r?$')
$tokenMatch = [regex]::Match($config, '(?m)^bearer_token = "([^"\r\n]+)"\r?$')
$bindMatch = [regex]::Match($config, '(?m)^bind = "127\.0\.0\.1"\r?$')
if (!$portMatch.Success -or !$tokenMatch.Success -or !$bindMatch.Success) {
    throw 'Installed x64 configuration requires a loopback bind, port, and bearer_token.'
}
$port = [int]$portMatch.Groups[1].Value
if ($port -lt 1 -or $port -gt 65535) { throw 'Installed x64 port is invalid.' }
$token = $tokenMatch.Groups[1].Value
$config = $null
$tokenMatch = $null
$baseUri = "http://127.0.0.1:$port"
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }
$previousToken = $env:X64DBG_MCP_TOKEN
$sampleHash = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash

function Get-FlareListeners {
    # Enumerating first distinguishes an empty result from a failed TCP table query.
    @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
        $_.State -eq 'Listen' -and $_.LocalPort -eq $port
    })
}
if (@(Get-FlareListeners).Count) { throw 'Installed Flare port is already in use; refusing endpoint reuse.' }

$debuggerProcess = $null
$sidecarProcess = $null
$report = $null
$cleanupConfirmed = $false
try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $debugger
    $startInfo.WorkingDirectory = Split-Path -Parent $debugger
    $startInfo.UseShellExecute = $false
    foreach ($name in @($startInfo.EnvironmentVariables.Keys)) {
        if ($name -like 'X64DBG_MCP_*') { $startInfo.EnvironmentVariables.Remove($name) }
    }
    # Symbol engine environment paths must not redirect writes out of the isolated tree.
    foreach ($name in @('_NT_SYMBOL_PATH', '_NT_ALT_SYMBOL_PATH')) {
        $startInfo.EnvironmentVariables.Remove($name)
    }
    $debuggerProcess = [System.Diagnostics.Process]::Start($startInfo)
    $null = $debuggerProcess.Handle

    $ready = $null
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 100
        $endpoint = @(Get-FlareListeners)
        if (!$endpoint.Count) { continue }
        $sidecar = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.ProcessId -in $endpoint.OwningProcess -and
            $_.ParentProcessId -eq $debuggerProcess.Id -and
            $_.ExecutablePath -ieq $server
        })
        if ($sidecar.Count -ne 1 -or
            @($endpoint | Where-Object {
                $_.OwningProcess -ne $sidecar[0].ProcessId -or $_.LocalAddress -ne '127.0.0.1'
            }).Count) {
            throw 'Installed MCP endpoint is not owned by the launched debugger sidecar.'
        }
        if (!$sidecarProcess) {
            $sidecarProcess = Get-Process -Id $sidecar[0].ProcessId -ErrorAction Stop
            $null = $sidecarProcess.Handle
        }
        if ($sidecarProcess.HasExited -or $debuggerProcess.HasExited) {
            throw 'Owned installed host or sidecar exited during startup.'
        }
        # Authenticate only after establishing listener ownership, never against an arbitrary port.
        try {
            $ready = Invoke-RestMethod -UseBasicParsing -Uri "$baseUri/health/ready" `
                -Headers $headers -TimeoutSec 2
        } catch {
            $ready = $null
        }
    } until ($ready.status -eq 'ready' -or [DateTime]::UtcNow -ge $readyDeadline -or
        $debuggerProcess.HasExited)
    if ($ready.status -ne 'ready') {
        throw 'Installed x64 backend did not become ready.'
    }
    $instanceId = ([Guid]::Parse([string]$ready.instance_id)).ToString()

    $pythonArgs = @($python.Arguments)
    $pythonArgs += @(
        (Join-Path $PSScriptRoot '..\tests\python\flare_checksum_smoke.py'),
        '--base-url', $baseUri, '--instance-id', $instanceId, '--sample', $sample,
        "--main-rva=$MainRva", '--debugger-pid', [string]$debuggerProcess.Id,
        '--sidecar-pid', [string]$sidecarProcess.Id, '--port', [string]$port
    )
    # Set only for Python, leaving installed debugger configuration precedence unchanged.
    $env:X64DBG_MCP_TOKEN = $token
    $reportJson = & $python.Source @pythonArgs
    if ($LASTEXITCODE -ne 0) { throw "Flare checksum Python scenario failed (exit $LASTEXITCODE)." }
    $report = ($reportJson -join "`n") | ConvertFrom-Json
    if ($null -eq $report) { throw 'Flare scenario completed without a result summary.' }
} finally {
    try {
        # Capture only a verified direct child if startup failed before it opened its listener.
        if ($debuggerProcess -and !$debuggerProcess.HasExited -and !$sidecarProcess) {
            $children = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
                $_.ParentProcessId -eq $debuggerProcess.Id -and $_.ExecutablePath -ieq $server
            })
            if ($children.Count -eq 1) {
                $sidecarProcess = Get-Process -Id $children[0].ProcessId -ErrorAction SilentlyContinue
                if ($sidecarProcess) { $null = $sidecarProcess.Handle }
            }
        }
    } finally {
        try {
            if ($debuggerProcess -and !$debuggerProcess.HasExited) {
                $null = $debuggerProcess.CloseMainWindow()
                if (!$debuggerProcess.WaitForExit(7000)) {
                    $debuggerProcess.Kill()
                    if (!$debuggerProcess.WaitForExit(5000)) { throw 'Owned debugger did not exit.' }
                }
            }
        } finally {
            try {
                if ($sidecarProcess -and !$sidecarProcess.WaitForExit(5000)) {
                    $sidecarProcess.Kill()
                    if (!$sidecarProcess.WaitForExit(5000)) { throw 'Owned sidecar did not exit.' }
                }
                $closeDeadline = [DateTime]::UtcNow.AddSeconds(5)
                do {
                    $listeners = @(Get-FlareListeners)
                    if (!$listeners.Count) { break }
                    Start-Sleep -Milliseconds 100
                } while ([DateTime]::UtcNow -lt $closeDeadline)
                if ($listeners.Count) { throw 'Installed Flare listener remained open after teardown.' }
                $cleanupConfirmed = $debuggerProcess -and $debuggerProcess.HasExited -and
                    $sidecarProcess -and $sidecarProcess.HasExited
            } finally {
                $env:X64DBG_MCP_TOKEN = $previousToken
                $token = $null
                $headers = $null
                if ((Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash -ne $sampleHash) {
                    throw 'Flare sample hash changed during qualification.'
                }
            }
        }
    }
}

if (!$cleanupConfirmed -or !$report) { throw 'Flare qualification did not confirm owned process cleanup.' }
$report | Add-Member -NotePropertyMembers @{
    owned_debugger_exited = $true
    owned_sidecar_exited = $true
    loopback_port_closed = $true
    sample_sha256_before = $sampleHash.ToLowerInvariant()
    sample_sha256_after = $sampleHash.ToLowerInvariant()
    sample_unchanged = $true
}
$report | ConvertTo-Json -Depth 6
