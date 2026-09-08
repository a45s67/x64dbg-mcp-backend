[CmdletBinding()]
param(
    [ValidateSet('x32', 'x64', 'both')]
    [string]$Backend = 'both',
    [ValidateRange(1, 20)]
    [int]$Iterations = 3,
    [string]$IntegrationRoot,
    [string]$ServerPath
)

$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot 'run-real-integration.ps1'
$backends = if ($Backend -eq 'both') { @('x32', 'x64') } else { @($Backend) }

function Test-LoopbackPortOpen([int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync('127.0.0.1', $Port)
        if (!$task.Wait(300)) {
            return $false
        }
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

$reports = @()
$observedInstanceIds = @{}
foreach ($iteration in 1..$Iterations) {
    foreach ($currentBackend in $backends) {
        Write-Verbose "Integration soak $iteration/$Iterations ($currentBackend)"
        $existingSidecarIds = @(Get-Process -Name 'x64dbg-mcp-server' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Id })
        $arguments = @{
            Backend = $currentBackend
        }
        if (![string]::IsNullOrWhiteSpace($IntegrationRoot)) {
            $arguments.IntegrationRoot = $IntegrationRoot
        }
        if (![string]::IsNullOrWhiteSpace($ServerPath)) {
            $arguments.ServerPath = $ServerPath
        }
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $json = & $runner @arguments | Out-String
        $timer.Stop()
        $report = $json | ConvertFrom-Json
        $report | Add-Member -NotePropertyName elapsed_seconds -NotePropertyValue $timer.Elapsed.TotalSeconds
        if (!$report.debugger_host_process_id -or !$report.sidecar_port -or !$report.instance_id) {
            throw 'Integration report omitted lifecycle ownership fields.'
        }
        $canonicalInstanceId = ([Guid]::Parse([string]$report.instance_id)).ToString()
        if ($observedInstanceIds.ContainsKey($canonicalInstanceId)) {
            throw "Backend instance identity was reused: $canonicalInstanceId"
        }
        $observedInstanceIds[$canonicalInstanceId] = $true

        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $ownedSidecars = @(Get-Process -Name 'x64dbg-mcp-server' -ErrorAction SilentlyContinue |
                Where-Object { $_.Id -notin $existingSidecarIds })
            $portOpen = Test-LoopbackPortOpen ([int]$report.sidecar_port)
            if ($ownedSidecars.Count -eq 0 -and !$portOpen) {
                break
            }
            Start-Sleep -Milliseconds 100
        } until ([DateTime]::UtcNow -ge $deadline)
        if ($ownedSidecars.Count -ne 0 -or $portOpen) {
            throw "Owned sidecar or listener remained after $currentBackend integration cleanup."
        }
        $reports += $report
    }
}

[ordered]@{
    iterations = $Iterations
    backends = $backends
    runs = $reports.Count
    all_owned_sidecars_exited = $true
    all_loopback_ports_closed = $true
    reports = $reports
} | ConvertTo-Json -Depth 8
