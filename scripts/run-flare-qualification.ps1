[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackageRoot,
    [string]$X64dbgRoot = 'C:\tools\x64dbg',
    [Parameter(Mandatory)]
    [string]$SamplePath,
    [Parameter(Mandatory)]
    [string]$OutputDirectory,
    [ValidateRange(1, 20)]
    [int]$Iterations = 3
)

# Qualify a fresh package in a separate installed-layout runtime, never the source installation.
$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
$source = (Resolve-Path -LiteralPath $X64dbgRoot).Path.TrimEnd('\')
$package = (Resolve-Path -LiteralPath $PackageRoot).Path
$sample = (Resolve-Path -LiteralPath $SamplePath).Path
if (!$output.StartsWith($workspace + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory must be a new directory strictly inside the repository workspace (prefer build).'
}
if (Test-Path -LiteralPath $output) { throw 'OutputDirectory already exists; use a fresh directory.' }
if (!(Test-Path -LiteralPath (Split-Path -Parent $output) -PathType Container)) {
    throw 'OutputDirectory parent must already exist.'
}

# Permit only the repository build junction, not arbitrary redirects under the workspace.
$build = Join-Path $workspace 'build'
$physicalOutput = $null
$ancestor = Split-Path -Parent $output
while ($ancestor -and $ancestor -ine $workspace) {
    $item = Get-Item -LiteralPath $ancestor -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        if ($ancestor -ine $build -or !$item.Target -or @($item.Target).Count -ne 1) {
            throw 'OutputDirectory has an unapproved reparse-point ancestor.'
        }
        $physical = [IO.Path]::GetFullPath([string]@($item.Target)[0]).TrimEnd('\')
        $physicalOutput = $physical + $output.Substring($build.Length)
        if ($physicalOutput -ieq $source -or
            $physicalOutput.StartsWith($source + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The build junction must not target the source runtime.'
        }
        $targetAncestor = $physical
        while ($targetAncestor) {
            if ((Get-Item -LiteralPath $targetAncestor -Force).Attributes -band
                [IO.FileAttributes]::ReparsePoint) {
                throw 'The build junction target has another reparse-point ancestor.'
            }
            $targetAncestor = Split-Path -Parent $targetAncestor
        }
    }
    $ancestor = Split-Path -Parent $ancestor
}
foreach ($root in @($workspace, $source)) {
    $ancestor = $root
    while ($ancestor) {
        if ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Workspace and source runtime ancestors must not be reparse points.'
        }
        $ancestor = Split-Path -Parent $ancestor
    }
}
if ($output.StartsWith($source + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDirectory must not be inside the source runtime.'
}

function Assert-FlareTree([string]$Root, [switch]$SourceRuntime) {
    # Walk one level at a time so no reparse point is followed, even during preflight.
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    while ($pending.Count) {
        $directory = $pending.Pop()
        if ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Runtime isolation rejects reparse points.'
        }
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
            if ($SourceRuntime -and (($directory -ieq $Root -and $item.Name -ieq 'plugins') -or
                (!$item.PSIsContainer -and $item.Name -like '*mcp*'))) { continue }
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Runtime isolation rejects nested reparse points.'
            }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
}

if ((Get-Item -LiteralPath (Join-Path $source 'release') -Force).Attributes -band
    [IO.FileAttributes]::ReparsePoint) { throw 'Source release must not be a reparse point.' }
foreach ($backend in @('x32', 'x64')) {
    Assert-FlareTree (Join-Path $source "release\$backend") -SourceRuntime
}
$binaries = @(
    @('mcp\x96dbg-mcp-server.exe', 'mcp\x96dbg-mcp-server.exe'),
    @('mcp\x96dbg-mcp-control.exe', 'mcp\x96dbg-mcp-control.exe'),
    @('x32\x64dbg-mcp-backend.dp32', 'x32\plugins\x64dbg-mcp-backend.dp32'),
    @('x64\x64dbg-mcp-backend.dp64', 'x64\plugins\x64dbg-mcp-backend.dp64')
)
$packageHashes = @{}
foreach ($binary in $binaries) {
    $packageHashes[$binary[0]] = (Get-FileHash -LiteralPath (Join-Path $package $binary[0]) -Algorithm SHA256).Hash
}
$sampleHash = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash
. (Join-Path $PSScriptRoot 'python-test-runtime.ps1')
$python = Get-TestPython
if (@(Get-Process -Name 'x64dbg', 'x64dbg-unsigned' -ErrorAction SilentlyContinue).Count) {
    throw 'An x64 debugger is already running; coordinate serial qualification first.'
}

$runtime = Join-Path $output 'runtime'
$release = Join-Path $runtime 'release'
# Use physical launch paths so CIM ownership checks do not depend on junction spelling.
$runtimeForLaunch = if ($physicalOutput) { Join-Path $physicalOutput 'runtime' } else { $runtime }
$previousEnvironment = @{}
$reservations = @()
$installedHashes = @{}
$runs = @()
$passed = $false
$stagedSample = $null
New-Item -ItemType Directory -Path $output | Out-Null
try {
    foreach ($entry in Get-ChildItem Env:) {
        if ($entry.Name -like 'X64DBG_MCP_*' -and $entry.Name -ine 'X64DBG_MCP_TEST_PYTHON') {
            $previousEnvironment[$entry.Name] = $entry.Value
            [Environment]::SetEnvironmentVariable($entry.Name, $null, 'Process')
        }
    }
    New-Item -ItemType Directory -Path $runtime | Out-Null
    & (Join-Path $PSScriptRoot 'prepare-integration.ps1') -X64dbgRoot $source -Destination $release | Out-Null
    Assert-FlareTree $release
    foreach ($backend in @('x32', 'x64')) {
        # Never inspect source settings. Delete only our copies, restoring portable defaults.
        foreach ($name in @('x32dbg.ini', 'x32dbg-unsigned.ini', 'x64dbg.ini',
                'x64dbg-unsigned.ini', 'userdir', 'qt.conf')) {
            $copiedSetting = Join-Path $release "$backend\$name"
            if (Test-Path -LiteralPath $copiedSetting -PathType Leaf) {
                Remove-Item -LiteralPath $copiedSetting -Force
            } elseif (Test-Path -LiteralPath $copiedSetting) {
                throw 'A copied settings path is unexpectedly a directory.'
            }
        }
    }
    foreach ($unused in 1..2) {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.ExclusiveAddressUse = $true
        $listener.Start()
        $reservations += $listener
    }
    $ports = @($reservations | ForEach-Object { ([Net.IPEndPoint]$_.LocalEndpoint).Port })
    # Installer success output includes credentials. Never capture it in a report or transcript.
    & (Join-Path $PSScriptRoot 'install.ps1') -PackageRoot $package -X64dbgRoot $runtime `
        -X32Port $ports[0] -X64Port $ports[1] | Out-Null
    Assert-FlareTree $release
    foreach ($binary in $binaries) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $release $binary[1]) -Algorithm SHA256).Hash
        if ($hash -ne $packageHashes[$binary[0]] -or
            $hash -ne (Get-FileHash -LiteralPath (Join-Path $package $binary[0]) -Algorithm SHA256).Hash) {
            throw 'Installed binary hash differs from the supplied package.'
        }
        $installedHashes[$binary[1]] = $hash.ToLowerInvariant()
    }
    $pluginDirectories = @(Get-ChildItem -LiteralPath $release -Directory -Recurse -Force |
        Where-Object { $_.Name -ieq 'plugins' })
    if ($pluginDirectories.Count -ne 2) { throw 'Isolation requires exactly two plugin directories.' }
    foreach ($backend in @('x32', 'x64')) {
        $plugins = @(Get-ChildItem -LiteralPath (Join-Path $release "$backend\plugins") -Force)
        $extension = if ($backend -eq 'x32') { 'dp32' } else { 'dp64' }
        if ($plugins.Count -ne 1 -or $plugins[0].Name -ine "x64dbg-mcp-backend.$extension" -or
            $plugins[0].PSIsContainer) { throw 'Isolation requires only this project plugin.' }
    }
    $sampleDirectory = Join-Path $output 'sample'
    New-Item -ItemType Directory -Path $sampleDirectory | Out-Null
    $stagedSample = Join-Path $sampleDirectory ([IO.Path]::GetFileName($sample))
    Copy-Item -LiteralPath $sample -Destination $stagedSample
    if ((Get-FileHash -LiteralPath $stagedSample -Algorithm SHA256).Hash -ne $sampleHash) {
        throw 'Staged sample differs from the supplied sample.'
    }
    foreach ($listener in $reservations) { $listener.Stop() }
    $reservations = @()
    for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
        Assert-FlareTree $runtime
        $runDirectory = Join-Path $output ('iteration-{0:d2}' -f $iteration)
        New-Item -ItemType Directory -Path $runDirectory | Out-Null
        $pythonArgs = @($python.Arguments) + @(
            '-m', 'pytest', (Join-Path $workspace 'tests\python\test_live.py'),
            '-m', 'installed_flare', '--run-live', '--integration-root', $release,
            '--server-path', (Join-Path $package 'mcp\x96dbg-mcp-server.exe'),
            '--x64dbg-root', $runtimeForLaunch, '--flare-sample', $stagedSample,
            '--report-directory', $runDirectory, '--junitxml', (Join-Path $runDirectory 'junit.xml'),
            '-q'
        )
        & $python.Source @pythonArgs 2>&1 | Out-File -LiteralPath (Join-Path $runDirectory 'pytest.log') -Encoding utf8
        if ($LASTEXITCODE -ne 0) { throw "Installed Flare iteration $iteration failed; see its pytest.log." }
        $report = Get-Content -LiteralPath (Join-Path $runDirectory 'installed-flare.json') -Raw | ConvertFrom-Json
        foreach ($field in @('stopped', 'endpoint_parent_verified', 'owned_debugger_exited',
                'owned_sidecar_exited', 'loopback_port_closed', 'sample_unchanged')) {
            if ($report.$field -ne $true) { throw "Iteration $iteration did not confirm $field." }
        }
        if (@(Get-Process -Name 'x64dbg', 'x64dbg-unsigned' -ErrorAction SilentlyContinue).Count -or
            @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                $_.State -eq 'Listen' -and $_.LocalPort -in $ports
            }).Count) { throw "Iteration $iteration left an active host or endpoint." }
        if ((Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash -ne $sampleHash -or
            (Get-FileHash -LiteralPath $stagedSample -Algorithm SHA256).Hash -ne $sampleHash) {
            throw "Sample hash changed in iteration $iteration."
        }
        $runs += $report
    }
    $passed = $true
} finally {
    foreach ($listener in $reservations) { $listener.Stop() }
    foreach ($entry in @(Get-ChildItem Env:)) {
        if ($entry.Name -like 'X64DBG_MCP_*' -and $entry.Name -ine 'X64DBG_MCP_TEST_PYTHON') {
            [Environment]::SetEnvironmentVariable($entry.Name, $null, 'Process')
        }
    }
    foreach ($name in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    $sampleAfter = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash
    $stagedAfter = if ($stagedSample -and (Test-Path -LiteralPath $stagedSample -PathType Leaf)) {
        (Get-FileHash -LiteralPath $stagedSample -Algorithm SHA256).Hash
    } else { $null }
    $unchanged = $sampleAfter -eq $sampleHash -and (!$stagedSample -or $stagedAfter -eq $sampleHash)
    [ordered]@{
        passed = $passed -and $unchanged
        iterations_requested = $Iterations
        iterations_completed = $runs.Count
        package_root = $package
        isolated_root = $runtime
        installed_sha256 = $installedHashes
        sample_sha256_before = $sampleHash.ToLowerInvariant()
        sample_sha256_after = $sampleAfter.ToLowerInvariant()
        staged_sample_sha256_after = $stagedAfter
        sample_unchanged = $unchanged
        reports = $runs
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'qualification.json') -Encoding UTF8
    if (!$unchanged) { throw 'Source or staged sample changed during qualification.' }
}
Write-Output "Installed Flare qualification passed $Iterations iterations. Report: $(Join-Path $output 'qualification.json')"
