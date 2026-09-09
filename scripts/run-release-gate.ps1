[CmdletBinding()]
param(
    [string]$X64dbgRoot = 'C:\tools\x64dbg',
    [ValidateRange(1, 20)]
    [int]$IntegrationIterations = 1,
    [string]$OutputDirectory,
    [string]$InstalledFlareSamplePath
)

$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
    $OutputDirectory = Join-Path $workspace "artifacts\release-gate\$stamp"
}
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
if (!$output.StartsWith($workspace + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Release-gate output must remain inside the repository workspace.'
}
if (Test-Path -LiteralPath $output) {
    throw "Refusing to reuse an existing release-gate output directory: $output"
}

$packageOutput = Join-Path $output 'package'
$integrationRoot = Join-Path $output 'integration'
$pythonReports = Join-Path $output 'python-reports'
$version = (Get-Content -LiteralPath (Join-Path $workspace 'Cargo.toml') |
    Select-String -Pattern '^version = "([^"]+)"$' | Select-Object -First 1).Matches.Groups[1].Value
if ([string]::IsNullOrWhiteSpace($version)) {
    throw 'Could not determine the workspace package version.'
}

. (Join-Path $PSScriptRoot 'python-test-runtime.ps1')
$python = Get-TestPython
$pythonPrefix = @($python.Arguments)
& $python.Source @pythonPrefix -c 'import sys; assert sys.version_info >= (3, 11); import pytest'
if ($LASTEXITCODE -ne 0) {
    throw 'Python 3.11+ and pytest are required. Run py -3 -m pip install -r requirements-test.txt (or python -m pip) first.'
}

$previousX64dbgRoot = $env:X64DBG_ROOT
$env:X64DBG_ROOT = $X64dbgRoot
Push-Location $workspace
try {
    & cargo.exe fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'Rust formatting gate failed.' }
    & cargo.exe test --offline --locked --workspace --all-targets
    if ($LASTEXITCODE -ne 0) { throw 'Rust test gate failed; fetch locked dependencies before running this offline gate.' }
    & cargo.exe clippy --offline --locked --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Rust Clippy gate failed.' }
    foreach ($architecture in @('x86', 'x64')) {
        & cmd.exe /d /c (Join-Path $PSScriptRoot 'build-plugin.cmd') $architecture test
        if ($LASTEXITCODE -ne 0) { throw "Native $architecture test gate failed." }
    }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $PSScriptRoot 'package.ps1') `
        -Version $version -OutputDirectory $packageOutput -X64dbgRoot $X64dbgRoot
    if ($LASTEXITCODE -ne 0) { throw 'Package gate failed.' }

    # Cargo may use a redirected target directory or an explicit target triple.
    # Keep its executable name for the soak wrapper's process ownership checks,
    # but require the exact bytes just shipped in the newly created package.
    $messages = & cargo.exe build --offline --locked --release --bin x64dbg-mcp-server --message-format=json
    if ($LASTEXITCODE -ne 0) { throw 'Release server artifact discovery failed.' }
    $manifest = Join-Path $workspace 'crates\server\Cargo.toml'
    $artifacts = @($messages | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object {
        $_.reason -ceq 'compiler-artifact' -and
        $_.target.name -ceq 'x64dbg-mcp-server' -and
        $_.target.kind -contains 'bin' -and !$_.profile.test -and
        $_.manifest_path -and [IO.Path]::GetFullPath($_.manifest_path) -ieq $manifest -and
        $_.executable
    })
    if ($artifacts.Count -ne 1) { throw 'Expected exactly one release server executable artifact.' }
    $serverPath = (Resolve-Path -LiteralPath $artifacts[0].executable).Path
    $packageStage = Join-Path $packageOutput "x64dbg-mcp-backend-$version"
    $packagedServer = Join-Path $packageStage 'mcp\x96dbg-mcp-server.exe'
    if ((Get-FileHash -LiteralPath $serverPath -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $packagedServer -Algorithm SHA256).Hash) {
        throw 'The release test executable does not match the newly packaged server.'
    }

    & $python.Source @pythonPrefix -m pytest tests/python `
        --server-path $serverPath --junitxml (Join-Path $output 'pytest-unit-http.xml')
    if ($LASTEXITCODE -ne 0) { throw 'Python unit and real HTTP gate failed.' }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $PSScriptRoot 'prepare-integration.ps1') `
        -X64dbgRoot $X64dbgRoot -Destination $integrationRoot
    if ($LASTEXITCODE -ne 0) { throw 'Integration preparation failed.' }

    & $python.Source @pythonPrefix -m pytest tests/python/test_live.py `
        --run-live --integration-root $integrationRoot --server-path $serverPath `
        --integration-iterations $IntegrationIterations --report-directory $pythonReports `
        --junitxml (Join-Path $output 'pytest-live.xml')
    if ($LASTEXITCODE -ne 0) { throw 'Python real-debugger integration gate failed.' }
    $soakReports = @()
    $attach = [ordered]@{}
    $generic = [ordered]@{}
    foreach ($backend in @('x32', 'x64')) {
        $backendSoak = Get-Content -LiteralPath (Join-Path $pythonReports "real-$backend.json") -Raw | ConvertFrom-Json
        if (!$backendSoak.all_owned_sidecars_exited -or !$backendSoak.all_loopback_ports_closed) {
            throw "Soak cleanup checks failed for $backend."
        }
        $soakReports += @($backendSoak.reports)
        $attach[$backend] = Get-Content -LiteralPath (Join-Path $pythonReports "attach-$backend.json") -Raw | ConvertFrom-Json
        $generic[$backend] = Get-Content -LiteralPath (Join-Path $pythonReports "generic-$backend.json") -Raw | ConvertFrom-Json
    }
    $soak = [ordered]@{
        iterations = $IntegrationIterations
        backends = @('x32', 'x64')
        runs = $soakReports.Count
        all_owned_sidecars_exited = $true
        all_loopback_ports_closed = $true
        reports = $soakReports
    }

    $hostControl = [ordered]@{}
    foreach ($backend in @('x32', 'x64')) {
        $controlOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File (Join-Path $PSScriptRoot 'run-host-control-integration.ps1') `
            -Backend $backend -IntegrationRoot $integrationRoot `
            -ServerPath $serverPath `
            -ControllerPath (Join-Path $packageStage 'mcp\x96dbg-mcp-control.exe')
        if ($LASTEXITCODE -ne 0) { throw "Host control integration failed for $backend." }
        $hostControl[$backend] = ($controlOutput -join "`n")
    }

    $flare = $null
    if (![string]::IsNullOrWhiteSpace($InstalledFlareSamplePath)) {
        & $python.Source @pythonPrefix -m pytest tests/python/test_live.py -m installed_flare `
            --run-live --integration-root $integrationRoot --server-path $serverPath `
            --x64dbg-root $X64dbgRoot --flare-sample $InstalledFlareSamplePath `
            --report-directory $pythonReports --junitxml (Join-Path $output 'pytest-installed-flare.xml')
        if ($LASTEXITCODE -ne 0) { throw 'Installed Flare-On qualification failed.' }
        $flare = Get-Content -LiteralPath (Join-Path $pythonReports 'installed-flare.json') -Raw | ConvertFrom-Json
    }

    $archive = Join-Path $packageOutput "x64dbg-mcp-backend-$version.zip"
    $report = [ordered]@{
        schema_version = 1
        version = $version
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        package = [ordered]@{
            path = $archive.Substring($workspace.Length + 1).Replace('\', '/')
            sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
            offline_verified = $true
        }
        real_debugger_integration = $soak
        attach_integration = $attach
        generic_sample_smoke = $generic
        python_tests = [ordered]@{
            unit_http_junit = (Join-Path $output 'pytest-unit-http.xml').Substring($workspace.Length + 1).Replace('\', '/')
            live_junit = (Join-Path $output 'pytest-live.xml').Substring($workspace.Length + 1).Replace('\', '/')
            report_directory = $pythonReports.Substring($workspace.Length + 1).Replace('\', '/')
        }
        host_control_integration = $hostControl
        installed_flare_qualification = $flare
        publisher_qualification = 'not_run'
        publisher_requirements = @('authenticode_signing', 'pristine_windows_vm_install')
    }
    $reportPath = Join-Path $output 'release-gate-report.json'
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    $report | ConvertTo-Json -Depth 10
} finally {
    Pop-Location
    if ($null -eq $previousX64dbgRoot) {
        Remove-Item Env:X64DBG_ROOT -ErrorAction SilentlyContinue
    } else {
        $env:X64DBG_ROOT = $previousX64dbgRoot
    }
}
