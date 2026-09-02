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
$version = (Get-Content -LiteralPath (Join-Path $workspace 'Cargo.toml') |
    Select-String -Pattern '^version = "([^"]+)"$' | Select-Object -First 1).Matches.Groups[1].Value
if ([string]::IsNullOrWhiteSpace($version)) {
    throw 'Could not determine the workspace package version.'
}

Push-Location $workspace
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $PSScriptRoot 'package.ps1') `
        -Version $version -OutputDirectory $packageOutput -X64dbgRoot $X64dbgRoot
    if ($LASTEXITCODE -ne 0) { throw 'Package gate failed.' }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $PSScriptRoot 'prepare-integration.ps1') `
        -X64dbgRoot $X64dbgRoot -Destination $integrationRoot
    if ($LASTEXITCODE -ne 0) { throw 'Integration preparation failed.' }

    $soakText = & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $PSScriptRoot 'run-integration-soak.ps1') `
        -Backend both -Iterations $IntegrationIterations `
        -IntegrationRoot $integrationRoot `
        -ServerPath (Join-Path $workspace 'target\release\x64dbg-mcp-server.exe') |
        Out-String
    if ($LASTEXITCODE -ne 0) { throw 'Real-debugger integration gate failed.' }
    $soak = $soakText | ConvertFrom-Json

    $hostControl = [ordered]@{}
    foreach ($backend in @('x32', 'x64')) {
        $controlOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File (Join-Path $PSScriptRoot 'run-host-control-integration.ps1') `
            -Backend $backend -IntegrationRoot $integrationRoot `
            -ServerPath (Join-Path $workspace 'target\release\x64dbg-mcp-server.exe') `
            -ControllerPath (Join-Path $workspace 'build\windows-x64\x96dbg-mcp-control.exe')
        if ($LASTEXITCODE -ne 0) { throw "Host control integration failed for $backend." }
        $hostControl[$backend] = ($controlOutput -join "`n")
    }

    $flare = $null
    if (![string]::IsNullOrWhiteSpace($InstalledFlareSamplePath)) {
        $flareText = & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File (Join-Path $PSScriptRoot 'run-flare-checksum-smoke.ps1') `
            -X64dbgRoot $X64dbgRoot -SamplePath $InstalledFlareSamplePath |
            Out-String
        if ($LASTEXITCODE -ne 0) { throw 'Installed Flare-On qualification failed.' }
        $flare = $flareText | ConvertFrom-Json
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
}
