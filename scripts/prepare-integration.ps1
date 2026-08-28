[CmdletBinding()]
param(
    [string]$X64dbgRoot = 'C:\tools\x64dbg',
    [string]$Destination
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $PSScriptRoot '..\artifacts\integration'
}
$resolvedRoot = (Resolve-Path -LiteralPath $X64dbgRoot).Path
$destinationPath = [System.IO.Path]::GetFullPath($Destination)
$workspacePath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (!$destinationPath.StartsWith($workspacePath + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Integration destination must remain inside the repository workspace.'
}
if (Test-Path -LiteralPath $destinationPath) {
    $existing = Get-ChildItem -LiteralPath $destinationPath -Force -ErrorAction Stop
    if ($existing.Count -ne 0) {
        throw "Integration destination already exists and is not empty: $destinationPath"
    }
} else {
    New-Item -ItemType Directory -Path $destinationPath | Out-Null
}

foreach ($backend in @('x32', 'x64')) {
    $source = Join-Path $resolvedRoot "release\$backend"
    $target = Join-Path $destinationPath $backend
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    & robocopy.exe $source $target /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP `
        /XD (Join-Path $source 'plugins') /XF '*mcp*' 'mcp_config.json' | Out-Null
    if ($LASTEXITCODE -ge 8) {
        throw "robocopy failed for $backend with exit code $LASTEXITCODE"
    }
    $pluginDirectory = Join-Path $target 'plugins'
    New-Item -ItemType Directory -Path $pluginDirectory -Force | Out-Null
    $extension = if ($backend -eq 'x32') { 'dp32' } else { 'dp64' }
    $architecture = if ($backend -eq 'x32') { 'x86' } else { 'x64' }
    $plugin = Join-Path $workspacePath "build\windows-$architecture\x64dbg-mcp-backend.$extension"
    $fixture = Join-Path $workspacePath "build\windows-$architecture\x64dbg_mcp_debuggee_fixture.exe"
    if (!(Test-Path -LiteralPath $plugin) -or !(Test-Path -LiteralPath $fixture)) {
        throw "Build the $architecture plugin and fixture before preparing integration files."
    }
    Copy-Item -LiteralPath $plugin -Destination $pluginDirectory
    Copy-Item -LiteralPath $fixture -Destination (Join-Path $target 'mcp-debuggee-fixture.exe')
}

$forbidden = Get-ChildItem -LiteralPath $destinationPath -Recurse -File |
    Where-Object {
        $_.Name -ine 'x64dbg-mcp-backend.dp32' -and
        $_.Name -ine 'x64dbg-mcp-backend.dp64' -and
        $_.Name -ine 'mcp-debuggee-fixture.exe' -and
        ($_.Name -match '(?i)mcp' -or $_.Name -ieq 'mcp_config.json')
    }
if ($forbidden) {
    throw 'Isolation check found a pre-existing MCP artifact in the integration copy.'
}

Write-Output "Prepared isolated x32/x64 integration trees at $destinationPath"
