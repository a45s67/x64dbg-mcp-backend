[CmdletBinding()]
param(
    [string]$Version = '0.3.0-beta',
    [string]$OutputDirectory,
    [string]$X64dbgRoot = 'C:\tools\x64dbg'
)

$ErrorActionPreference = 'Stop'

function Get-ServerExecutable([string[]]$Messages, [string]$ServerManifest) {
    $artifacts = @($Messages | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object {
        $_.reason -ceq 'compiler-artifact' -and
        $_.target.name -ceq 'x64dbg-mcp-server' -and
        $_.target.kind.Count -eq 1 -and $_.target.kind[0] -ceq 'bin' -and
        !$_.profile.test -and
        ![string]::IsNullOrWhiteSpace($_.manifest_path) -and
        [IO.Path]::GetFullPath($_.manifest_path) -ieq [IO.Path]::GetFullPath($ServerManifest)
    })
    if ($artifacts.Count -ne 1 -or [string]::IsNullOrWhiteSpace($artifacts[0].executable)) {
        throw 'Expected exactly one server binary artifact with an executable path.'
    }
    return $artifacts[0].executable
}

$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $workspace 'dist'
}
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
if (!$output.StartsWith($workspace + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Package output must remain inside the repository workspace.'
}
$stage = Join-Path $output "x64dbg-mcp-backend-$Version"
$archive = "$stage.zip"
if ((Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $archive)) {
    throw 'Refusing to overwrite an existing release stage or archive.'
}

$previousX64dbgRoot = $env:X64DBG_ROOT
$env:X64DBG_ROOT = $X64dbgRoot
Push-Location $workspace
try {
    $cargoMessages = & cargo.exe build --offline --locked --release --message-format=json
    if ($LASTEXITCODE -ne 0) { throw 'Rust release build failed.' }
    $serverSource = Get-ServerExecutable -Messages $cargoMessages `
        -ServerManifest (Join-Path $workspace 'crates\server\Cargo.toml')
    & cmd.exe /d /c (Join-Path $workspace 'scripts\build-plugin.cmd') x86
    if ($LASTEXITCODE -ne 0) { throw 'x86 plugin build failed.' }
    & cmd.exe /d /c (Join-Path $workspace 'scripts\build-plugin.cmd') x64
    if ($LASTEXITCODE -ne 0) { throw 'x64 plugin build failed.' }

    New-Item -ItemType Directory -Path $stage | Out-Null
    foreach ($relative in @('x32', 'x64', 'mcp')) {
        New-Item -ItemType Directory -Path (Join-Path $stage $relative) -Force | Out-Null
    }
    Copy-Item -LiteralPath 'build\windows-x86\x64dbg-mcp-backend.dp32' `
        -Destination (Join-Path $stage 'x32')
    Copy-Item -LiteralPath 'build\windows-x64\x64dbg-mcp-backend.dp64' `
        -Destination (Join-Path $stage 'x64')
    Copy-Item -LiteralPath $serverSource `
        -Destination (Join-Path $stage 'mcp\x96dbg-mcp-server.exe')
    Copy-Item -LiteralPath 'build\windows-x64\x96dbg-mcp-control.exe' `
        -Destination (Join-Path $stage 'mcp\x96dbg-mcp-control.exe')
    Copy-Item -Path 'config\*.toml' -Destination (Join-Path $stage 'mcp')
    Copy-Item -LiteralPath 'scripts\install.ps1' -Destination (Join-Path $stage 'install.ps1')
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $workspace 'scripts\verify-package.ps1') -PackageRoot $stage
    if ($LASTEXITCODE -ne 0) { throw 'Package layout verification failed.' }
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archiveStream = [System.IO.File]::Open($archive, [System.IO.FileMode]::CreateNew)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new(
            $archiveStream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $prefix = [System.IO.Path]::GetFileName($stage)
            $fixedTimestamp = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            foreach ($file in Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName) {
                $relative = $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
                $entry = $zip.CreateEntry("$prefix/$relative",
                    [System.IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $fixedTimestamp
                $entryStream = $entry.Open()
                $inputStream = [System.IO.File]::OpenRead($file.FullName)
                try { $inputStream.CopyTo($entryStream) } finally {
                    $inputStream.Dispose()
                    $entryStream.Dispose()
                }
            }
        } finally { $zip.Dispose() }
    } finally { $archiveStream.Dispose() }
    Write-Output "Created $archive"
} finally {
    Pop-Location
    if ($null -eq $previousX64dbgRoot) {
        Remove-Item Env:X64DBG_ROOT -ErrorAction SilentlyContinue
    } else {
        $env:X64DBG_ROOT = $previousX64dbgRoot
    }
}
