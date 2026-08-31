[CmdletBinding()]
param(
    [string]$Version = '0.1.0',
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
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

Push-Location $workspace
try {
    & cargo.exe build --offline --locked --release
    if ($LASTEXITCODE -ne 0) { throw 'Rust release build failed.' }
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
    Copy-Item -LiteralPath 'target\release\x64dbg-mcp-server.exe' `
        -Destination (Join-Path $stage 'mcp\x96dbg-mcp-server.exe')
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
}
