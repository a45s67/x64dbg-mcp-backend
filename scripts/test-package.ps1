[CmdletBinding()]
param([Parameter(Mandatory)][string]$PackageRoot)

$ErrorActionPreference = 'Stop'
$verifier = Join-Path $PSScriptRoot 'verify-package.ps1'
$source = (Resolve-Path -LiteralPath $PackageRoot).Path
$systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $systemTemp ('x64dbg-mcp-package-test-' + [guid]::NewGuid().ToString('N'))

function Assert-True([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw "package verifier contract failed: $Message" }
}

try {
    & $verifier -PackageRoot $source | Out-Null
    Copy-Item -LiteralPath $source -Destination $testRoot -Recurse

    $config = Join-Path $testRoot 'mcp\x96dbg-mcp-server.example.toml'
    [IO.File]::AppendAllText($config, "`nmax_inflight = 8")
    $nonMinimalFailed = $false
    try { & $verifier -PackageRoot $testRoot | Out-Null } catch {
        $nonMinimalFailed = $_.Exception.Message -match 'only bind, port, and bearer_token'
    }
    Assert-True $nonMinimalFailed 'a non-minimal config was accepted'

    Copy-Item -LiteralPath (Join-Path $source 'mcp\x96dbg-mcp-server.example.toml') -Destination $config -Force
    [IO.File]::WriteAllText((Join-Path $testRoot 'unlisted.txt'), 'unexpected')
    $unlistedFailed = $false
    try { & $verifier -PackageRoot $testRoot | Out-Null } catch {
        $unlistedFailed = $_.Exception.Message -match 'exactly'
    }
    Assert-True $unlistedFailed 'an unlisted file was accepted'

    [IO.File]::Delete((Join-Path $testRoot 'unlisted.txt'))
    [IO.File]::Delete((Join-Path $testRoot 'x32\x64dbg-mcp-backend.dp32'))
    $missingFailed = $false
    try { & $verifier -PackageRoot $testRoot | Out-Null } catch {
        $missingFailed = $_.Exception.Message -match 'exactly'
    }
    Assert-True $missingFailed 'a missing plugin was accepted'
    Write-Output 'package verifier contract tests passed'
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
        if (!$resolvedTestRoot.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to clean a test path outside the system temporary directory.'
        }
        [IO.Directory]::Delete($resolvedTestRoot, $true)
    }
}
