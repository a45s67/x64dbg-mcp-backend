[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackageRoot
)

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

    $readme = Join-Path $testRoot 'README.md'
    [IO.File]::AppendAllText($readme, "`ntampered")
    $tamperFailed = $false
    try { & $verifier -PackageRoot $testRoot | Out-Null } catch {
        $tamperFailed = $_.Exception.Message -match 'Checksum mismatch'
    }
    Assert-True $tamperFailed 'content tampering was not rejected'

    Copy-Item -LiteralPath (Join-Path $source 'README.md') -Destination $readme -Force
    [IO.File]::WriteAllText((Join-Path $testRoot 'unlisted.txt'), 'unexpected')
    $unlistedFailed = $false
    try { & $verifier -PackageRoot $testRoot | Out-Null } catch {
        $unlistedFailed = $_.Exception.Message -match 'file count|Unlisted'
    }
    Assert-True $unlistedFailed 'an unlisted file was not rejected'
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
