[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'package.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Package script has parse errors.' }

# Load the production selector without executing builds, packaging, or installation.
$selector = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Get-ServerExecutable'
}, $true)
if ($null -eq $selector) { throw 'Missing production artifact selector.' }
. ([scriptblock]::Create($selector.Extent.Text))
$selection = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -eq '$serverSource'
}, $true)
if ($null -eq $selection) { throw 'Missing production server source assignment.' }
$copy = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq 'Copy-Item' -and
    $node.CommandElements[2].Extent.Text -eq '$serverSource'
}, $true)
if ($null -eq $copy) { throw 'Packaging must copy the selected server executable.' }

$manifest = Join-Path $workspace 'crates\server\Cargo.toml'
function New-Artifact([string]$Executable, [string]$Name = 'x64dbg-mcp-server',
        [string]$Kind = 'bin', [string]$ManifestPath = $manifest, [bool]$Test = $false,
        [bool]$Fresh = $false) {
    @{
        reason = 'compiler-artifact'
        manifest_path = $ManifestPath.Replace('\', '/')
        target = @{ name = $Name; kind = @($Kind) }
        profile = @{ test = $Test }
        executable = $Executable
        fresh = $Fresh
    } | ConvertTo-Json -Depth 4 -Compress
}

$noise = @(
    (New-Artifact -Executable '' -Kind 'lib'),
    (New-Artifact -Executable 'C:\other.exe' -Name 'other-bin'),
    (New-Artifact -Executable 'C:\dependency.exe' -ManifestPath (Join-Path $workspace 'other\Cargo.toml')),
    (New-Artifact -Executable 'C:\test.exe' -Test $true),
    '{"reason":"compiler-message","message":{"rendered":"warning: example"}}',
    '{"reason":"build-finished","success":true}'
)
$cases = @(
    @{ Name = 'host output'; Path = 'C:\repo\target\release\x64dbg-mcp-server.exe' },
    @{ Name = 'external target directory with spaces'; Path = 'Z:\build cache\release\x64dbg-mcp-server.exe' },
    @{ Name = 'configured target triple'; Path = 'Z:\build-cache\x86_64-pc-windows-msvc\release\x64dbg-mcp-server.exe' }
)
foreach ($case in $cases) {
    foreach ($fresh in @($false, $true)) {
        $cargoMessages = $noise + @(New-Artifact -Executable $case.Path -Fresh $fresh)
        . ([scriptblock]::Create($selection.Extent.Text))
        if ($serverSource -cne $case.Path) { throw "Wrong executable for $($case.Name), fresh=$fresh" }
    }
}

$server = New-Artifact -Executable $cases[0].Path
$failures = @(
    @{ Name = 'empty build output'; Messages = @() },
    @{ Name = 'missing server'; Messages = $noise },
    @{ Name = 'missing executable'; Messages = $noise + @(New-Artifact -Executable '') },
    @{ Name = 'duplicate server'; Messages = @($server, $server) },
    @{ Name = 'host and configured target ambiguity'; Messages = @($server, (New-Artifact -Executable $cases[2].Path)) }
)
foreach ($case in $failures) {
    $cargoMessages = $case.Messages
    $failed = $false
    try {
        . ([scriptblock]::Create($selection.Extent.Text))
    } catch {
        if ($_.Exception.Message -notlike 'Expected exactly one server binary artifact*') { throw }
        $failed = $true
    }
    if (!$failed) { throw "Expected selection failure: $($case.Name)" }
}
Write-Output 'package artifact contract tests passed (6 successful selections, 5 fail-closed cases)'
