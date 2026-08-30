[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$skillRoot = Join-Path $PSScriptRoot '..\skills\x64dbg-debugging'
$skillPath = Join-Path $skillRoot 'SKILL.md'
$markerPath = Join-Path $skillRoot '.managed-by-x64dbg-mcp-backend'
$workspaceManifest = Join-Path $PSScriptRoot '..\Cargo.toml'

function Assert-Skill([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw "x64dbg skill contract failed: $Message" }
}

$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$skill = $strictUtf8.GetString([IO.File]::ReadAllBytes($skillPath))
Assert-Skill $skill.StartsWith("---`n") 'SKILL.md has no YAML frontmatter'
$frontmatter = [regex]::Match($skill, '(?s)^---\n(.*?)\n---\n')
Assert-Skill $frontmatter.Success 'SKILL.md frontmatter is malformed'
$manifest = $strictUtf8.GetString([IO.File]::ReadAllBytes($workspaceManifest))
$versionMatch = [regex]::Match($manifest, '(?m)^version = "([0-9]+\.[0-9]+\.[0-9]+)"$')
Assert-Skill $versionMatch.Success 'workspace version is missing or invalid'
$backendVersion = [regex]::Escape($versionMatch.Groups[1].Value)
Assert-Skill ($frontmatter.Groups[1].Value -match '(?m)^name: x64dbg-debugging$') 'skill name is missing or invalid'
Assert-Skill ($frontmatter.Groups[1].Value -match '(?m)^description: .{20,1024}$') 'skill description is missing or unbounded'
Assert-Skill ($frontmatter.Groups[1].Value -match "(?m)^  version: `"$backendVersion`"$") 'independent skill version is missing'
Assert-Skill ($frontmatter.Groups[1].Value -match "(?m)^  minimum-backend-version: `"$backendVersion`"$") 'minimum backend version is missing'
Assert-Skill (Test-Path -LiteralPath $markerPath -PathType Leaf) 'managed ownership marker is missing'

$allText = Get-ChildItem -LiteralPath $skillRoot -Recurse -File | ForEach-Object {
    $strictUtf8.GetString([IO.File]::ReadAllBytes($_.FullName))
}
$combined = $allText -join "`n"
Assert-Skill ($combined -notmatch '(?i)bearer[_ -]?token\s*[=:]\s*["''][^"'']+') 'skill contains a bearer token value'
Assert-Skill ($combined -notmatch '(?m)^\s*\[TODO:') 'skill contains an unfinished scaffold TODO'
Assert-Skill ($combined -match 'instance_id') 'backend instance precondition is missing'
Assert-Skill ($combined -match 'BACKEND_RESTARTED') 'restart diagnostic is missing'

foreach ($reference in @('references\recipes.md', 'references\troubleshooting.md')) {
    Assert-Skill (Test-Path -LiteralPath (Join-Path $skillRoot $reference) -PathType Leaf) "missing referenced file $reference"
}

$published = @(
    'debugger.state', 'debugger.snapshot', 'debugger.wait_for_pause', 'debugger.pause', 'debugger.resume',
    'debugger.step_into', 'debugger.step_over', 'debugger.step_out', 'debugger.run_to_address',
    'debugger.stop', 'trace.start', 'trace.status', 'trace.cancel', 'trace.results',
    'debuggee.launch', 'debuggee.launch_dll',
    'debuggee.attach', 'debuggee.detach',
    'registers.read', 'registers.write', 'address.resolve', 'analysis.function',
    'memory.read', 'memory.write', 'memory.map', 'memory.search',
    'modules.list', 'threads.list', 'breakpoints.list', 'breakpoints.set',
    'breakpoints.remove', 'breakpoints.hardware.set', 'breakpoints.hardware.remove',
    'breakpoints.memory.set', 'breakpoints.memory.remove',
    'breakpoints.conditional.set', 'breakpoints.conditional.remove',
    'breakpoints.exception.set', 'breakpoints.exception.remove',
    'assembly.preview', 'assembly.patch', 'patches.restore', 'patches.list',
    'disassembly.read', 'expression.evaluate', 'symbols.search',
    'functions.list', 'functions.at', 'callstack.read', 'symbols.resolve', 'imports.list', 'exports.list',
    'sections.list', 'events.list', 'strings.search', 'references.to'
)
$mentioned = [regex]::Matches(
    $combined,
    '(?<![a-z_])(?:debugger|debuggee|trace|registers|address|memory|modules|sections|threads|callstack|breakpoints|assembly|patches|disassembly|expression|symbols|functions|imports|exports|events|strings|references|analysis)(?:\.[a-z_]+)+'
) | ForEach-Object Value | Sort-Object -Unique
foreach ($tool in $mentioned) {
    Assert-Skill ($tool -in $published) "skill references unpublished tool $tool"
}

Write-Output 'x64dbg workflow skill contract tests passed'
