[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$skillRoot = Join-Path $PSScriptRoot '..\skills\x64dbg-debugging'
$skillPath = Join-Path $skillRoot 'SKILL.md'
$markerPath = Join-Path $skillRoot '.managed-by-x64dbg-mcp-backend'

function Assert-Skill([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw "x64dbg skill contract failed: $Message" }
}

$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$skill = $strictUtf8.GetString([IO.File]::ReadAllBytes($skillPath))
Assert-Skill $skill.StartsWith("---`n") 'SKILL.md has no YAML frontmatter'
$frontmatter = [regex]::Match($skill, '(?s)^---\n(.*?)\n---\n')
Assert-Skill $frontmatter.Success 'SKILL.md frontmatter is malformed'
Assert-Skill ($frontmatter.Groups[1].Value -match '(?m)^name: x64dbg-debugging$') 'skill name is missing or invalid'
Assert-Skill ($frontmatter.Groups[1].Value -match '(?m)^description: .{20,1024}$') 'skill description is missing or unbounded'
Assert-Skill ($frontmatter.Groups[1].Value -match '(?m)^  version: "0\.4\.0"$') 'independent skill version is missing'
Assert-Skill ($frontmatter.Groups[1].Value -match '(?m)^  minimum-backend-version: "0\.4\.0"$') 'minimum backend version is missing'
Assert-Skill (Test-Path -LiteralPath $markerPath -PathType Leaf) 'managed ownership marker is missing'

$allText = Get-ChildItem -LiteralPath $skillRoot -Recurse -File | ForEach-Object {
    $strictUtf8.GetString([IO.File]::ReadAllBytes($_.FullName))
}
$combined = $allText -join "`n"
Assert-Skill ($combined -notmatch '(?i)bearer[_ -]?token\s*[=:]\s*["''][^"'']+') 'skill contains a bearer token value'
Assert-Skill ($combined -notmatch '(?m)^\s*\[TODO:') 'skill contains an unfinished scaffold TODO'

foreach ($reference in @('references\recipes.md', 'references\troubleshooting.md')) {
    Assert-Skill (Test-Path -LiteralPath (Join-Path $skillRoot $reference) -PathType Leaf) "missing referenced file $reference"
}

$published = @(
    'debugger.state', 'debugger.snapshot', 'debugger.wait_for_pause', 'debugger.pause', 'debugger.resume',
    'debugger.step_into', 'debugger.step_over', 'debugger.stop', 'debuggee.launch',
    'debuggee.attach', 'debuggee.detach',
    'registers.read', 'address.resolve', 'memory.read', 'memory.write', 'memory.map',
    'modules.list', 'threads.list', 'breakpoints.list', 'breakpoints.set',
    'breakpoints.remove', 'disassembly.read', 'expression.evaluate', 'symbols.search',
    'functions.list', 'strings.search', 'references.to'
)
$mentioned = [regex]::Matches(
    $combined,
    '(?<![a-z_])(?:debugger|debuggee|registers|address|memory|modules|threads|breakpoints|disassembly|expression|symbols|functions|strings|references)\.[a-z_]+'
) | ForEach-Object Value | Sort-Object -Unique
foreach ($tool in $mentioned) {
    Assert-Skill ($tool -in $published) "skill references unpublished tool $tool"
}

Write-Output 'x64dbg workflow skill contract tests passed'
