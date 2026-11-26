[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Origin,

    [ValidateRange(1024, 65535)]
    [int]$Port = 18772,

    [ValidateRange(1024, 65535)]
    [int]$ReviewPort = 18773,

    [string]$Workspace = (Join-Path $PSScriptRoot 'workspace')
)

$ErrorActionPreference = 'Stop'
$httpsOrigin = $null
if (-not [Uri]::TryCreate($Origin, [UriKind]::Absolute, [ref]$httpsOrigin) -or
    $httpsOrigin.Scheme -ne 'https' -or $httpsOrigin.UserInfo -or
    $httpsOrigin.AbsolutePath -ne '/' -or $httpsOrigin.Query -or $httpsOrigin.Fragment) {
    throw 'Supply a bare HTTPS origin without a path, query, fragment or credentials.'
}

$python = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Create .venv and install requirements.txt first.'
}
if (-not (Test-Path -LiteralPath $Workspace -PathType Container)) {
    if ($PSBoundParameters.ContainsKey('Workspace')) {
        throw 'The workspace supplied via -Workspace must be an existing directory.'
    }
    New-Item -ItemType Directory -Path $Workspace | Out-Null
}
$workspacePath = (Get-Item -LiteralPath $Workspace).FullName
$server = Join-Path $PSScriptRoot 'connected.py'
$events = Join-Path $PSScriptRoot '.bridge/events.jsonl'

$originUrl = $httpsOrigin.GetLeftPart([UriPartial]::Authority)
& $python $server --origin $originUrl --port $Port --review-port $ReviewPort --workspace $workspacePath --trace-file $events
exit $LASTEXITCODE
