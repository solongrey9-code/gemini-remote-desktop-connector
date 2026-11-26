[CmdletBinding(DefaultParameterSetName = 'Open')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Open')]
    [switch]$Open,

    [Parameter(Mandatory, ParameterSetName = 'Approve')]
    [ValidatePattern('^[A-Za-z0-9_-]{32}$')]
    [string]$Approve,

    [Parameter(Mandatory, ParameterSetName = 'Close')]
    [switch]$Close
)

$ErrorActionPreference = 'Stop'
$runtime = Join-Path $PSScriptRoot '.bridge'
$enrollment = Join-Path $runtime 'enrollment'
$approvals = Join-Path $runtime 'approvals'
switch ($PSCmdlet.ParameterSetName) {
    'Open' {
        New-Item -ItemType Directory -Path $approvals -Force | Out-Null
        [IO.File]::WriteAllText($enrollment, [string][DateTimeOffset]::UtcNow.AddMinutes(15).ToUnixTimeSeconds())
        'Pairing is open for 15 minutes.'
    }
    'Approve' {
        $deadline = if (Test-Path -LiteralPath $enrollment -PathType Leaf) { Get-Content -LiteralPath $enrollment -Raw }
        if ($deadline -notmatch '^\d{10}$' -or [long]$deadline -le [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) {
            throw 'Open a pairing window first.'
        }
        New-Item -ItemType File -Path (Join-Path $approvals $Approve) | Out-Null
        'Pairing approved. Return to the browser and select Finish linking.'
    }
    'Close' {
        if (Test-Path -LiteralPath $enrollment -PathType Leaf) {
            Remove-Item -LiteralPath $enrollment
        }
        'Pairing is closed.'
    }
}
