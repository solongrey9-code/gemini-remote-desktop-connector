$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$computer = Get-CimInstance Win32_ComputerSystem -Property Manufacturer, Model, TotalPhysicalMemory
$processors = @(Get-CimInstance Win32_Processor -Property Name, NumberOfCores, NumberOfLogicalProcessors)
$memory = Get-CimInstance Win32_PhysicalMemory -Property Capacity | Measure-Object -Property Capacity -Sum
$windows = Get-CimInstance Win32_OperatingSystem -Property Caption, BuildNumber
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
if (-not $env:ProgramFiles -and $programFiles) {
    $env:ProgramFiles = $programFiles
}
$nvidiaPaths = @(
    (Join-Path $env:SystemRoot 'System32\nvidia-smi.exe')
    if ($programFiles) { Join-Path $programFiles 'NVIDIA Corporation\NVSMI\nvidia-smi.exe' }
)
$nvidia = $nvidiaPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
$nvidiaGpus = @()
if ($nvidia) {
    $rows = & $nvidia '--query-gpu=name,memory.total,driver_version' '--format=csv,noheader,nounits'
    if ($LASTEXITCODE -eq 0) {
        $nvidiaGpus = @(
            foreach ($row in $rows) {
                $gpu = $row -split ',\s*', 3
                if ($gpu.Length -eq 3 -and $gpu[1] -match '^\d+$') {
                    [ordered]@{
                        name = $gpu[0].Trim()
                        vram_mib = [int]$gpu[1]
                        driver = $gpu[2].Trim()
                    }
                }
            }
        )
    }
}

[ordered]@{
    manufacturer = $computer.Manufacturer
    model = $computer.Model
    windows = $windows.Caption
    windows_build = $windows.BuildNumber
    installed_ram_gib = if ($memory.Count) { [math]::Round($memory.Sum / 1GB, 2) } else { $null }
    usable_ram_gib = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2)
    processors = @(
        foreach ($cpu in $processors) {
            [ordered]@{
                name = $cpu.Name
                cores = $cpu.NumberOfCores
                logical_processors = $cpu.NumberOfLogicalProcessors
            }
        }
    )
    nvidia_gpus = $nvidiaGpus
} | ConvertTo-Json -Depth 5 -Compress
