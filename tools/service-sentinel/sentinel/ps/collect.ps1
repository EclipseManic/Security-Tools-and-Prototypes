<#
.SYNOPSIS
    Data collector for ServiceSentinel Web.

.DESCRIPTION
    Emits JSON facts only. No scoring or interpretation happens here: the Python
    layer owns all analysis so the rules stay testable and in one place.

    Modes:
      services  Win32_Service facts
      evidence  existence, size, mtime, company, version per path
      inspect   Authenticode status, signer and SHA-256 per path
      events    Service Control Manager records with raw property values
      action    service management with real exit codes
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('services', 'evidence', 'inspect', 'events', 'action')]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$OutPath,

    [string]$ArgsFile
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$cfg = @{}
if ($ArgsFile -and (Test-Path -LiteralPath $ArgsFile)) {
    try {
        $raw = Get-Content -LiteralPath $ArgsFile -Raw
        if ($raw.Trim()) {
            $parsed = $raw | ConvertFrom-Json
            foreach ($property in $parsed.PSObject.Properties) { $cfg[$property.Name] = $property.Value }
        }
    } catch {
        $cfg = @{}
    }
}

function Get-Config {
    param([string]$Key, $Default = $null)
    if ($cfg.ContainsKey($Key) -and $null -ne $cfg[$Key]) { return $cfg[$Key] }
    return $Default
}

function Write-Json {
    param($Payload)
    $json = $Payload | ConvertTo-Json -Depth 6
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($OutPath, $json, $utf8)
}

function Write-Failure {
    param([string]$Message)
    Write-Json ([pscustomobject]@{ error = $Message })
    exit 1
}

try {
    switch ($Mode) {
        'services' {
            $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
            $startCache = @{}
            $items = New-Object System.Collections.ArrayList
            foreach ($service in $services) {
                $processId = 0
                if ($service.ProcessId) { $processId = [int]$service.ProcessId }
                $processStart = $null
                if ($processId -gt 0) {
                    if ($startCache.ContainsKey($processId)) {
                        $processStart = $startCache[$processId]
                    } else {
                        try {
                            $processStart = (Get-Process -Id $processId -ErrorAction Stop).StartTime.ToString('o')
                        } catch {
                            $processStart = $null
                        }
                        $startCache[$processId] = $processStart
                    }
                }
                [void]$items.Add([pscustomobject]@{
                    name         = $service.Name
                    display_name = $service.DisplayName
                    description  = $service.Description
                    state        = $service.State
                    start_mode   = $service.StartMode
                    start_name   = $service.StartName
                    service_type = $service.ServiceType
                    process_id   = $processId
                    command_line = $service.PathName
                    process_start = $processStart
                })
            }
            Write-Json ([pscustomobject]@{ items = @($items) })
        }

        'evidence' {
            $items = New-Object System.Collections.ArrayList
            foreach ($path in @(Get-Config 'paths' @())) {
                $entry = [pscustomobject]@{
                    path    = $path
                    exists  = $false
                    size    = 0
                    mtime   = $null
                    company = $null
                    version = $null
                }
                if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
                    try {
                        $item = Get-Item -LiteralPath $path -ErrorAction Stop
                        $entry.exists = $true
                        $entry.size = [long]$item.Length
                        $entry.mtime = $item.LastWriteTimeUtc.ToString('o')
                        $entry.company = $item.VersionInfo.CompanyName
                        $entry.version = $item.VersionInfo.FileVersion
                    } catch {
                        $entry.exists = $false
                    }
                }
                [void]$items.Add($entry)
            }
            Write-Json ([pscustomobject]@{ items = @($items) })
        }

        'inspect' {
            $hashFiles = [bool](Get-Config 'hash' $false)
            $items = New-Object System.Collections.ArrayList
            foreach ($path in @(Get-Config 'paths' @())) {
                $status = 'NotChecked'
                $signer = $null
                $sha256 = $null
                if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
                    try {
                        $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
                        $status = $signature.Status.ToString()
                        if ($signature.SignerCertificate) { $signer = $signature.SignerCertificate.Subject }
                    } catch {
                        $status = 'Error'
                    }
                    if ($hashFiles) {
                        try {
                            $sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
                        } catch {
                            $sha256 = $null
                        }
                    }
                } else {
                    $status = 'FileNotFound'
                }
                [void]$items.Add([pscustomobject]@{
                    path      = $path
                    signature = $status
                    signer    = $signer
                    sha256    = $sha256
                })
            }
            Write-Json ([pscustomobject]@{ items = @($items) })
        }

        'events' {
            $hours = [int](Get-Config 'hours' 168)
            $maxEvents = [int](Get-Config 'max_events' 8000)
            $start = (Get-Date).AddHours(-1 * $hours)
            $truncated = $false
            $items = New-Object System.Collections.ArrayList
            try {
                $events = @(Get-WinEvent -FilterHashtable @{
                    LogName      = 'System'
                    ProviderName = 'Service Control Manager'
                    StartTime    = $start
                } -ErrorAction Stop)
            } catch {
                Write-Json ([pscustomobject]@{
                    items        = @()
                    truncated    = $false
                    event_error  = $_.Exception.Message
                })
                exit 0
            }

            if ($events.Count -gt $maxEvents) {
                $truncated = $true
                $events = @($events | Select-Object -First $maxEvents)
            }

            foreach ($event in $events) {
                $values = New-Object System.Collections.ArrayList
                foreach ($property in $event.Properties) {
                    $value = $property.Value
                    if ($null -eq $value) {
                        [void]$values.Add($null)
                    } else {
                        [void]$values.Add([string]$value)
                    }
                }
                [void]$items.Add([pscustomobject]@{
                    id        = [int]$event.Id
                    time      = $event.TimeCreated.ToString('o')
                    record_id = $event.RecordId
                    values    = @($values)
                })
            }
            Write-Json ([pscustomobject]@{ items = @($items); truncated = $truncated })
        }

        'action' {
            $name = [string](Get-Config 'name' '')
            $action = [string](Get-Config 'action' '')
            $startup = [string](Get-Config 'startup' 'Manual')
            $force = [bool](Get-Config 'force' $false)
            $steps = New-Object System.Collections.ArrayList

            function Add-Step {
                param([string]$Step, [bool]$Ok, [string]$Message)
                [void]$steps.Add([pscustomobject]@{ step = $Step; ok = $Ok; message = $Message })
            }

            if (-not $name) { Write-Failure 'No service name supplied.' }

            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            if (-not $service) {
                Write-Json ([pscustomobject]@{ ok = $false; found = $false; steps = @(
                    [pscustomobject]@{ step = 'lookup'; ok = $false; message = "Service '$name' was not found." }
                ) })
                exit 0
            }

            $dependents = @()
            try { $dependents = @($service.DependentServices | Select-Object -ExpandProperty Name) } catch { }

            if ($action -eq 'preflight') {
                Write-Json ([pscustomobject]@{
                    ok         = $true
                    found      = $true
                    name       = $service.Name
                    display    = $service.DisplayName
                    status     = $service.Status.ToString()
                    start_type = $service.StartType.ToString()
                    dependents = $dependents
                })
                exit 0
            }

            switch ($action) {
                'start' {
                    try {
                        Start-Service -Name $name -ErrorAction Stop
                        Add-Step 'start' $true 'Service start requested.'
                    } catch {
                        Add-Step 'start' $false $_.Exception.Message
                    }
                }
                'stop' {
                    try {
                        if ($force) { Stop-Service -Name $name -Force -ErrorAction Stop }
                        else { Stop-Service -Name $name -ErrorAction Stop }
                        Add-Step 'stop' $true 'Service stopped.'
                    } catch {
                        Add-Step 'stop' $false $_.Exception.Message
                    }
                }
                'restart' {
                    try {
                        if ($force) { Restart-Service -Name $name -Force -ErrorAction Stop }
                        else { Restart-Service -Name $name -ErrorAction Stop }
                        Add-Step 'restart' $true 'Service restarted.'
                    } catch {
                        Add-Step 'restart' $false $_.Exception.Message
                    }
                }
                'setstartup' {
                    try {
                        Set-Service -Name $name -StartupType $startup -ErrorAction Stop
                        Add-Step 'startup' $true "Startup type set to $startup."
                    } catch {
                        Add-Step 'startup' $false $_.Exception.Message
                    }
                }
                'contain' {
                    if ($service.Status -ne 'Stopped') {
                        try {
                            Stop-Service -Name $name -ErrorAction Stop
                            Add-Step 'stop' $true 'Service stopped.'
                        } catch {
                            Add-Step 'stop' $false $_.Exception.Message
                        }
                    } else {
                        Add-Step 'stop' $true 'Service was already stopped.'
                    }
                    try {
                        Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
                        Add-Step 'disable' $true 'Startup type set to Disabled.'
                    } catch {
                        Add-Step 'disable' $false $_.Exception.Message
                    }
                }
                'delete' {
                    if ($service.Status -ne 'Stopped') {
                        try {
                            Stop-Service -Name $name -ErrorAction Stop
                            Add-Step 'stop' $true 'Service stopped before deletion.'
                        } catch {
                            Add-Step 'stop' $false ("Could not stop before deletion: " + $_.Exception.Message)
                        }
                    }
                    $output = (& sc.exe delete $name 2>&1 | Out-String).Trim()
                    $code = $LASTEXITCODE
                    Add-Step 'delete' ($code -eq 0) ("sc.exe exit $code" + $(if ($output) { ": $output" } else { '.' }))
                }
                'restore' {
                    try {
                        Set-Service -Name $name -StartupType $startup -ErrorAction Stop
                        Add-Step 'startup' $true "Startup type restored to $startup."
                    } catch {
                        Add-Step 'startup' $false $_.Exception.Message
                    }
                    if ([bool](Get-Config 'start_service' $false)) {
                        try {
                            Start-Service -Name $name -ErrorAction Stop
                            Add-Step 'start' $true 'Service started.'
                        } catch {
                            Add-Step 'start' $false $_.Exception.Message
                        }
                    }
                }
                default {
                    Write-Failure "Unsupported action '$action'."
                }
            }

            $ok = -not ($steps | Where-Object { -not $_.ok })
            Write-Json ([pscustomobject]@{
                ok         = $ok
                found      = $true
                name       = $service.Name
                display    = $service.DisplayName
                dependents = $dependents
                steps      = @($steps)
            })
        }
    }
} catch {
    Write-Failure $_.Exception.Message
}
