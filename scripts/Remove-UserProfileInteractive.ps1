<#
.Title
    Remove-UserProfileInteractive.ps1

.SYNOPSIS
    Interactively delete local user profiles (folder + registry), with logging.

.DESCRIPTION
    Enumerates non-system, non-special profiles (including LOADED ones so you can see them).
    Displays a numbered list with username, last use time, and size.
    Blocks deletion if the selected profile is currently LOADED (in use).
    Logs all significant actions and outcomes to CSV.

.NOTES
    Author: Ahmed (Abassam08)
    Version: 1.1.0
    Requires: PowerShell 5.1+, Windows 10/11 or Server 2016+
    Run as: Administrator
    License: MIT
#>

param(
    [string]$LogRoot = "C:\ProgramData\WindowsMgmtScripts\Logs"
)

# v1.2.0 — Event Log integration ---------------------------------------------

# Ensure you add this to your param() in each script:
# [switch]$WriteEventLog

# Constants for Application Event Log
$Global:AppEventLogName  = 'Application'
$Global:AppEventSource   = 'WindowsMgmtScripts'

function Ensure-AppEventSource {
    [CmdletBinding()]
    param()
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Global:AppEventSource)) {
            # Creating an event source requires admin. If the script isn't running elevated,
            # catch and continue (CSV logging remains unaffected).
            New-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -ErrorAction Stop
            # Optional: Write an initial informational record to confirm creation
            Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId 1000 -EntryType Information -Message 'Event source initialized.'
        }
    } catch {
        # Non-fatal: fall back to CSV-only if this fails (e.g., not admin)
        Write-Verbose "Ensure-AppEventSource: $_"
    }
}

function Write-AppEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Information','Warning','Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [int]$EventId = 1001
    )

# v1.2.0 — Event Log integration ---------------------------------------------

# Ensure you add this to your param() in each script:
# [switch]$WriteEventLog

# Constants for Application Event Log
$Global:AppEventLogName  = 'Application'
$Global:AppEventSource   = 'WindowsMgmtScripts'

function Ensure-AppEventSource {
    [CmdletBinding()]
    param()
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Global:AppEventSource)) {
            # Creating an event source requires admin. If the script isn't running elevated,
            # catch and continue (CSV logging remains unaffected).
            New-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -ErrorAction Stop
            # Optional: Write an initial informational record to confirm creation
            Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId 1000 -EntryType Information -Message 'Event source initialized.'
        }
    } catch {
        # Non-fatal: fall back to CSV-only if this fails (e.g., not admin)
        Write-Verbose "Ensure-AppEventSource: $_"
    }
}

function Write-AppEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Information','Warning','Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [int]$EventId = 1001
    )
    if (-not $WriteEventLog) { return }

    # Ensure source exists (no-op after first success)
    Ensure-AppEventSource

    try {
        $entryType = switch ($Level) {
            'Information' { 'Information' }
            'Warning'     { 'Warning' }
            'Error'       { 'Error' }
        }
        Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId $EventId -EntryType $entryType -Message $Message
    } catch {
        # Never break main flow due to eventing
        Write-Verbose "Write-AppEvent failed: $_"
    }
}
# ---------------------------------------------------------------------------
    
    if (-not $WriteEventLog) { return }

    # Ensure source exists (no-op after first success)
    Ensure-AppEventSource

    try {
        $entryType = switch ($Level) {
            'Information' { 'Information' }
            'Warning'     { 'Warning' }
            'Error'       { 'Error' }
        }
        Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId $EventId -EntryType $entryType -Message $Message
    } catch {
        # Never break main flow due to eventing
        Write-Verbose "Write-AppEvent failed: $_"
    }
}
# ---------------------------------------------------------------------------

# --- Logging helpers ---
function Initialize-Log {
    param([Parameter(Mandatory)][string]$LogFile)
    if (-not (Test-IsAdmin)) { return }
    if (-not (Test-Path -LiteralPath $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null }
    if (Test-Path -LiteralPath $LogFile) {
        $max = 5MB
        $len = (Get-Item -LiteralPath $LogFile).Length
        if ($len -gt $max) {
            $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
            Rename-Item -LiteralPath $LogFile -NewName ("{0}.{1}.bak" -f (Split-Path $LogFile -Leaf), $stamp) -Force
        }
    }
    if (-not (Test-Path -LiteralPath $LogFile)) {
        "Timestamp,Computer,RunAs,Script,Action,TargetUser,TargetSID,ProfilePath,SizeMB,Loaded,Result,Message" |
            Out-File -FilePath $LogFile -Encoding utf8
    }
}


# v1.2.0 — Event Log integration ---------------------------------------------

# Ensure you add this to your param() in each script:
# [switch]$WriteEventLog

# Constants for Application Event Log
$Global:AppEventLogName  = 'Application'
$Global:AppEventSource   = 'WindowsMgmtScripts'

function Ensure-AppEventSource {
    [CmdletBinding()]
    param()
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Global:AppEventSource)) {
            # Creating an event source requires admin. If the script isn't running elevated,
            # catch and continue (CSV logging remains unaffected).
            New-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -ErrorAction Stop
            # Optional: Write an initial informational record to confirm creation
            Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId 1000 -EntryType Information -Message 'Event source initialized.'
        }
    } catch {
        # Non-fatal: fall back to CSV-only if this fails (e.g., not admin)
        Write-Verbose "Ensure-AppEventSource: $_"
    }
}

function Write-AppEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Information','Warning','Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [int]$EventId = 1001
    )
    if (-not $WriteEventLog) { return }

    # Ensure source exists (no-op after first success)
    Ensure-AppEventSource

    try {
        $entryType = switch ($Level) {
            'Information' { 'Information' }
            'Warning'     { 'Warning' }
            'Error'       { 'Error' }
        }
        Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId $EventId -EntryType $entryType -Message $Message
    } catch {
        # Never break main flow due to eventing
        Write-Verbose "Write-AppEvent failed: $_"
    }
}
# ---------------------------------------------------------------------------

function Write-Log {
    param(
        [string]$Action,
        [string]$TargetUser,
        [string]$TargetSID,
        [string]$ProfilePath,
        [double]$SizeMB,
        [bool]$Loaded,
        [string]$Result,
        [string]$Message
    )

# v1.2.0 — Event Log integration ---------------------------------------------

# Ensure you add this to your param() in each script:
# [switch]$WriteEventLog

# Constants for Application Event Log
$Global:AppEventLogName  = 'Application'
$Global:AppEventSource   = 'WindowsMgmtScripts'

function Ensure-AppEventSource {
    [CmdletBinding()]
    param()
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Global:AppEventSource)) {
            # Creating an event source requires admin. If the script isn't running elevated,
            # catch and continue (CSV logging remains unaffected).
            New-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -ErrorAction Stop
            # Optional: Write an initial informational record to confirm creation
            Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId 1000 -EntryType Information -Message 'Event source initialized.'
        }
    } catch {
        # Non-fatal: fall back to CSV-only if this fails (e.g., not admin)
        Write-Verbose "Ensure-AppEventSource: $_"
    }
}

function Write-AppEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Information','Warning','Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [int]$EventId = 1001
    )
    if (-not $WriteEventLog) { return }

    # Ensure source exists (no-op after first success)
    Ensure-AppEventSource

    try {
        $entryType = switch ($Level) {
            'Information' { 'Information' }
            'Warning'     { 'Warning' }
            'Error'       { 'Error' }
        }
        Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId $EventId -EntryType $entryType -Message $Message
    } catch {
        # Never break main flow due to eventing
        Write-Verbose "Write-AppEvent failed: $_"
    }
}
# ---------------------------------------------------------------------------
    
    try {
        $row = [PSCustomObject]@{
            Timestamp   = (Get-Date).ToString("s")
            Computer    = $env:COMPUTERNAME
            RunAs       = (whoami)
            Script      = $MyInvocation.MyCommand.Name
            Action      = $Action
            TargetUser  = $TargetUser
            TargetSID   = $TargetSID
            ProfilePath = $ProfilePath
            SizeMB      = $SizeMB
            Loaded      = $Loaded
            Result      = $Result
            Message     = $Message
        }
        $row | Export-Csv -Path $script:LogFile -NoTypeInformation -Append -Encoding UTF8
    } catch { Write-Verbose "Write-Log failed: $($_.Exception.Message)" }
}

# --- Helper: admin check ---
function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Init log file path ---
$script:LogFile = Join-Path $LogRoot 'Remove-UserProfileInteractive.log.csv'
Initialize-Log -LogFile $script:LogFile

# --- Require elevation ---
if (-not (Test-IsAdmin)) {
    Write-Warning "Please run this script in an elevated PowerShell session (Run as Administrator)."
    Write-Log -Action 'ElevationCheck' -Result 'Blocked' -Message 'Script not elevated'
    return
}

# --- Enumerate profiles ---
try {
    $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
        Where-Object {
            $_.LocalPath -and
            $_.LocalPath -notlike '*systemprofile*' -and
            $_.LocalPath -notlike '*LocalService*'  -and
            $_.LocalPath -notlike '*NetworkService*' -and
            $_.Special -eq $false
        }
    Write-Log -Action 'EnumerateProfiles' -Result 'Success' -Message ("Count={0}" -f ($profiles | Measure-Object).Count)
}
catch {
    Write-Error "Failed to enumerate profiles: $($_.Exception.Message)"
    Write-Log -Action 'EnumerateProfiles' -Result 'Error' -Message $_.Exception.Message
    return
}

if (-not $profiles -or $profiles.Count -eq 0) {
    Write-Host "No eligible user profiles found."
    Write-Log -Action 'EnumerateProfiles' -Result 'Empty' -Message 'No profiles matched filters'
    return
}

$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function Get-FolderSizeMB {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return 0 }
        $bytes = (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
                  Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        if (-not $bytes) { $bytes = 0 }
        return [math]::Round($bytes / 1MB, 1)
    } catch { return 0 }
}

# v1.2.0 — Event Log integration ---------------------------------------------

# Ensure you add this to your param() in each script:
# [switch]$WriteEventLog

# Constants for Application Event Log
$Global:AppEventLogName  = 'Application'
$Global:AppEventSource   = 'WindowsMgmtScripts'

function Ensure-AppEventSource {
    [CmdletBinding()]
    param()
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Global:AppEventSource)) {
            # Creating an event source requires admin. If the script isn't running elevated,
            # catch and continue (CSV logging remains unaffected).
            New-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -ErrorAction Stop
            # Optional: Write an initial informational record to confirm creation
            Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId 1000 -EntryType Information -Message 'Event source initialized.'
        }
    } catch {
        # Non-fatal: fall back to CSV-only if this fails (e.g., not admin)
        Write-Verbose "Ensure-AppEventSource: $_"
    }
}

function Write-AppEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Information','Warning','Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [int]$EventId = 1001
    )
    if (-not $WriteEventLog) { return }

    # Ensure source exists (no-op after first success)
    Ensure-AppEventSource

    try {
        $entryType = switch ($Level) {
            'Information' { 'Information' }
            'Warning'     { 'Warning' }
            'Error'       { 'Error' }
        }
        Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId $EventId -EntryType $entryType -Message $Message
    } catch {
        # Never break main flow due to eventing
        Write-Verbose "Write-AppEvent failed: $_"
    }
}
# ---------------------------------------------------------------------------


$display = @()
foreach ($p in $profiles) {
    $username = Split-Path $p.LocalPath -Leaf
    $lastUse  = $p.LastUseTime
    $sizeMB   = Get-FolderSizeMB -Path $p.LocalPath
    $display += [PSCustomObject]@{
        Username   = $username
        SID        = $p.SID
        Path       = $p.LocalPath
        LastUse    = if ($lastUse) { (Get-Date $lastUse) } else { $null }
        SizeMB     = $sizeMB
        Loaded     = [bool]$p.Loaded
        IsCurrent  = ($p.SID -eq $currentSid)
        CimObject  = $p
    }
}

if ($display.Count -eq 0) {
    Write-Host "No eligible user profiles found."
    Write-Log -Action 'PrepareDisplay' -Result 'Empty' -Message 'No display rows created'
    return
}

$display = $display | Sort-Object LastUse

Write-Host "Select a profile to delete:`n" -ForegroundColor Cyan
for ($i = 0; $i -lt $display.Count; $i++) {
    $row = $display[$i]
    $last = if ($row.LastUse) { $row.LastUse.ToString("yyyy-MM-dd HH:mm") } else { "N/A" }
    $loadedTag = if ($row.Loaded) { " [LOADED]" } else { "" }
    $currentTag = if ($row.IsCurrent) { " [CURRENT USER]" } else { "" }
    Write-Host ("{0,2}) {1}{2}{3}  | Last Use: {4} | Size: {5} MB" -f ($i+1), $row.Username, $loadedTag, $currentTag, $last, $row.SizeMB)
}

Write-Host
$choice = Read-Host "Enter the number of the profile to delete (or press Enter to cancel)"
if ([string]::IsNullOrWhiteSpace($choice)) {
    Write-Host "Operation cancelled."
    Write-Log -Action 'SelectProfile' -Result 'Cancelled' -Message 'User pressed Enter'
    return
}
if (-not ($choice -as [int])) {
    Write-Host "Invalid selection (not a number)."
    Write-Log -Action 'SelectProfile' -Result 'Invalid' -Message "Input=$choice"
    return
}
$choice = [int]$choice
if ($choice -lt 1 -or $choice -gt $display.Count) {
    Write-Host "Invalid selection (out of range)."
    Write-Log -Action 'SelectProfile' -Result 'Invalid' -Message "OutOfRange=$choice"
    return
}

$selected = $display[$choice - 1]

Write-Host "`nYou selected: $($selected.Username)"
Write-Host "SID:   $($selected.SID)"
Write-Host "Path:  $($selected.Path)"
Write-Host "Last:  $($selected.LastUse)"
Write-Host "Size:  $($selected.SizeMB) MB"
if ($selected.Loaded) { Write-Warning "This profile is currently LOADED (in use)." }
if ($selected.IsCurrent) { Write-Warning "This is the CURRENTLY LOGGED-ON user." }

Write-Log -Action 'SelectProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $selected.Loaded -Result 'Selected' -Message 'User chose a profile'

if ($selected.Loaded) {
    $msg = "Deletion blocked: profile is LOADED"
    Write-Warning $msg
    Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $selected.Loaded -Result 'Blocked' -Message $msg
    return
}

$confirm = Read-Host "`nAre you sure you want to delete this profile (folder + registry)? (Y/N)"
if ($confirm -notmatch '^(Y|y)$') {
    Write-Host "Operation cancelled."
    Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $selected.Loaded -Result 'Cancelled' -Message 'User declined'
    return
}

try {
    Remove-CimInstance -InputObject $selected.CimObject -ErrorAction Stop
    Write-Host "`nProfile for '$($selected.Username)' deleted successfully." -ForegroundColor Green
    Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $selected.Loaded -Result 'Success' -Message 'CIM delete ok'
}
catch {
    $err = "Failed to delete profile: $($_.Exception.Message)"
    Write-Error $err
    Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $selected.Loaded -Result 'Error' -Message $err
}
