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
    Optionally also writes to Windows Event Log (Application, Source=WindowsMgmtScripts).

.NOTES
    Author: Ahmed (Abassam08)
    Version: 1.2.0
    Requires: PowerShell 5.1+, Windows 10/11 or Server 2016+
    Run as: Administrator
    License: MIT
#>

param(
    [string]$LogRoot = "C:\ProgramData\WindowsMgmtScripts\Logs",
    [bool]  $EnableEventLog = $true   # Default ON; set -EnableEventLog:$false to disable
)

# ================================
# Windows Event Log (Application)
# ================================
$Global:AppEventLogName = 'Application'
$Global:AppEventSource  = 'WindowsMgmtScripts'

function Ensure-AppEventSource {
    [CmdletBinding()]
    param()
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Global:AppEventSource)) {
            # Requires admin to create. If not elevated, this throws; we catch and continue.
            New-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -ErrorAction Stop
            Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId 1000 -EntryType Information -Message 'Event source initialized.'
        }
    } catch {
        Write-Verbose "Ensure-AppEventSource: $($_.Exception.Message)"
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
    if (-not $EnableEventLog) { return }

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
        Write-Verbose "Write-AppEvent failed: $($_.Exception.Message)"
    }
}

# ================================
# CSV Logging
# ================================
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

# ================================
# Utility helpers
# ================================
function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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

# (Optional hardening) Safe DMTF -> DateTime conversion for Win32_UserProfile.LastUseTime
function Convert-DmtfToDateTimeSafe {
    param([string]$Dmtf)
    try {
        if ([string]::IsNullOrWhiteSpace($Dmtf)) { return $null }
        if ($Dmtf -notmatch '^\d{14}\.\d{6}(\+|\-)\d{3}$') { return $null }
        return [Management.ManagementDateTimeConverter]::ToDateTime($Dmtf)
    } catch { return $null }
}

# ================================
# Init & prechecks
# ================================
$script:LogFile = Join-Path $LogRoot 'Remove-UserProfileInteractive.log.csv'
Initialize-Log -LogFile $script:LogFile

Write-Host ("[INFO] Logging to: {0}" -f $script:LogFile) -ForegroundColor Cyan
Write-AppEvent -Level Information -EventId 2104 -Message "WindowsMgmtScripts: DeleteProfile: Start | LogFile=$script:LogFile"

if (-not (Test-IsAdmin)) {
    Write-Warning "Please run this script in an elevated PowerShell session (Run as Administrator)."
    Write-Log -Action 'ElevationCheck' -Result 'Blocked' -Message 'Script not elevated'
    Write-AppEvent -Level Warning -EventId 2101 -Message "WindowsMgmtScripts: DeleteProfile: Blocked | Reason=Not elevated"
    Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
    return
}

# ================================
# Enumerate profiles
# ================================
try {
    $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
        Where-Object {
            $_.LocalPath -and
            $_.LocalPath -notlike '*systemprofile*'   -and
            $_.LocalPath -notlike '*LocalService*'    -and
            $_.LocalPath -notlike '*NetworkService*'  -and
            $_.Special -eq $false
        }

    $count = ($profiles | Measure-Object).Count
    Write-Log -Action 'EnumerateProfiles' -Result 'Success' -Message ("Count={0}" -f $count)
    Write-AppEvent -Level Information -EventId 2105 -Message "WindowsMgmtScripts: DeleteProfile: EnumerateProfiles | Count=$count"
}
catch {
    $msg = "Failed to enumerate profiles: $($_.Exception.Message)"
    Write-Error $msg
    Write-Log -Action 'EnumerateProfiles' -Result 'Error' -Message $_.Exception.Message
    Write-AppEvent -Level Error -EventId 2102 -Message "WindowsMgmtScripts: DeleteProfile: Error | Message=""$($_.Exception.Message)"""
    Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
    return
}

if (-not $profiles -or $profiles.Count -eq 0) {
    Write-Host "No eligible user profiles found."
    Write-Log -Action 'EnumerateProfiles' -Result 'Empty' -Message 'No profiles matched filters'
    Write-AppEvent -Level Warning -EventId 2101 -Message "WindowsMgmtScripts: DeleteProfile: Blocked | Reason=No eligible profiles"
    Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
    return
}

$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Build display list (robust LastUse handling)
$display = @()
foreach ($p in $profiles) {
    $username = Split-Path $p.LocalPath -Leaf
    # Prefer safe DMTF conversion; fall back to raw Get-Date if it looks normal
    $lastUse = Convert-DmtfToDateTimeSafe -Dmtf $p.LastUseTime
    if (-not $lastUse -and $p.LastUseTime) {
        try { $lastUse = Get-Date $p.LastUseTime } catch { $lastUse = $null }
    }
    $sizeMB = Get-FolderSizeMB -Path $p.LocalPath

    $display += [PSCustomObject]@{
        Username   = $username
        SID        = $p.SID
        Path       = $p.LocalPath
        LastUse    = $lastUse
        SizeMB     = $sizeMB
        Loaded     = [bool]$p.Loaded
        IsCurrent  = ($p.SID -eq $currentSid)
        CimObject  = $p
    }
}

if ($display.Count -eq 0) {
    Write-Host "No eligible user profiles found."
    Write-Log -Action 'PrepareDisplay' -Result 'Empty' -Message 'No display rows created'
    Write-AppEvent -Level Warning -EventId 2101 -Message "WindowsMgmtScripts: DeleteProfile: Blocked | Reason=No display rows"
    Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
    return
}

$display = $display | Sort-Object LastUse

Write-Host "Select a profile to delete:`n" -ForegroundColor Cyan
for ($i = 0; $i -lt $display.Count; $i++) {
    $row = $display[$i]
    $last = if ($row.LastUse) { $row.LastUse.ToString("yyyy-MM-dd HH:mm") } else { "N/A" }
    $loadedTag  = if ($row.Loaded)   { " [LOADED]" } else { "" }
    $currentTag = if ($row.IsCurrent){ " [CURRENT USER]" } else { "" }
    Write-Host ("{0,2}) {1}{2}{3}  | Last Use: {4} | Size: {5} MB" -f ($i+1), $row.Username, $loadedTag, $currentTag, $last, $row.SizeMB)
}

Write-Host
$choice = Read-Host "Enter the number of the profile to delete (or press Enter to cancel)"
if ([string]::IsNullOrWhiteSpace($choice)) {
    Write-Host "Operation cancelled."
    Write-Log -Action 'SelectProfile' -Result 'Cancelled' -Message 'User pressed Enter'
    Write-AppEvent -Level Information -EventId 2103 -Message "WindowsMgmtScripts: DeleteProfile: Cancelled | Reason=User pressed Enter"
    Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
    return
}
if (-not ($choice -as [int])) {
    Write-Host "Invalid selection (not a number)."
    Write-Log -Action 'SelectProfile' -Result 'Invalid' -Message "Input=$choice"
    Write-AppEvent -Level Warning -EventId 2101 -Message "WindowsMgmtScripts: DeleteProfile: Blocked | Reason=Invalid selection (non-numeric)"
    Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
    return
}
$choice = [int]$choice
if ($choice -lt 1 -or $choice -gt $display.Count) {
    Write-Host "Invalid selection (out of range)."
    Write-Log -Action 'SelectProfile' -Result 'Invalid' -Message "OutOfRange=$choice"
    Write-AppEvent -Level Warning -EventId 2101 -Message "WindowsMgmtScripts: DeleteProfile: Blocked | Reason=Invalid selection (out of range)"
    Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
    return
}

$selected = $display[$choice - 1]

Write-Host "`nYou selected: $($selected.Username)"
Write-Host "SID:   $($selected.SID)"
Write-Host "Path:  $($selected.Path)"
Write-Host "Last:  $($selected.LastUse)"
Write-Host "Size:  $($selected.SizeMB) MB"
if ($selected.Loaded)   { Write-Warning "This profile is currently LOADED (in use)." }
if ($selected.IsCurrent){ Write-Warning "This is the CURRENTLY LOGGED-ON user." }

Write-Log -Action 'SelectProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $selected.Loaded -Result 'Selected' -Message 'User chose a profile'
Write-AppEvent -Level Information -EventId 2105 -Message "WindowsMgmtScripts: DeleteProfile: Selected | User=$($selected.Username), SID=$($selected.SID), Path=$($selected.Path), Loaded=$($selected.Loaded)"

if ($selected.Loaded) {
    $msg = "Deletion blocked: profile is LOADED"
    Write-Warning $msg
    Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $selected.Loaded -Result 'Blocked' -Message $msg
    Write-AppEvent -Level Warning -EventId 2101 -Message "WindowsMgmtScripts: DeleteProfile: Blocked | Reason=Profile LOADED, User=$($selected.Username)"
    Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
    return
}

$confirm = Read-Host "`nAre you sure you want to delete this profile (folder + registry)? (Y/N)"
if ($confirm -notmatch '^(Y|y)$') {
    Write-Host "Operation cancelled."
    Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $selected.Loaded -Result 'Cancelled' -Message 'User declined'
    Write-AppEvent -Level Information -EventId 2103 -Message "WindowsMgmtScripts: DeleteProfile: Cancelled | Reason=User declined, User=$($selected.Username)"
    Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
    return
}

try {
    Remove-CimInstance -InputObject $selected.CimObject -ErrorAction Stop
    Write-Host "`nProfile for '$($selected.Username)' deleted successfully." -ForegroundColor Green
    Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $selected.Loaded -Result 'Success' -Message 'CIM delete ok'
    Write-AppEvent -Level Information -EventId 2100 -Message "WindowsMgmtScripts: DeleteProfile: Success | User=$($selected.Username), SID=$($selected.SID), Path=$($selected.Path)"
}
catch {
    $err = "Failed to delete profile: $($_.Exception.Message)"
    Write-Error $err
    Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $selected.Loaded -Result 'Error' -Message $err
    Write-AppEvent -Level Error -EventId 2102 -Message "WindowsMgmtScripts: DeleteProfile: Error | Message=""$($_.Exception.Message)"", User=$($selected.Username)"
}
finally {
    Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Cyan
    Write-AppEvent -Level Information -EventId 2103 -Message "WindowsMgmtScripts: DeleteProfile: Finish | LogFile=$script:LogFile"
}
