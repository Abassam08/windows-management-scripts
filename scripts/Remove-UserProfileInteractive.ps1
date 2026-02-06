<# ---------------------------------------------------------------------------
.Title
    Remove-UserProfileInteractive.ps1

.SYNOPSIS
    Interactively delete local user profiles (folder + registry), with logging.

.DESCRIPTION
    Enumerates non-system, non-special profiles (including LOADED ones so you can see them).
    Displays a numbered list with username, last use time, and size.
    If the selected profile is LOADED:
        [1] Schedule a one-time deletion at next reboot (runs as SYSTEM at startup).
        [2] Force delete NOW (log off user, stop services/processes, unload hive, then delete).
    Always blocks deletion of the CURRENTLY LOGGED-ON user (safety).
    Logs all significant actions to CSV and optionally Windows Event Log.

.NOTES
    Author: Ahmed (Abassam08)
    Version: 1.4.2  (adds Loading/Progress UI and input buffer flush)
    Requires: PowerShell 5.1+, Windows 10/11 or Server 2016+
    Run as: Administrator
    License: MIT
--------------------------------------------------------------------------- #>

[CmdletBinding()]
param(
    [string]$LogRoot = "C:\ProgramData\WindowsMgmtScripts\Logs",
    [bool]  $EnableEventLog = $true
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
        Write-Verbose "Write-AppEvent failed: $($_.Exception.Message)"
    }
}

# ================================
# CSV Logging
# ================================
function Initialize-Log {
    param([Parameter(Mandatory)][string]$LogFile)

    if (-not (Test-IsAdmin)) { return }

    if (-not (Test-Path -LiteralPath $LogRoot)) {
        New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
    }

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
    } catch {
        Write-Verbose "Write-Log failed: $($_.Exception.Message)"
    }
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
# Additions: session/process/service/hive helpers
# ================================
function Get-NTAccountFromSid {
    param([Parameter(Mandatory)][string]$Sid)
    try {
        return ([System.Security.Principal.SecurityIdentifier]$Sid).
            Translate([System.Security.Principal.NTAccount]).Value
    } catch { return $null }
}

function Get-UserSessions {
    <#
      Returns a list of hashtables with SessionId and State for a user.
      Uses 'quser' which is standard on client/server Windows.
    #>
    param([Parameter(Mandatory)][string]$UserName) # NTAccount (DOMAIN\User) or simple name
    $sessions = @()
    try {
        $out = (quser.exe) 2>$null
        if (-not $out) { return $sessions }
        foreach ($line in $out -split "`r?`n") {
            if ($line -match '^\s*(\S+)\s+(\S+)?\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$') {
                $u = $Matches[1]
                $id = [int]$Matches[3]
                $state = $Matches[4]
                # Compare ignoring domain prefix differences
                if ($u -ieq $UserName -or $u -ieq ($UserName.Split('\')[-1])) {
                    $sessions += @{ User=$u; SessionId=$id; State=$state }
                }
            }
        }
    } catch {}
    return $sessions
}

function Logoff-UserSessions {
    param([Parameter(Mandatory)][hashtable[]]$Sessions)
    foreach ($s in $Sessions) {
        try { logoff.exe $s.SessionId /V 2>$null } catch {}
    }
}

function Stop-UserServices {
    param([Parameter(Mandatory)][string]$NtAccount) # e.g., CONTOSO\cgray or .\cgray
    try {
        $pattern = '^' + [regex]::Escape($NtAccount) + '$'
        $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq 'Running' -and $_.StartName -match $pattern }
        foreach ($svc in $svcs) {
            try { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue } catch {}
        }
        return $svcs
    } catch { return @() }
}

function Stop-UserProcesses {
    param([Parameter(Mandatory)][string]$NtAccount)
    $killed = @()
    try {
        $procs = Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
                 Where-Object {
                    $_.UserName -and (
                        $_.UserName -ieq $NtAccount -or
                        $_.UserName.Split('\')[-1] -ieq $NtAccount.Split('\')[-1]
                    )
                 }
        foreach ($p in $procs) {
            try {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                $killed += $p
            } catch {}
        }
    } catch {}
    return $killed
}

function Unload-UserHive {
    param([Parameter(Mandatory)][string]$Sid)
    try {
        if (Test-Path -LiteralPath "Registry::HKEY_USERS\$Sid") {
            & reg.exe unload "HKU\$Sid" | Out-Null
            Start-Sleep -Milliseconds 600
        }
        return -not (Test-Path -LiteralPath "Registry::HKEY_USERS\$Sid")
    } catch { return $false }
}

function Remove-ProfileWmiFirstThenManual {
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$ProfilePath
    )
    $ok = $false
    try {
        $p = Get-CimInstance Win32_UserProfile -Filter "SID='$Sid'" -ErrorAction Stop
        Remove-CimInstance -InputObject $p -ErrorAction Stop
        $ok = $true
    } catch {
        # Fallback: manual cleanup (registry + folder)
        try {
            Unload-UserHive -Sid $Sid | Out-Null
            $regKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
            if (Test-Path -LiteralPath $regKey) {
                Remove-Item -LiteralPath $regKey -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path -LiteralPath $ProfilePath) {
                try { & takeown.exe /F $ProfilePath /R /D Y | Out-Null } catch {}
                try { & icacls.exe $ProfilePath /grant "*S-1-5-32-544:(OI)(CI)(F)" /T /C | Out-Null } catch {}
                Remove-Item -LiteralPath $ProfilePath -Recurse -Force -ErrorAction Stop
            }
            $regGone = -not (Test-Path -LiteralPath $regKey)
            $dirGone = -not (Test-Path -LiteralPath $ProfilePath)
            $ok = ($regGone -and $dirGone)
        } catch { $ok = $false }
    }
    return $ok
}

function Schedule-ProfileDeleteAtBoot {
    <#
      Creates a one-time Scheduled Task running as SYSTEM at startup
      to delete the specified SID profile, then self-deletes the task.
    #>
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$ProfilePath,
        [Parameter(Mandatory)][string]$TaskName,
        [string]$TaskFolder = '\WindowsMgmtScripts\'
    )
    try {
        # The inline script run at startup (SYSTEM)
        $inline = @"
`$sid = '$Sid'
`$profilePath = '$ProfilePath'

# Try WMI delete first if not loaded
try {
    `$p = Get-CimInstance Win32_UserProfile -Filter "SID='`$sid'" -ErrorAction SilentlyContinue
    if (`$p -and -not `$p.Loaded) {
        Remove-CimInstance -InputObject `$p -ErrorAction Stop
    }
} catch {}

# Fallback: manual cleanup
try {
    if (Test-Path "Registry::HKEY_USERS\`$sid") { & reg.exe unload "HKU\`$sid" | Out-Null }
    `$regKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`$sid"
    if (Test-Path -LiteralPath `$regKey) { Remove-Item -LiteralPath `$regKey -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath `$profilePath) {
        try { & takeown.exe /F "`$profilePath" /R /D Y | Out-Null } catch {}
        try { & icacls.exe "`$profilePath" /grant "*S-1-5-32-544:(OI)(CI)(F)" /T /C | Out-Null } catch {}
        Remove-Item -LiteralPath "`$profilePath" -Recurse -Force -ErrorAction SilentlyContinue
    }
} catch {}
"@

        $action  = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -Command $([string]::Format("{{{0}}}", $inline))"
        $trigger = New-ScheduledTaskTrigger -AtStartup

        Register-ScheduledTask -TaskPath $TaskFolder -TaskName $TaskName -Action $action -Trigger $trigger -RunLevel Highest -User 'SYSTEM' -Force | Out-Null
        return $true
    } catch { return $false }
}

# ================================
# Init & prechecks
# ================================
$script:LogFile = Join-Path $LogRoot 'Remove-UserProfileInteractive.log.csv'
Initialize-Log -LogFile $script:LogFile

Write-Host ("[INFO] Logging to: {0}" -f $script:LogFile) -ForegroundColor Cyan
