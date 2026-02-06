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
    Version: 1.4.0
    Requires: PowerShell 5.1+, Windows 10/11 or Server 2016+
    Run as: Administrator
    License: MIT

.CHANGELOG
    1.2.0  Original interactive delete with logging (your base).
    1.4.0  Added LOADED handling: schedule-at-boot & force-now, hive/process/service logic,
           safer scheduled task path, improved logging.

--------------------------------------------------------------------------- #>

[CmdletBinding()]
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
        # Get-Process -IncludeUserName works on PowerShell 5.1+ on Windows
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

        # Ensure folder exists; Register-ScheduledTask will create it if using -TaskPath
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
Write-Host "Enumerating user profiles... this may take a minute. Please don't press any keys." -ForegroundColor Yellow
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
# Build display list (with progress)
$display = @()
$idx = 0
$total = $profiles.Count

foreach ($p in $profiles) {
    $idx++
    $username = Split-Path $p.LocalPath -Leaf

    Write-Progress -Activity "Enumerating profiles" `
                   -Status "Scanning $username ($idx of $total)..." `
                   -PercentComplete (int * 100))

    $lastUse = Convert-DmtfToDateTimeSafe -Dmtf $p.LastUseTime
    if (-not $lastUse -and $p.LastUseTime) {
        try { $lastUse = Get-Date $p.LastUseTime } catch { $lastUse = $null }
    }

    $sizeMB = Get-FolderSizeMB -Path $p.LocalPath  # size calc can be slow; progress above keeps UI alive

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

# Clear the progress once done
Write-Progress -Activity "Enumerating profiles" -Completed
# ================================
# LOADED handling
# ================================
if ($selected.Loaded) {
    # Safety: never allow deleting the currently logged-on user
    if ($selected.IsCurrent) {
        $msg = "Deletion blocked: selected profile is the CURRENTLY LOGGED-ON user."
        Write-Warning $msg
        Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $true -Result 'Blocked' -Message $msg
        Write-AppEvent -Level Warning -EventId 2101 -Message "WindowsMgmtScripts: DeleteProfile: Blocked | Reason=Current user"
        Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
        return
    }

    Write-Warning "The selected profile is LOADED (in use)."
    Write-Host ""
    Write-Host "[1] Schedule deletion at next reboot (recommended)" -ForegroundColor Cyan
    Write-Host "    - Creates a one-time Startup task (SYSTEM) to remove the profile before it loads."
    Write-Host "    - Zero risk to your current session; minimal interference."
    Write-Host "[2] Force deletion NOW (advanced)" -ForegroundColor Yellow
    Write-Host "    - Logs off that user's sessions, stops services/processes, unloads hive, then deletes."
    Write-Host "    - Use only if you cannot reboot soon."
    Write-Host "[Enter] Cancel"
    Write-Host ""

    $choice2 = Read-Host "Choose 1 / 2 (or press Enter to cancel)"
    if ([string]::IsNullOrWhiteSpace($choice2)) {
        Write-Host "Operation cancelled."
        Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $true -Result 'Cancelled' -Message 'User cancelled at LOADED menu'
        Write-AppEvent -Level Information -EventId 2103 -Message "WindowsMgmtScripts: DeleteProfile: Cancelled | Reason=User cancelled at LOADED menu"
        Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
        return
    }

    switch ($choice2) {
        '1' {
            $taskName = "DeleteProfile_$($selected.Username)_$($selected.SID.Replace('-',''))"
            $taskPath = '\WindowsMgmtScripts\'

            $ok = Schedule-ProfileDeleteAtBoot -Sid $selected.SID -ProfilePath $selected.Path -TaskName $taskName -TaskFolder $taskPath
            if ($ok) {
                Write-Host "`nA one-time Startup task has been created to delete this profile on the next reboot:" -ForegroundColor Green
                Write-Host "  Task: $taskPath$taskName"
                Write-Log -Action 'ScheduleAtBoot' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $true -Result 'Scheduled' -Message "Task=$taskPath$taskName"
                Write-AppEvent -Level Information -EventId 2100 -Message "WindowsMgmtScripts: DeleteProfile: ScheduledAtBoot | Task=$taskPath$taskName, User=$($selected.Username)"

                $restart = Read-Host "Restart NOW to complete deletion? (Y/N)"
                if ($restart -match '^(Y|y)$') {
                    Write-Host "Restarting..." -ForegroundColor Yellow
                    Write-AppEvent -Level Information -EventId 2105 -Message "WindowsMgmtScripts: DeleteProfile: RestartNow | User=$($selected.Username)"
                    Restart-Computer -Force
                } else {
                    Write-Host "You can restart later to complete the deletion."
                }
            } else {
                Write-Warning "Failed to create Startup task. Nothing was changed."
                Write-Log -Action 'ScheduleAtBoot' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $true -Result 'Error' -Message 'Register-ScheduledTask failed'
                Write-AppEvent -Level Error -EventId 2102 -Message "WindowsMgmtScripts: DeleteProfile: ScheduleAtBoot Failed | User=$($selected.Username)"
            }
            Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
            return
        }

        '2' {
            # Force NOW path (advanced)
            $nt = Get-NTAccountFromSid -Sid $selected.SID
            if (-not $nt) { $nt = $selected.Username }  # fallback

            Write-Warning "FORCE DELETE NOW will:"
            Write-Host "  • Sign the user out of active sessions" -ForegroundColor Yellow
            Write-Host "  • Stop any services running as that user" -ForegroundColor Yellow
            Write-Host "  • Kill remaining processes of that user" -ForegroundColor Yellow
            Write-Host "  • Unload the user's registry hive (HKU\$($selected.SID))" -ForegroundColor Yellow
            Write-Host "  • Then delete the profile (WMI, fallback manual)" -ForegroundColor Yellow
            $confirmText = Read-Host "Type:  DELETE $($selected.Username)  to proceed"
            if ($confirmText -ne "DELETE $($selected.Username)") {
                Write-Host "Confirmation mismatch. Operation cancelled."
                Write-Log -Action 'ForceNow' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $true -Result 'Cancelled' -Message 'Typed confirmation mismatch'
                Write-AppEvent -Level Information -EventId 2103 -Message "WindowsMgmtScripts: DeleteProfile: ForceNow Cancelled | Reason=Typed confirmation mismatch"
                return
            }

            # 1) Logoff sessions
            $sessions = Get-UserSessions -UserName $nt
            if ($sessions.Count -gt 0) {
                Write-Host "Logging off $($sessions.Count) session(s) for $nt ..."
                Logoff-UserSessions -Sessions $sessions
                Start-Sleep -Seconds 2
            }

            # 2) Stop services and processes
            $stoppedSvcs = Stop-UserServices -NtAccount $nt
            $killedProcs = Stop-UserProcesses -NtAccount $nt

            # 3) Unload hive
            $hiveOk = Unload-UserHive -Sid $selected.SID

            # 4) Delete profile (WMI, fallback manual)
            $success = Remove-ProfileWmiFirstThenManual -Sid $selected.SID -ProfilePath $selected.Path

            $msg = "ForceNow: Sessions=$($sessions.Count), StoppedSvcs=$($stoppedSvcs.Count), KilledProcs=$($killedProcs.Count), HiveUnloaded=$hiveOk, Deleted=$success"
            if ($success) {
                Write-Host "`nProfile for '$($selected.Username)' deleted successfully." -ForegroundColor Green
                Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $true -Result 'Success' -Message $msg
                Write-AppEvent -Level Information -EventId 2100 -Message "WindowsMgmtScripts: DeleteProfile: ForceNow Success | $msg"
            } else {
                Write-Warning "Failed to delete profile after force operations."
                Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $true -Result 'Error' -Message $msg
                Write-AppEvent -Level Error -EventId 2102 -Message "WindowsMgmtScripts: DeleteProfile: ForceNow Error | $msg"
            }

            Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Cyan
            return
        }

        Default {
            Write-Host "Invalid selection. Operation cancelled."
            Write-Log -Action 'DeleteProfile' -TargetUser $selected.Username -TargetSID $selected.SID -ProfilePath $selected.Path -SizeMB $selected.SizeMB -Loaded $true -Result 'Cancelled' -Message 'Invalid choice at LOADED menu'
            Write-AppEvent -Level Information -EventId 2103 -Message "WindowsMgmtScripts: DeleteProfile: Cancelled | Reason=Invalid choice at LOADED menu"
            Write-Host ("[INFO] Log saved to: {0}" -f $script:LogFile) -ForegroundColor Yellow
            return
        }
    }
}

# ================================
# NOT LOADED -> standard confirmation & delete (your original path)
# ================================
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
