<#
.Title
    Manage-LocalUsers.ps1

.SYNOPSIS
    Interactively list local users and choose to delete or disable them (with optional profile cleanup) + logging.

.DESCRIPTION
    Uses the LocalAccounts module to enumerate local users (excluding protected/built-in accounts),
    lets the operator select an account, shows details, and then:
      - Delete the local account (optionally also delete its local user profile)
      - OR disable the local account (safer)
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

# --- Helper: admin check ---
function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Init log file path ---
$script:LogFile = Join-Path $LogRoot 'Manage-LocalUsers.log.csv'
Initialize-Log -LogFile $script:LogFile

# --- Require elevation ---
if (-not (Test-IsAdmin)) {
    Write-Warning "Please run this script in an elevated PowerShell session (Run as Administrator)."
    Write-Log -Action 'ElevationCheck' -Result 'Blocked' -Message 'Script not elevated'
    return
}

# --- Check LocalAccounts cmdlets ---
if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
    $msg = "Get-LocalUser/Remove-LocalUser/Disable-LocalUser unavailable."
    Write-Error $msg
    Write-Log -Action 'CmdletCheck' -Result 'Error' -Message $msg
    return
}

# --- Safety: protected/built-in accounts ---
$ProtectedAccounts = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')

# --- Enumerate local users ---
try {
    $users = Get-LocalUser | Where-Object { $ProtectedAccounts -notcontains $_.Name }
    Write-Log -Action 'EnumerateUsers' -Result 'Success' -Message ("Count={0}" -f ($users | Measure-Object).Count)
}
catch {
    $err = "Failed to enumerate local users: $($_.Exception.Message)"
    Write-Error $err
    Write-Log -Action 'EnumerateUsers' -Result 'Error' -Message $err
    return
}

if (-not $users -or $users.Count -eq 0) {
    Write-Host "No deletable/disable-able local users found."
    Write-Log -Action 'EnumerateUsers' -Result 'Empty' -Message 'No users matched filters'
    return
}

Write-Host "Select a local user to manage:`n" -ForegroundColor Cyan
for ($i = 0; $i -lt $users.Count; $i++) {
    $u = $users[$i]
    $status = if ($u.Enabled) { 'Enabled' } else { 'Disabled' }
    Write-Host ("{0,2}) {1}  [{2}]" -f ($i+1), $u.Name, $status)
}

$choice = Read-Host "`nEnter the number of the user to manage (or press Enter to cancel)"
if ([string]::IsNullOrWhiteSpace($choice)) {
    Write-Log -Action 'SelectUser' -Result 'Cancelled' -Message 'User pressed Enter'
    Write-Host "Operation cancelled."
    return
}
if (-not ($choice -as [int])) {
    Write-Host "Invalid selection (not a number)."
    Write-Log -Action 'SelectUser' -Result 'Invalid' -Message "Input=$choice"
    return
}
$choice = [int]$choice
if ($choice -lt 1 -or $choice -gt $users.Count) {
    Write-Host "Selection out of range."
    Write-Log -Action 'SelectUser' -Result 'Invalid' -Message "OutOfRange=$choice"
    return
}

$selected = $users[$choice - 1]

Write-Host "`nSelected user: $($selected.Name)" -ForegroundColor Yellow
Write-Host "Enabled:     $($selected.Enabled)"
Write-Host "Description: $($selected.Description)"
Write-Host "SID:         $($selected.SID)"
Write-Log -Action 'SelectUser' -TargetUser $selected.Name -TargetSID $selected.SID -Result 'Selected' -Message 'User chose local account'

if ($ProtectedAccounts -contains $selected.Name) {
    $msg = "Protected account; refusing to modify."
    Write-Warning $msg
    Write-Log -Action 'Guard' -TargetUser $selected.Name -TargetSID $selected.SID -Result 'Blocked' -Message $msg
    return
}

Write-Host "`nChoose an action:" -ForegroundColor Cyan
Write-Host "  1) Delete this local account"
Write-Host "  2) Disable this local account (safer)"
Write-Host "  3) Cancel"

$action = Read-Host "Enter 1, 2, or 3"
switch ($action) {
    '1' {
        $confirm = Read-Host "Are you sure you want to DELETE local user '$($selected.Name)'? (Y/N)"
        if ($confirm -notmatch '^(Y|y)$') {
            Write-Host "Cancelled."
            Write-Log -Action 'DeleteAccount' -TargetUser $selected.Name -TargetSID $selected.SID -Result 'Cancelled' -Message 'User declined'
            break
        }

        try {
            $profile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$($selected.SID)'" -ErrorAction SilentlyContinue
            if ($profile) {
                if ($profile.Loaded) {
                    $msg = "Profile is LOADED; cannot remove profile data now."
                    Write-Warning $msg
                    Write-Log -Action 'DeleteProfileData' -TargetUser $selected.Name -TargetSID $selected.SID -ProfilePath $profile.LocalPath -Loaded $true -Result 'Blocked' -Message $msg
                } else {
                    $delProf = Read-Host "Also delete this user's local profile data (folder + registry)? (Y/N)"
                    if ($delProf -match '^(Y|y)$') {
                        try {
                            $sizeMB = 0
                            try {
                                $bytes = (Get-ChildItem -LiteralPath $profile.LocalPath -Recurse -Force -ErrorAction SilentlyContinue |
                                          Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                                if (-not $bytes) { $bytes = 0 }
                                $sizeMB = [math]::Round($bytes / 1MB, 1)
                            } catch {}
                            Remove-CimInstance -InputObject $profile -ErrorAction Stop
                            Write-Host "Profile deleted."
                            Write-Log -Action 'DeleteProfileData' -TargetUser $selected.Name -TargetSID $selected.SID -ProfilePath $profile.LocalPath -SizeMB $sizeMB -Loaded $false -Result 'Success' -Message 'CIM delete ok'
                        }
                        catch {
                            $err = "Profile deletion failed: $($_.Exception.Message)"
                            Write-Warning $err
                            Write-Log -Action 'DeleteProfileData' -TargetUser $selected.Name -TargetSID $selected.SID -ProfilePath $profile.LocalPath -Loaded $false -Result 'Error' -Message $err
                        }
                    }
                }
            }

            Remove-LocalUser -Name $selected.Name -ErrorAction Stop
            Write-Host "Local user '$($selected.Name)' deleted successfully." -ForegroundColor Green
            Write-Log -Action 'DeleteAccount' -TargetUser $selected.Name -TargetSID $selected.SID -Result 'Success' -Message 'Account removed'
        }
        catch {
            $err = "Failed to delete user: $($_.Exception.Message)"
            Write-Error $err
            Write-Log -Action 'DeleteAccount' -TargetUser $selected.Name -TargetSID $selected.SID -Result 'Error' -Message $err
        }
    }
    '2' {
        try {
            Disable-LocalUser -Name $selected.Name -ErrorAction Stop
            Write-Host "Local user '$($selected.Name)' disabled." -ForegroundColor Green
            Write-Log -Action 'DisableAccount' -TargetUser $selected.Name -TargetSID $selected.SID -Result 'Success' -Message 'Account disabled'
        }
        catch {
            $err = "Failed to disable user: $($_.Exception.Message)"
            Write-Error $err
            Write-Log -Action 'DisableAccount' -TargetUser $selected.Name -TargetSID $selected.SID -Result 'Error' -Message $err
        }
    }
    default {
        Write-Host "No action taken."
        Write-Log -Action 'Menu' -Result 'NoAction' -Message "Selection=$action"
    }
}
