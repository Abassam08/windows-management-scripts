<#
.SYNOPSIS
    Interactively deletes a local user profile with CSV + optional Windows Event Log logging.

.VERSION
    1.2.0

.DESCRIPTION
    - Lists local user profiles under C:\Users (excluding special profiles).
    - Lets you choose a profile to remove.
    - Blocks deletion if the profile is loaded.
    - Logs to CSV in C:\ProgramData\WindowsMgmtScripts\Logs by default.
    - Optional: also logs to Windows Event Log (Application) when -WriteEventLog is passed.
    - Requires elevation to delete profiles and to register event source the first time.

.PARAMETER LogRoot
    Folder where CSV logs are written. Default: C:\ProgramData\WindowsMgmtScripts\Logs

.PARAMETER WriteEventLog
    When set, writes to Windows Event Log (Application) using Source = WindowsMgmtScripts.

.NOTES
    Run in an elevated PowerShell session for full functionality.

#>

[CmdletBinding()]
param(
    [string]$LogRoot = "C:\ProgramData\WindowsMgmtScripts\Logs",
    [switch]$WriteEventLog
)

# =========================
# v1.2.0 — Event Log helper
# =========================

# Constants for Application Event Log
$Global:AppEventLogName  = 'Application'
$Global:AppEventSource   = 'WindowsMgmtScripts'

function Ensure-AppEventSource {
    [CmdletBinding()]
    param()
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Global:AppEventSource)) {
            # Requires admin to create; if not elevated, this will fail and we fall back to CSV-only.
            New-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -ErrorAction Stop
            Write-EventLog -LogName $Global:AppEventLogName -Source $Global:AppEventSource -EventId 1000 -EntryType Information -Message 'Event source initialized.'
        }
    } catch {
        Write-Verbose "Ensure-AppEventSource failed or not elevated: $($_.Exception.Message)"
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

# =========================
# CSV logging helper
# =========================

$script:ScriptName = 'Remove-UserProfileInteractive'
$script:LogDir     = Join-Path -Path $LogRoot -ChildPath $script:ScriptName
$script:LogFile    = Join-Path -Path $script:LogDir -ChildPath ("{0}_{1}.csv" -f $script:ScriptName, (Get-Date -Format 'yyyyMMdd'))

function Initialize-Log {
    [CmdletBinding()]
    param()
    try {
        if (-not (Test-Path -LiteralPath $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null }
        if (-not (Test-Path -LiteralPath $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null }
    } catch {
        Write-Verbose "Initialize-Log failed: $($_.Exception.Message)"
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Info','Warning','Error')] [string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [string]$Action = '',
        [string]$User   = '',
        [string]$SID    = '',
        [string]$Path   = ''
    )

    $row = [PSCustomObject]@{
        Time    = (Get-Date).ToString('s')
        Level   = $Level
        Action  = $Action
        User    = $User
        SID     = $SID
        Path    = $Path
        Message = $Message
    }

    try {
        $row | Export-Csv -Path $script:LogFile -NoTypeInformation -Append -Encoding UTF8
    } catch {
        Write-Verbose "Write-Log failed: $($_.Exception.Message)"
    }
}

# =========================
# Utility helpers
# =========================

function Test-IsElevated {
    try {
        $currentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal        = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Resolve-UserFromSid {
    param([string]$SidString)
    try {
        $sid  = New-Object System.Security.Principal.SecurityIdentifier($SidString)
        $acct = $sid.Translate([System.Security.Principal.NTAccount]).Value  # e.g., WORKSTATION\jdoe
        if ($acct -like '*\*') { return ($acct.Split('\')[-1]) } else { return $acct }
    } catch {
        return ''
    }
}

# =========================
# Main
# =========================

Initialize-Log

# Event IDs for consistency
$EVT_START   = 2004
$EVT_SUCCESS = 2000
$EVT_BLOCKED = 2001
$EVT_ERROR   = 2002
$EVT_FINISH  = 2003

$actionName = 'DeleteProfile'

Write-Log -Level Info -Action "$actionName: Start" -Message "$actionName: Start"
Write-AppEvent -Level Information -EventId $EVT_START -Message "WindowsMgmtScripts: $actionName: Start"

if (-not (Test-IsElevated)) {
    $msg = "$actionName: Error | Message=""Script not running elevated. Please run PowerShell as Administrator."""
    Write-Log -Level Error -Action "$actionName: Error" -Message $msg
    Write-AppEvent -Level Error -EventId $EVT_ERROR -Message "WindowsMgmtScripts: $msg"
    Write-Warning "This script must be run in an elevated PowerShell session."
    return
}

try {
    # Enumerate local (non-special) user profiles under C:\Users
    $profilesRaw = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
        Where-Object {
            $_.LocalPath -and ($_.LocalPath -like 'C:\Users\*') -and ($_.Special -eq $false)
        }

    if (-not $profilesRaw -or $profilesRaw.Count -eq 0) {
        $msg = "$actionName: Blocked | Reason=No eligible profiles found"
        Write-Log -Level Warning -Action "$actionName: Blocked" -Message $msg
        Write-AppEvent -Level Warning -EventId $EVT_BLOCKED -Message "WindowsMgmtScripts: $msg"
        Write-Host "No eligible profiles were found under C:\Users."
        return
    }

    # Project view model for selection
    $profiles = $profilesRaw | ForEach-Object {
        [PSCustomObject]@{
            User   = (Resolve-UserFromSid -SidString $_.SID)
            SID    = $_.SID
            Path   = $_.LocalPath
            Loaded = [bool]$_.Loaded
            LastUseTime = if ($_.LastUseTime) { [Management.ManagementDateTimeConverter]::ToDateTime($_.LastUseTime) } else { $null }
        }
    }

    # Display options
    Write-Host ""
    Write-Host "== Select a profile to DELETE =="
    for ($i = 0; $i -lt $profiles.Count; $i++) {
        $p = $profiles[$i]
        $loadedMark = if ($p.Loaded) { ' (LOADED)' } else { '' }
        $lut = if ($p.LastUseTime) { $p.LastUseTime.ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
        Write-Host ("[{0}] User={1}, SID={2}, Path={3}{4}, LastUse={5}" -f ($i+1), $p.User, $p.SID, $p.Path, $loadedMark, $lut)
    }
    Write-Host ""

    # Selection prompt
    $sel = Read-Host "Enter the number of the profile to delete (or press Enter to cancel)"
    if ([string]::IsNullOrWhiteSpace($sel)) {
        $msg = "$actionName: Cancelled by user"
        Write-Log -Level Info -Action "$actionName: Cancelled" -Message $msg
        Write-AppEvent -Level Information -EventId $EVT_FINISH -Message "WindowsMgmtScripts: $msg"
        return
    }

    if (-not ($sel -as [int]) -or $sel -lt 1 -or $sel -gt $profiles.Count) {
        $msg = "$actionName: Blocked | Reason=Invalid selection"
        Write-Log -Level Warning -Action "$actionName: Blocked" -Message $msg
        Write-AppEvent -Level Warning -EventId $EVT_BLOCKED -Message "WindowsMgmtScripts: $msg"
        Write-Warning "Invalid selection."
        return
    }

    $target = $profiles[$sel - 1]
    $username = $target.User
    $sid      = $target.SID
    $path     = $target.Path

    # Block if loaded
    if ($target.Loaded) {
        $msg = "$actionName: Blocked | Reason=Profile LOADED, User=$username, SID=$sid, Path=$path"
        Write-Log -Level Warning -Action "$actionName: Blocked" -User $username -SID $sid -Path $path -Message $msg
        Write-AppEvent -Level Warning -EventId $EVT_BLOCKED -Message "WindowsMgmtScripts: $msg"
        Write-Warning "Profile is currently loaded. Please sign the user off and try again."
        return
    }

    # Final confirmation
    $confirm = Read-Host "Type YES to confirm deletion of profile for '$username' at '$path'"
    if ($confirm -ne 'YES') {
        $msg = "$actionName: Cancelled by user at confirmation"
        Write-Log -Level Info -Action "$actionName: Cancelled" -User $username -SID $sid -Path $path -Message $msg
        Write-AppEvent -Level Information -EventId $EVT_FINISH -Message "WindowsMgmtScripts: $msg"
        Write-Host "Cancelled."
        return
    }

    # Locate the original CIM instance for deletion
    $targetCim = $profilesRaw | Where-Object { $_.SID -eq $sid }
    if (-not $targetCim) {
        $msg = "$actionName: Error | Message=""Target profile instance not found for SID $sid"""
        Write-Log -Level Error -Action "$actionName: Error" -User $username -SID $sid -Path $path -Message $msg
        Write-AppEvent -Level Error -EventId $EVT_ERROR -Message "WindowsMgmtScripts: $msg"
        throw $msg
    }

    try {
        # Use the WMI Delete method for Win32_UserProfile
        $result = Invoke-CimMethod -InputObject $targetCim -MethodName Delete -ErrorAction Stop

        if ($null -ne $result -and $result.ReturnValue -ne 0) {
            $code = $result.ReturnValue
            $emsg = "$actionName: Error | Message=""Win32_UserProfile.Delete returned code $code"", User=$username, SID=$sid, Path=$path"
            Write-Log -Level Error -Action "$actionName: Error" -User $username -SID $sid -Path $path -Message $emsg
            Write-AppEvent -Level Error -EventId $EVT_ERROR -Message "WindowsMgmtScripts: $emsg"
            throw $emsg
        }

        $smsg = "$actionName: Success | User=$username, SID=$sid, Path=$path"
        Write-Log -Level Info -Action "$actionName: Success" -User $username -SID $sid -Path $path -Message $smsg
        Write-AppEvent -Level Information -EventId $EVT_SUCCESS -Message "WindowsMgmtScripts: $smsg"
        Write-Host "Success: Profile for '$username' has been deleted."
    } catch {
        $emsg = "$actionName: Error | Message=""$($_.Exception.Message)"", User=$username, SID=$sid, Path=$path"
        Write-Log -Level Error -Action "$actionName: Error" -User $username -SID $sid -Path $path -Message $emsg
        Write-AppEvent -Level Error -EventId $EVT_ERROR -Message "WindowsMgmtScripts: $emsg"
        throw
    }
}
finally {
    Write-Log -Level Info -Action "$actionName: Finish" -Message "$actionName: Finish"
    Write-AppEvent -Level Information -EventId $EVT_FINISH -Message "WindowsMgmtScripts: $actionName: Finish"
}
