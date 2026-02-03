<#
.Title
    Manage-LocalUsers.ps1

.SYNOPSIS
    Interactively list local users and choose to delete or disable them (with optional profile cleanup).

.DESCRIPTION
    Uses the LocalAccounts module to enumerate local users (excluding protected/built-in accounts),
    lets the operator select an account, shows details, and then:
      - Delete the local account (optionally also delete its local user profile)
      - OR disable the local account (safer)
    Includes safety checks and runs best on Windows 10/11 or Server 2016+.

.NOTES
    Author: Ahmed (Abassam08)
    Version: 1.0.0
    Requires: PowerShell 5.1+, Windows 10/11 or Server 2016+
    Run as: Administrator
    License: MIT
#>

param()

# --- Helper: admin check ---
function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Warning "Please run this script in an elevated PowerShell session (Run as Administrator)."
    return
}

# --- Check LocalAccounts cmdlets availability ---
if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
    Write-Error "Get-LocalUser/Remove-LocalUser/Disable-LocalUser are unavailable. You're likely on an older Windows/PowerShell. Consider using the legacy 'net user' approach."
    return
}

# --- Safety: protected/built-in accounts ---
$ProtectedAccounts = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')

# --- Enumerate local users ---
try {
    $users = Get-LocalUser | Where-Object { $ProtectedAccounts -notcontains $_.Name }
}
catch {
    Write-Error "Failed to enumerate local users: $($_.Exception.Message)"
    return
}

if (-not $users -or $users.Count -eq 0) {
    Write-Host "No deletable/disable-able local users found."
    return
}

# --- Display menu ---
Write-Host "Select a local user to manage:`n" -ForegroundColor Cyan
for ($i = 0; $i -lt $users.Count; $i++) {
    $u = $users[$i]
    $status = if ($u.Enabled) { 'Enabled' } else { 'Disabled' }
    Write-Host ("{0,2}) {1}  [{2}]" -f ($i+1), $u.Name, $status)
}

$choice = Read-Host "`nEnter the number of the user to manage (or press Enter to cancel)"
if ([string]::IsNullOrWhiteSpace($choice)) { Write-Host "Operation cancelled."; return }
if (-not ($choice -as [int])) { Write-Host "Invalid selection (not a number)."; return }
$choice = [int]$choice
if ($choice -lt 1 -or $choice -gt $users.Count) { Write-Host "Selection out of range."; return }

$selected = $users[$choice - 1]

# --- Show details ---
Write-Host "`nSelected user: $($selected.Name)" -ForegroundColor Yellow
Write-Host "Enabled:     $($selected.Enabled)"
Write-Host "Description: $($selected.Description)"
Write-Host "SID:         $($selected.SID)"

# --- Extra guard (shouldn't be needed due to initial filter) ---
if ($ProtectedAccounts -contains $selected.Name) {
    Write-Warning "This account is protected and will not be modified."
    return
}

# --- Choose action ---
Write-Host "`nChoose an action:" -ForegroundColor Cyan
Write-Host "  1) Delete this local account"
Write-Host "  2) Disable this local account (safer)"
Write-Host "  3) Cancel"

$action = Read-Host "Enter 1, 2, or 3"
switch ($action) {

    '1' {
        $confirm = Read-Host "Are you sure you want to DELETE local user '$($selected.Name)'? (Y/N)"
        if ($confirm -notmatch '^(Y|y)$') { Write-Host "Cancelled."; return }

        try {
            # Offer to delete the user's local profile if one exists (match via SID)
            $profile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$($selected.SID)'" -ErrorAction SilentlyContinue

            if ($profile) {
                # Block deletion if profile is LOADED
                if ($profile.Loaded) {
                    Write-Warning "The user's profile is currently LOADED. Please log off that user before profile deletion."
                } else {
                    $delProf = Read-Host "Also delete this user's local profile data (folder + registry)? (Y/N)"
                    if ($delProf -match '^(Y|y)$') {
                        try {
                            Remove-CimInstance -InputObject $profile -ErrorAction Stop
                            Write-Host "Profile deleted."
                        }
                        catch {
                            Write-Warning "Profile deletion failed: $($_.Exception.Message)"
                        }
                    }
                }
            }

            # Delete the local account
            Remove-LocalUser -Name $selected.Name -ErrorAction Stop
            Write-Host "Local user '$($selected.Name)' deleted successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to delete user: $($_.Exception.Message)"
        }
    }

    '2' {
        try {
            Disable-LocalUser -Name $selected.Name -ErrorAction Stop
            Write-Host "Local user '$($selected.Name)' disabled." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to disable user: $($_.Exception.Message)"
        }
    }

    default {
        Write-Host "No action taken."
    }
}
