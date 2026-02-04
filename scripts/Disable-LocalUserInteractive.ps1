<#
.SYNOPSIS
    Interactively disable a local user account.

.DESCRIPTION
    Lists local non-system accounts and lets the operator disable one.
    Blocks disabling built-in or special accounts.
    Confirms before applying the change.

.NOTES
    Author: Ahmed (Abassam08)
    Version: 1.0.1
    Requires: Windows 10/11 or Server 2016+
    Run as: Administrator
#>

# --- Require elevation ---
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'Please run this script in an elevated PowerShell session (Run as Administrator).'
    return
}

Write-Host 'Enumerating local user accounts...' -ForegroundColor Cyan

# Get all local users
$users = Get-LocalUser | Sort-Object Name

# Built-in or protected accounts to block
$protected = @(
    'Administrator',
    'DefaultAccount',
    'Guest',
    'WDAGUtilityAccount',
    'sshd'
)

# Filter display list
$display = $users | Where-Object { $_.Name -notin $protected }

if (-not $display -or $display.Count -eq 0) {
    Write-Host 'No eligible local user accounts to disable.'
    return
}

Write-Host "`n== Select a local account to DISABLE ==" -ForegroundColor Cyan

for ($i = 0; $i -lt $display.Count; $i++) {
    $u = $display[$i]
    $status = if ($u.Enabled) { 'Enabled' } else { 'Disabled' }
    Write-Host ('{0}) {1}  -  {2}' -f ($i+1), $u.Name, $status)
}

Write-Host
$choice = Read-Host 'Enter the number of the account to disable (or press Enter to cancel)'

if ([string]::IsNullOrWhiteSpace($choice)) {
    Write-Host 'Cancelled.'
    return
}

if (-not ($choice -as [int]) -or $choice -lt 1 -or $choice -gt $display.Count) {
    Write-Warning 'Invalid selection.'
    return
}

$target = $display[$choice - 1]

Write-Host ('`nYou selected: {0}' -f $target.Name)
Write-Host ('Current Status: {0}' -f (if ($target.Enabled) { 'Enabled' } else { 'Disabled' }))

if (-not $target.Enabled) {
    Write-Warning 'This account is already DISABLED.'
    return
}

$confirm = Read-Host 'Disable this account? (Y/N)'

if ($confirm -notmatch '^(Y|y)$') {
    Write-Host 'Cancelled.'
    return
}

try {
    Disable-LocalUser -Name $target.Name -ErrorAction Stop
    Write-Host ('`n✔ Local user ''{0}'' has been DISABLED.' -f $target.Name) -ForegroundColor Green
}
catch {
    # Avoid interpolated double quotes to be safe; use format operator instead.
    Write-Error ('Failed to disable user: {0}' -f $_.Exception.Message)
}
``
