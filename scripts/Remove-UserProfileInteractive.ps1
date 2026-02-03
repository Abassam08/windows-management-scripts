<#
.Title
    Remove-UserProfileInteractive.ps1

.SYNOPSIS
    Interactively delete local user profiles (folder + registry).

.DESCRIPTION
    Enumerates non-system, non-special profiles (including LOADED ones so you can see them).
    Displays a numbered list with username, last use time, and size.
    Blocks deletion if the selected profile is currently LOADED (in use).

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

# --- Gather profiles via CIM (modern) ---
try {
    $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
        Where-Object {
            $_.LocalPath -and
            $_.LocalPath -notlike '*systemprofile*' -and
            $_.LocalPath -notlike '*LocalService*'  -and
            $_.LocalPath -notlike '*NetworkService*' -and
            $_.Special -eq $false       # show Default/Public/etc. only if not special
            # NOTE: We intentionally DO NOT filter on Loaded here (we will display LOADED)
        }
}
catch {
    Write-Error "Failed to enumerate profiles: $($_.Exception.Message)"
    return
}

if (-not $profiles -or $profiles.Count -eq 0) {
    Write-Host "No eligible user profiles found."
    return
}

# --- Current user SID to help annotate (not strictly required to block) ---
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# --- Helper: safely compute folder size (approx), ignoring errors ---
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

# Build a display list with metadata
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
    return
}

# Sort by LastUse (oldest first) to help cleanup decisions
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
    return
}

if (-not ($choice -as [int])) {
    Write-Host "Invalid selection (not a number)."
    return
}

$choice = [int]$choice
if ($choice -lt 1 -or $choice -gt $display.Count) {
    Write-Host "Invalid selection (out of range)."
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

# Block deletion if profile is loaded
if ($selected.Loaded) {
    Write-Warning "Deletion is blocked for LOADED profiles. Log off that user, or run the script from another admin account (or Safe Mode), then try again."
    return
}

# Confirm deletion (case-insensitive Y)
$confirm = Read-Host "`nAre you sure you want to delete this profile (folder + registry)? (Y/N)"
if ($confirm -notmatch '^(Y|y)$') {
    Write-Host "Operation cancelled."
    return
}

# --- Perform deletion via CIM ---
try {
    Remove-CimInstance -InputObject $selected.CimObject -ErrorAction Stop
    Write-Host "`nProfile for '$($selected.Username)' deleted successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to delete profile. Possible causes include: insufficient rights or file locks. Details: $($_.Exception.Message)"
}
