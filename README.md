# Windows Management Scripts

PowerShell tools for Windows endpoint maintenance and support—built to run on-demand from NinjaOne.

## What’s included
- **Remove-UserProfileInteractive.ps1**: Interactive profile cleanup (shows all profiles, labels LOADED/CURRENT USER, blocks risky deletes, removes profile folder + registry via CIM).
- **Manage-LocalUsers.ps1**: Interactively list local users, disable or delete them, and optionally remove the associated profile.

## How to use with NinjaOne (recommended)
Use the small “download & run” wrapper so endpoints always run the latest version from this repo:

```powershell
# Example: Remove-UserProfileInteractive
$scriptUrl = "https://raw.githubusercontent.com/Abassam08/windows-management-scripts/main/scripts/Remove-UserProfileInteractive.ps1"
$dest = "$env:TEMP\Remove-UserProfileInteractive.ps1"
Invoke-WebRequest -UseBasicParsing -Uri $scriptUrl -OutFile $dest
powershell.exe -ExecutionPolicy Bypass -File $dest
