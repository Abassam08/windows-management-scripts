Windows Management Scripts
PowerShell tools for Windows endpoint maintenance and support—built to run on‑demand from NinjaOne.
What’s included

Remove-UserProfileInteractive.ps1: Interactive profile cleanup (shows all profiles, labels LOADED/CURRENT USER, blocks risky deletes, removes profile folder + registry via CIM).
Manage-LocalUsers.ps1: Interactively list local users, disable or delete them, and optionally remove the associated profile.

🔧 Quick Toolbelt (Copy/Paste One‑Liners)
Run these directly on any endpoint (elevated PowerShell). They download the latest version of each script from this repo to %TEMP% and execute it. Optionally uncomment the cleanup line to remove the downloaded file after use.

Requires outbound access to GitHub (raw content). If blocked, use the offline “here‑string” method shown in the docs.

A) Profiles tool — Remove‑UserProfileInteractive
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$u="https://raw.githubusercontent.com/Abassam08/windows-management-scripts/main/scripts/Remove-UserProfileInteractive.ps1";$d="$env:TEMP\Remove-UserProfileInteractive.ps1";Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $d;powershell.exe -ExecutionPolicy Bypass -File $d
# Optional cleanup:
# Remove-Item $d -Force -ErrorAction SilentlyContinue

B) Local users tool — Manage‑LocalUsers
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$u="https://raw.githubusercontent.com/Abassam08/windows-management-scripts/main/scripts/Manage-LocalUsers.ps1";$d="$env:TEMP\Manage-LocalUsers.ps1";Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $d;powershell.exe -ExecutionPolicy Bypass -File $d
# Optional cleanup:
# Remove-Item $d -Force -ErrorAction SilentlyContinue

How to use with NinjaOne (recommended)
Use the small “download & run” wrapper so endpoints always run the latest version from this repo:

# Example: Remove-UserProfileInteractive
$scriptUrl = "https://raw.githubusercontent.com/Abassam08/windows-management-scripts/main/scripts/Remove-UserProfileInteractive.ps1"
$dest = "$env:TEMP\Remove-UserProfileInteractive.ps1"
Invoke-WebRequest -UseBasicParsing -Uri $scriptUrl -OutFile $dest
powershell.exe -ExecutionPolicy Bypass -File $dest

Save the above as a NinjaOne script and run on any device. Update the tool here in GitHub; no changes needed in NinjaOne.
Requirements

Run PowerShell as Administrator.
Windows 10/11 or Server 2016+ (uses CIM / LocalAccounts cmdlets).

Safety notes

The profile tool blocks deletion of LOADED profiles to prevent breaking live sessions.
Manage-LocalUsers protects common built‑in accounts and offers a Disable option.

Logging
Both tools write CSV logs to C:\ProgramData\WindowsMgmtScripts\Logs\ (auto‑created).
See docs/logging.md for details.
License
MIT (see LICENSE).
