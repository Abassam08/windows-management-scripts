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
Save the above as a NinjaOne script and run on any device. Update the tool here in GitHub; no changes needed in NinjaOne.
Requirements

Run PowerShell as Administrator.
Windows 10/11 or Server 2016+ (uses CIM / LocalAccounts cmdlets).

Safety notes

The profile tool blocks deletion of LOADED profiles to prevent breaking live sessions.
Manage-LocalUsers protects common built-in accounts and offers a Disable option.

License
MIT (see LICENSE).

---

## 🧾 LICENSE (MIT)  
MIT keeps things simple and permissive:

```text
MIT License

Copyright (c) 2026 Ahmed

Permission is hereby granted, free of charge, to any person obtaining a copy
...
