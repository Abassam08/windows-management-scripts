## How to Use — Remove-UserProfileInteractive

This script lets you safely delete local user profiles (folder + registry) with:

- CSV logging  
- Optional Windows Event Log entries (enabled by default)
- Interactive UI
- Safety checks (loaded profiles, current user, etc.)

---

### 📌 Run from GitHub (Recommended)
Runs the latest version directly from the repository.

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$u = "https://raw.githubusercontent.com/Abassam08/windows-management-scripts/main/scripts/Remove-UserProfileInteractive.ps1"
$d = "$env:TEMP\Remove-UserProfileInteractive.ps1"
Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $d
powershell -ExecutionPolicy Bypass -File $d
```

---

### 📁 Log Locations

CSV Log:
C:\ProgramData\WindowsMgmtScripts\Logs\Remove-UserProfileInteractive.log.csv

---

Windows Event Viewer:
Application → Source: WindowsMgmtScripts

🔎 View Events from the Last 48 Hours

```

Get-WinEvent -FilterHashtable @{
  LogName='Application'
  ProviderName='WindowsMgmtScripts'
  StartTime=(Get-Date).AddHours(-48)
} | Select-Object TimeCreated, Id, LevelDisplayName, Message |
  Sort-Object TimeCreated -Desc

```

✔ Requirements

Run PowerShell as Administrator
Windows 10/11 or Server 2016+
PowerShell 5.1+
