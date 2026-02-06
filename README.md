## How to Use — Remove-UserProfileInteractive

This script lets you safely delete local user profiles (folder + registry) with:

- CSV logging  
- Optional Windows Event Log entries (enabled by default)
- Interactive UI
- Safety checks (loaded profiles, current user, etc.)

---

### 📌 Run from GitHub (Recommended)
Runs the latest version directly from the repository.

```
iex (iwr "https://raw.githubusercontent.com/Abassam08/windows-management-scripts/main/scripts/Remove-UserProfileInteractive.ps1" -UseBasicParsing)
```
---

OR: 
```

powershell -nop -ep bypass -c "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$u='https://raw.githubusercontent.com/Abassam08/windows-management-scripts/main/scripts/Remove-UserProfileInteractive.ps1';$d=\"\$env:TEMP\Remove-UserProfileInteractive.ps1\";Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $d; & $d"
``
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


---

## Disable-LocalUserInteractive — How to Use

This tool allows you to safely **disable a local user account** on Windows.

- Shows all non-system accounts
- Blocks built-in protected accounts
- Confirms before disabling
- Short, clean, safe for technicians

---

### Run from GitHub (Recommended)

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$u = "https://raw.githubusercontent.com/Abassam08/windows-management-scripts/main/scripts/Disable-LocalUserInteractive.ps1?v=$(Get-Date -UFormat %s)"
$src = (iwr -UseBasicParsing -Headers @{Pragma='no-cache'; 'Cache-Control'='no-cache'} $u).Content
$src = $src -replace ([char]0x201C), '"' -replace ([char]0x201D), '"' -replace ([char]0x2018), "'" -replace ([char]0x2019), "'"
& ([scriptblock]::Create($src))
```

---

Requirements

Run as Administrator
Windows 10/11 or Server 2016+
PowerShell 5.1+
