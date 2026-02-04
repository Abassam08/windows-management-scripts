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
