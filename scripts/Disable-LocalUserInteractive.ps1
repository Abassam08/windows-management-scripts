# 1) Always force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 2) Download the RAW script to %TEMP%
$u = "https://raw.githubusercontent.com/Abassam08/windows-management-scripts/main/scripts/Disable-LocalUserInteractive.ps1"
$d = Join-Path $env:TEMP "Disable-LocalUserInteractive.ps1"
Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $d

# 3) Sanitize any smart quotes just in case (”, “, ’, ‘) → regular ASCII quotes
#    This protects you even if GitHub or a prior paste added curly quotes.
$raw = Get-Content -LiteralPath $d -Raw
$raw = $raw -replace [char]0x201C, '"' `
             -replace [char]0x201D, '"' `
             -replace [char]0x2018, "'" `
             -replace [char]0x2019, "'"
Set-Content -LiteralPath $d -Value $raw -Encoding UTF8

# 4) Run it
powershell.exe -ExecutionPolicy Bypass -File $d
