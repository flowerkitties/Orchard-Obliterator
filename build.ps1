$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "csc.exe not found at $csc" }

New-Item -ItemType Directory -Force bin | Out-Null

$opts = @(
    '/nologo', '/target:exe', '/platform:x64', '/optimize+',
    '/out:bin\OrchardObliterator.exe',
    '/resource:orchard.sig,orchard.sig',
    '/r:System.Management.dll', '/r:System.Drawing.dll'
)
if (Test-Path app.ico) { $opts += '/win32icon:app.ico' }

& $csc @opts (Get-ChildItem src\*.cs | ForEach-Object FullName)
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Get-Item bin\OrchardObliterator.exe | Select-Object Name, Length, LastWriteTime
