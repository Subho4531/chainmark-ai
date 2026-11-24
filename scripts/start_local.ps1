Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Starting Chainmark AI Local Development Environment    " -ForegroundColor Cyan
Write-Host "   Backend Proxy Gateway (Rust): http://localhost:8000   " -ForegroundColor Green
Write-Host "   Frontend React Console:       http://localhost:5173   " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$env:PATH = "$env:USERPROFILE\.cargo\bin;C:\Users\subho\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20261117-ucrt-x86_64\bin;$env:PATH"

python scripts/run_local.py
