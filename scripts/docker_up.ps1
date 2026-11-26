Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Chainmark AI - Docker Test Environment                 " -ForegroundColor Cyan
Write-Host "   Console:      http://localhost:8080                    " -ForegroundColor Green
Write-Host "   Gateway:      http://localhost:8010                    " -ForegroundColor Green
Write-Host "   Cloud API:    http://localhost:3002                    " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path "$root\docker-compose.yml")) {
    Write-Error "docker-compose.yml not found in $root"
    exit 1
}

docker compose up -d --build
if ($LASTEXITCODE -ne 0) {
    Write-Error "docker compose up failed"
    exit $LASTEXITCODE
}

Write-Host ""
docker compose ps
Write-Host ""
Write-Host "Follow logs with: docker compose logs -f" -ForegroundColor Yellow
Write-Host "Tear down with:   docker compose down" -ForegroundColor Yellow
