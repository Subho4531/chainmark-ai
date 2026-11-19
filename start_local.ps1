Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Starting Chainmark AI Local Development Environment    " -ForegroundColor Cyan
Write-Host "   Backend Proxy Gateway:  http://localhost:8000         " -ForegroundColor Green
Write-Host "   Frontend React Console: http://localhost:5173         " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

uv run python run_local.py
