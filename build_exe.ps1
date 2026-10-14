$ErrorActionPreference = "Stop"

python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --console `
    --hide-console hide-early `
    --name LogCatch `
    --collect-all tkinterdnd2 `
    logcatch.py

Write-Host "Build complete: dist\LogCatch.exe"
