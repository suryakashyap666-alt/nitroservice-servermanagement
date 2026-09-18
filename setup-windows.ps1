$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

$python = Get-Command py -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
}
if (-not $python) {
    throw "Python was not found. Install Python 3.11+ and enable 'Add Python to PATH'."
}

if (Test-Path ".venv") {
    Remove-Item -Recurse -Force ".venv"
}

& $python.Source -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host "Windows environment is ready. Start the API with:"
Write-Host ".\.venv\Scripts\python.exe -m uvicorn app.main:app --reload"