# GitHub Security Auditor Installation Script for Windows

Write-Host "🔒 GitHub Security Auditor Installation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check Python version
Write-Host "Checking Python version..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python 3\.(1[0-9]|[2-9][0-9])") {
        Write-Host "✅ $pythonVersion found" -ForegroundColor Green
    } else {
        Write-Host "❌ Python 3.10+ required. Found $pythonVersion" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Python not found. Please install Python 3.10 or higher" -ForegroundColor Red
    exit 1
}

# Create virtual environment (optional)
$createVenv = Read-Host "Create virtual environment? (y/n)"
if ($createVenv -eq 'y') {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    Write-Host "✅ Virtual environment created and activated" -ForegroundColor Green
}

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install --upgrade pip
pip install -r requirements.txt

# Install package
Write-Host "Installing gh-security-auditor..." -ForegroundColor Yellow
pip install -e .

# Create directories
New-Item -ItemType Directory -Force -Path reports | Out-Null
New-Item -ItemType Directory -Force -Path .gh-audit-cache | Out-Null

# Create .auditignore if not exists
if (-not (Test-Path .auditignore)) {
    @"
# Default ignore patterns for secret scanning
*.test.js
*.test.py
test_*.py
*_test.go
node_modules/*
vendor/*
*.min.js
*.min.css
*.lock
package-lock.json
yarn.lock
poetry.lock
Gemfile.lock

# Add your custom patterns below
# secrets.yml
# config/credentials.yml
"@ | Out-File -FilePath .auditignore -Encoding utf8
    Write-Host "✅ Created .auditignore template" -ForegroundColor Green
}

Write-Host ""
Write-Host "✅ Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Set your GitHub token: `$env:GH_TOKEN='your_token_here'"
Write-Host "2. Run a test audit: gh-audit --org your-org-name --dry-run"
Write-Host "3. Generate a full report: gh-audit --org your-org-name --format both"
Write-Host ""
Write-Host "For more help: gh-audit --help" -ForegroundColor Yellow