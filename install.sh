#!/bin/bash

# GitHub Security Auditor Installation Script

echo "🔒 GitHub Security Auditor Installation"
echo "========================================"

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | grep -Po '(?<=Python )\d+\.\d+')
if [ -z "$python_version" ]; then
    echo "❌ Python 3 not found. Please install Python 3.10 or higher."
    exit 1
fi

major=$(echo $python_version | cut -d. -f1)
minor=$(echo $python_version | cut -d. -f2)

if [ "$major" -lt 3 ] || ([ "$major" -eq 3 ] && [ "$minor" -lt 10 ]); then
    echo "❌ Python 3.10+ required. Found $python_version"
    exit 1
fi

echo "✅ Python $python_version found"

# Create virtual environment (optional)
read -p "Create virtual environment? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "✅ Virtual environment created and activated"
fi

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install package in development mode
echo "Installing gh-security-auditor..."
pip install -e .

# Create necessary directories
mkdir -p reports .gh-audit-cache

# Create .auditignore template if it doesn't exist
if [ ! -f .auditignore ]; then
    cat > .auditignore << EOF
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
EOF
    echo "✅ Created .auditignore template"
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "1. Set your GitHub token: export GH_TOKEN=your_token_here"
echo "2. Run a test audit: gh-audit --org your-org-name --dry-run"
echo "3. Generate a full report: gh-audit --org your-org-name --format both"
echo ""
echo "For more help: gh-audit --help"