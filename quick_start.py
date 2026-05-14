#!/usr/bin/env python3
"""Quick start script for GitHub Security Auditor."""

import subprocess
import sys
import os
from pathlib import Path

def check_github_token():
    """Check if GitHub token is set."""
    token = os.getenv('GH_TOKEN')
    if not token:
        print("❌ GH_TOKEN environment variable not set")
        print("\nPlease set your GitHub token:")
        print("  Windows: $env:GH_TOKEN='your_token_here'")
        print("  Linux/Mac: export GH_TOKEN='your_token_here'")
        return False
    print("✅ GitHub token found")
    return True

def run_quick_audit():
    """Run a quick audit on a test organization."""
    print("\n🔍 Running quick audit...")
    
    # Ask for organization name
    org_name = input("\nEnter GitHub organization name to audit: ").strip()
    
    if not org_name:
        print("❌ Organization name required")
        return False
    
    # Run dry-run first
    print(f"\n📊 Running dry-run audit on {org_name}...")
    cmd = [
        sys.executable, "-m", "gh_audit.cli",
        "--org", org_name,
        "--dry-run",
        "--format", "json",
        "--output", "./reports/quick_audit"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        
        if result.returncode == 0:
            print("\n✅ Quick audit completed successfully!")
            print(f"📁 Reports saved to: ./reports/quick_audit")
            return True
        else:
            print("\n❌ Audit failed")
            return False
            
    except Exception as e:
        print(f"❌ Error running audit: {e}")
        return False

def main():
    print("=" * 50)
    print("🚀 GitHub Security Auditor - Quick Start")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 10):
        print("❌ Python 3.10+ required")
        sys.exit(1)
    
    # Check token
    if not check_github_token():
        print("\n⚠️  Please set your GitHub token and try again")
        sys.exit(1)
    
    # Show menu
    print("\nSelect an option:")
    print("1. Run quick audit (dry-run)")
    print("2. Run full audit with HTML report")
    print("3. Show help")
    print("4. Exit")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == '1':
        run_quick_audit()
    elif choice == '2':
        org_name = input("Enter organization name: ").strip()
        if org_name:
            cmd = f"gh-audit --org {org_name} --format both --output ./reports/full_audit"
            print(f"\nRunning: {cmd}")
            os.system(cmd)
    elif choice == '3':
        subprocess.run([sys.executable, "-m", "gh_audit.cli", "--help"])
    else:
        print("Goodbye!")

if __name__ == "__main__":
    main()