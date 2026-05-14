"""Test script to verify GitHub Security Auditor installation."""

import sys
import os

def test_imports():
    """Test all imports work correctly."""
    print("Testing imports...")
    
    try:
        from gh_audit import __version__
        print(f"✓ Version: {__version__}")
    except Exception as e:
        print(f"✗ Version import failed: {e}")
        return False
    
    try:
        from gh_audit.models.finding import Finding, Severity
        print("✓ Models imported")
    except Exception as e:
        print(f"✗ Models import failed: {e}")
        return False
    
    try:
        from gh_audit.scanners.secret_scanner import SecretScanner
        print("✓ SecretScanner imported")
    except Exception as e:
        print(f"✗ SecretScanner import failed: {e}")
        return False
    
    try:
        from gh_audit.scanners.dependency_scanner import DependencyScanner
        print("✓ DependencyScanner imported")
    except Exception as e:
        print(f"✗ DependencyScanner import failed: {e}")
        return False
    
    try:
        from gh_audit.scanners.config_scanner import ConfigAuditor
        print("✓ ConfigAuditor imported")
    except Exception as e:
        print(f"✗ ConfigAuditor import failed: {e}")
        return False
    
    try:
        from gh_audit.utils.github_client import GitHubClient
        print("✓ GitHubClient imported")
    except Exception as e:
        print(f"✗ GitHubClient import failed: {e}")
        return False
    
    print("\n✅ All imports successful!")
    return True

def test_cli():
    """Test CLI entry point."""
    print("\nTesting CLI...")
    
    try:
        from gh_audit.cli import main
        print("✓ CLI main function imported")
    except Exception as e:
        print(f"✗ CLI import failed: {e}")
        return False
    
    print("✅ CLI test successful!")
    return True

if __name__ == "__main__":
    print("=" * 50)
    print("GitHub Security Auditor - Installation Test")
    print("=" * 50)
    
    success = test_imports()
    if success:
        test_cli()
        print("\n" + "=" * 50)
        print("🎉 Installation successful! You can now run the auditor.")
        print("=" * 50)
        print("\nNext steps:")
        print("1. Set your GitHub token: export GH_TOKEN=your_token_here")
        print("2. Run audit: gh-audit --org your-org-name")
        print("3. View help: gh-audit --help")
    else:
        print("\n❌ Installation test failed. Please check the errors above.")
        sys.exit(1)