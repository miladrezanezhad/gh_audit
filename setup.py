# setup.py (updated with correct dependencies)
"""Setup configuration for gh-security-auditor package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="gh-security-auditor",
    version="1.0.0",
    author="GH Security Auditor Team",
    author_email="security@example.com",
    description="Professional CLI tool for GitHub security auditing with auto-fix capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/gh-security-auditor",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "PyGithub>=2.1.0",
        "requests>=2.31.0",
        "click>=8.1.0",
        "detect-secrets>=1.4.0",
        "safety>=2.3.0",
        "jinja2>=3.1.0",
        "rich>=13.0.0",
        "python-dotenv>=1.0.0",
        "aiohttp>=3.8.0",
        "packaging>=23.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "gh-security-auditor=gh_audit.cli:main",
            "gh-audit=gh_audit.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)