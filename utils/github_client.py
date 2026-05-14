"""GitHub API client with rate limiting and retry logic."""

import os
import time
from typing import Optional, List, Dict, Any
from functools import wraps
from github import Github, GithubException, RateLimitExceededException
from github.Organization import Organization
from github.Repository import Repository
from github.NamedUser import NamedUser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging

logger = logging.getLogger(__name__)


def rate_limit_handler(func):
    """Decorator to handle GitHub API rate limits with exponential backoff."""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        max_retries = 5
        base_delay = 60  # seconds
        
        for attempt in range(max_retries):
            try:
                return func(self, *args, **kwargs)
            except RateLimitExceededException as e:
                if attempt == max_retries - 1:
                    raise
                
                reset_time = self.client.get_rate_limit().core.reset.timestamp()
                wait_time = max(reset_time - time.time(), 0) + 5
                
                logger.warning(f"Rate limit exceeded. Waiting {wait_time:.0f} seconds...")
                time.sleep(wait_time)
                
            except GithubException as e:
                if e.status == 403 and "rate limit" in str(e).lower():
                    continue
                raise
        return None
    return wrapper


class GitHubClient:
    """Wrapper for GitHub API client with enhanced features."""
    
    def __init__(self, token: Optional[str] = None, base_url: str = "https://api.github.com"):
        """
        Initialize GitHub client.
        
        Args:
            token: GitHub personal access token (uses GH_TOKEN env var if not provided)
            base_url: GitHub API base URL (for GitHub Enterprise Server)
        """
        self.token = token or os.getenv("GH_TOKEN")
        if not self.token:
            raise ValueError("GitHub token is required. Set GH_TOKEN environment variable or pass --token")
        
        self.base_url = base_url
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        
        self.session = requests.Session()
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Initialize PyGithub client
        self.client = Github(
            login_or_token=self.token,
            base_url=base_url,
            per_page=100,
            retry=3,
        )
        
        # Test authentication
        try:
            self.user = self.client.get_user()
            logger.info(f"Authenticated as: {self.user.login}")
        except GithubException as e:
            raise ValueError(f"Failed to authenticate with GitHub: {e}")
    
    @rate_limit_handler
    def get_organization(self, org_name: str) -> Organization:
        """Get organization by name."""
        try:
            return self.client.get_organization(org_name)
        except GithubException as e:
            if e.status == 404:
                raise ValueError(f"Organization '{org_name}' not found")
            raise
    
    @rate_limit_handler
    def get_organization_repos(self, org_name: str) -> List[Repository]:
        """Get all repositories in an organization."""
        org = self.get_organization(org_name)
        repos = []
        
        # Handle pagination
        for repo in org.get_repos(type="all"):
            repos.append(repo)
            
        logger.info(f"Found {len(repos)} repositories in {org_name}")
        return repos
    
    @rate_limit_handler
    def get_repository(self, full_name: str) -> Repository:
        """Get repository by full name (owner/repo)."""
        return self.client.get_repo(full_name)
    
    @rate_limit_handler
    def get_branch_protection(self, repo: Repository, branch: str) -> Optional[Dict[str, Any]]:
        """Get branch protection rules for a specific branch."""
        try:
            protection = repo.get_branch(branch).get_protection()
            return {
                "enabled": True,
                "required_reviews": protection.required_pull_request_reviews is not None,
                "required_status_checks": protection.required_status_checks is not None,
                "enforce_admins": protection.enforce_admins.enabled if protection.enforce_admins else False,
                "restrictions": protection.restrictions is not None,
            }
        except GithubException as e:
            if e.status == 404:
                return {"enabled": False, "error": "Branch protection not enabled"}
            raise
    
    @rate_limit_handler
    def enable_branch_protection(self, repo: Repository, branch: str) -> bool:
        """Enable branch protection for a branch."""
        try:
            repo.get_branch(branch).edit_protection(
                require_push_whitelist=False,
                enforce_admins=True,
                required_approving_review_count=1,
                dismiss_stale_reviews=True,
                require_code_owner_reviews=True,
                required_status_checks=None,
                restrictions=None,
            )
            logger.info(f"Enabled branch protection for {repo.full_name}:{branch}")
            return True
        except GithubException as e:
            logger.error(f"Failed to enable branch protection for {repo.full_name}: {e}")
            return False
    
    @rate_limit_handler
    def get_secret_scanning_enabled(self, repo: Repository) -> bool:
        """Check if secret scanning is enabled for a repository."""
        try:
            # Check repository settings
            data = self.session.get(
                f"{self.base_url}/repos/{repo.full_name}/secret-scanning",
                headers={"Authorization": f"token {self.token}"}
            ).json()
            return data.get("status") == "enabled"
        except Exception:
            return False
    
    @rate_limit_handler
    def enable_secret_scanning(self, repo: Repository) -> bool:
        """Enable secret scanning for a repository."""
        try:
            response = self.session.patch(
                f"{self.base_url}/repos/{repo.full_name}/secret-scanning",
                headers={"Authorization": f"token {self.token}"},
                json={"status": "enabled"}
            )
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Failed to enable secret scanning for {repo.full_name}: {e}")
            return False
    
    @rate_limit_handler
    def create_issue(self, repo: Repository, title: str, body: str, labels: List[str] = None) -> bool:
        """Create an issue in the repository."""
        try:
            repo.create_issue(title=title, body=body, labels=labels or [])
            logger.info(f"Created issue in {repo.full_name}: {title}")
            return True
        except GithubException as e:
            logger.error(f"Failed to create issue in {repo.full_name}: {e}")
            return False
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get current rate limit status."""
        rate_limit = self.client.get_rate_limit()
        return {
            "core": {
                "limit": rate_limit.core.limit,
                "remaining": rate_limit.core.remaining,
                "reset": rate_limit.core.reset.timestamp(),
            },
            "search": {
                "limit": rate_limit.search.limit,
                "remaining": rate_limit.search.remaining,
                "reset": rate_limit.search.reset.timestamp(),
            }
        }
    
    def close(self):
        """Close the client session."""
        self.session.close()