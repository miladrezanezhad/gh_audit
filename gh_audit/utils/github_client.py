# gh_audit/utils/github_client.py
"""GitHub API wrapper with rate limiting, retries, and enterprise support."""

import time
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

import requests
from github import Github, GithubException, RateLimitExceededException
from github.Repository import Repository
from github.Organization import Organization

logger = logging.getLogger(__name__)


class RateLimiter:
    """Handles GitHub API rate limiting with exponential backoff."""
    
    def __init__(self, max_retries: int = 5, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
    
    def wait_if_needed(self, github_client: Github) -> None:
        """Check rate limits and wait if necessary."""
        try:
            rate_limit = github_client.get_rate_limit()
            core_limit = rate_limit.core
            
            if core_limit.remaining < 10:
                reset_time = core_limit.reset
                wait_seconds = (reset_time - datetime.now()).total_seconds() + 5
                
                if wait_seconds > 0 and wait_seconds < 3600:  # Wait if less than 1 hour
                    logger.warning(f"Rate limit low ({core_limit.remaining} remaining). Waiting {wait_seconds:.0f} seconds...")
                    time.sleep(wait_seconds)
        except Exception as e:
            logger.debug(f"Could not check rate limits: {e}")
    
    def retry_on_rate_limit(self, func, *args, **kwargs):
        """Execute function with automatic retry on rate limit."""
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except RateLimitExceededException:
                wait_time = self.base_delay * (2 ** attempt)
                logger.warning(f"Rate limit exceeded. Attempt {attempt + 1}/{self.max_retries}. Waiting {wait_time}s...")
                time.sleep(wait_time)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise
                logger.debug(f"Retryable error: {e}. Retrying...")
                time.sleep(self.base_delay)
        raise Exception(f"Failed after {self.max_retries} retries")


class GitHubClient:
    """Wrapper for GitHub API with enhanced features."""
    
    def __init__(
        self,
        token: str,
        enterprise_url: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        verbose: bool = False
    ):
        """Initialize GitHub client.
        
        Args:
            token: GitHub personal access token
            enterprise_url: GitHub Enterprise server URL (optional)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verbose: Enable verbose logging
        """
        self.token = token
        self.enterprise_url = enterprise_url
        self.timeout = timeout
        self.verbose = verbose
        self.rate_limiter = RateLimiter(max_retries=max_retries)
        
        # Initialize GitHub client
        if enterprise_url:
            from github import GithubEnterprise
            self.client = GithubEnterprise(
                enterprise_url,
                login_or_token=token,
                timeout=timeout,
                retry=max_retries
            )
        else:
            self.client = Github(
                login_or_token=token,
                timeout=timeout,
                retry=max_retries
            )
        
        # Test authentication
        try:
            self.authenticated_user = self.client.get_user()
            if verbose:
                logger.info(f"Authenticated as: {self.authenticated_user.login}")
        except GithubException as e:
            raise ConnectionError(f"Failed to authenticate with GitHub: {e}")
    
    def get_organization(self, org_name: str) -> Organization:
        """Get GitHub organization by name.
        
        Args:
            org_name: Organization name
            
        Returns:
            Organization object
        """
        try:
            org = self.client.get_organization(org_name)
            if self.verbose:
                logger.info(f"Found organization: {org_name}")
            return org
        except GithubException as e:
            raise ValueError(f"Organization '{org_name}' not found or access denied: {e}")
    
    def get_organization_repos(
        self,
        org_name: str,
        include_archived: bool = False,
        include_forks: bool = False
    ) -> List[str]:
        """Get list of repository names in an organization.
        
        Args:
            org_name: Organization name
            include_archived: Include archived repositories
            include_forks: Include forked repositories
            
        Returns:
            List of repository names (full names with org prefix)
        """
        try:
            org = self.get_organization(org_name)
            
            # Get all repositories
            repos = org.get_repos()
            
            repo_names = []
            for repo in repos:
                # Filter archived if needed
                if repo.archived and not include_archived:
                    continue
                
                # Filter forks if needed
                if repo.fork and not include_forks:
                    continue
                
                repo_names.append(repo.full_name)
            
            if self.verbose:
                logger.info(f"Found {len(repo_names)} repositories in {org_name}")
            
            return repo_names
            
        except GithubException as e:
            logger.error(f"Failed to get repositories for {org_name}: {e}")
            raise
    
    def get_repository(self, repo_full_name: str) -> Repository:
        """Get a specific repository by full name.
        
        Args:
            repo_full_name: Repository full name (owner/repo)
            
        Returns:
            Repository object
        """
        try:
            repo = self.client.get_repo(repo_full_name)
            if self.verbose:
                logger.debug(f"Retrieved repository: {repo_full_name}")
            return repo
        except GithubException as e:
            logger.error(f"Failed to get repository {repo_full_name}: {e}")
            raise
    
    def get_file_content(
        self,
        repo_full_name: str,
        file_path: str,
        branch: str = "main"
    ) -> Optional[str]:
        """Get content of a file from repository.
        
        Args:
            repo_full_name: Repository full name
            file_path: Path to file in repository
            branch: Branch name (default: main)
            
        Returns:
            File content as string, or None if file doesn't exist
        """
        try:
            repo = self.get_repository(repo_full_name)
            
            # Try main branch, then master if main fails
            branches_to_try = [branch]
            if branch == "main":
                branches_to_try.append("master")
            
            for b in branches_to_try:
                try:
                    content = repo.get_contents(file_path, ref=b)
                    if content.encoding == "base64":
                        import base64
                        decoded_content = base64.b64decode(content.content).decode('utf-8')
                        return decoded_content
                except GithubException as e:
                    if e.status == 404:
                        continue
                    raise
            
            return None
            
        except GithubException as e:
            if e.status == 404:
                return None
            logger.warning(f"Failed to get file {file_path} from {repo_full_name}: {e}")
            return None
    
    def get_commit_history(
        self,
        repo_full_name: str,
        since: Optional[datetime] = None,
        max_commits: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get commit history for a repository.
        
        Args:
            repo_full_name: Repository full name
            since: Only get commits after this date
            max_commits: Maximum number of commits to fetch
            
        Returns:
            List of commit information dictionaries
        """
        try:
            repo = self.get_repository(repo_full_name)
            commits = []
            
            # Get commits with optional date filter
            if since:
                commits_iter = repo.get_commits(since=since)
            else:
                commits_iter = repo.get_commits()
            
            for commit in commits_iter[:max_commits]:
                commit_info = {
                    "hash": commit.sha,
                    "author": commit.author.login if commit.author else None,
                    "author_name": commit.commit.author.name,
                    "date": commit.commit.author.date,
                    "message": commit.commit.message,
                    "files": [f.filename for f in commit.files] if commit.files else []
                }
                commits.append(commit_info)
            
            if self.verbose:
                logger.info(f"Retrieved {len(commits)} commits from {repo_full_name}")
            
            return commits
            
        except GithubException as e:
            logger.error(f"Failed to get commits for {repo_full_name}: {e}")
            return []
    
    def get_branch_protection(self, repo_full_name: str, branch: str = "main") -> Optional[Dict[str, Any]]:
        """Get branch protection settings.
        
        Args:
            repo_full_name: Repository full name
            branch: Branch name
            
        Returns:
            Branch protection rules or None if not protected
        """
        try:
            repo = self.get_repository(repo_full_name)
            protection = repo.get_branch(branch).get_protection()
            
            protection_info = {
                "enabled": True,
                "requires_approving_reviews": protection.required_pull_request_reviews is not None,
                "required_approving_review_count": protection.required_pull_request_reviews.required_approving_review_count if protection.required_pull_request_reviews else 0,
                "requires_status_checks": protection.required_status_checks is not None,
                "requires_strict_status_checks": protection.required_status_checks.strict if protection.required_status_checks else False,
                "dismisses_stale_reviews": protection.required_pull_request_reviews.dismiss_stale_reviews if protection.required_pull_request_reviews else False,
                "requires_conversation_resolution": protection.required_conversation_resolution if hasattr(protection, 'required_conversation_resolution') else False
            }
            return protection_info
            
        except GithubException as e:
            if e.status == 404:
                return {"enabled": False}
            logger.debug(f"Failed to get branch protection for {repo_full_name}: {e}")
            return None
    
    def update_branch_protection(
        self,
        repo_full_name: str,
        branch: str = "main",
        requires_approving_reviews: int = 1,
        requires_status_checks: bool = True
    ) -> bool:
        """Update branch protection rules.
        
        Args:
            repo_full_name: Repository full name
            branch: Branch name
            requires_approving_reviews: Number of required approving reviews
            requires_status_checks: Require status checks to pass
            
        Returns:
            True if update successful
        """
        try:
            repo = self.get_repository(repo_full_name)
            branch_obj = repo.get_branch(branch)
            
            # Create protection rules
            repo.create_branch_protection_rule(
                branch=branch_obj.name,
                required_approving_review_count=requires_approving_reviews,
                dismiss_stale_reviews=True,
                require_code_owner_reviews=True,
                required_status_checks_contexts=None if not requires_status_checks else [],
                strict=requires_status_checks
            )
            
            if self.verbose:
                logger.info(f"Updated branch protection for {repo_full_name}")
            
            return True
            
        except GithubException as e:
            logger.error(f"Failed to update branch protection for {repo_full_name}: {e}")
            return False
    
    def check_rate_limit(self) -> Dict[str, Any]:
        """Check current rate limit status.
        
        Returns:
            Dictionary with rate limit information
        """
        try:
            rate_limit = self.client.get_rate_limit()
            return {
                "core": {
                    "limit": rate_limit.core.limit,
                    "remaining": rate_limit.core.remaining,
                    "reset": rate_limit.core.reset.isoformat()
                },
                "search": {
                    "limit": rate_limit.search.limit,
                    "remaining": rate_limit.search.remaining,
                    "reset": rate_limit.search.reset.isoformat()
                }
            }
        except Exception as e:
            logger.error(f"Failed to check rate limit: {e}")
            return {}
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the GitHub client."""
        self.client.close()