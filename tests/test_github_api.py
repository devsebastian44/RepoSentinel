"""Tests for the GitHubClient class."""

import sys
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.github_api import GitHubClient, RateLimitError, GitHubAPIError

@pytest.fixture
def client():
    return GitHubClient(token="fake_token")

class TestGitHubClient:
    """Test cases for GitHubClient."""

    @patch("requests.Session.get")
    def test_get_success(self, mock_get, client):
        """Test successful GET request."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": 123, "name": "test-repo"}
        mock_resp.headers = {"X-RateLimit-Remaining": "5000", "X-RateLimit-Reset": "12345678"}
        mock_get.return_value = mock_resp

        result = client._get("repos/owner/repo")
        assert result["name"] == "test-repo"
        mock_get.assert_called_once()

    @patch("requests.Session.get")
    def test_get_rate_limit(self, mock_get, client):
        """Test rate limit error handling."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "12345678"}
        mock_get.return_value = mock_resp

        with pytest.raises(RateLimitError):
            client._get("repos/owner/repo")

    @patch("requests.Session.get")
    def test_search_repos(self, mock_get, client):
        """Test search_repos_by_keyword."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"items": [{"full_name": "owner/repo"}]}
        mock_resp.headers = {"X-RateLimit-Remaining": "5000"}
        mock_get.return_value = mock_resp

        results = client.search_repos_by_keyword("security")
        assert len(results) == 1
        assert results[0]["full_name"] == "owner/repo"

    def test_parse_github_url(self, client):
        """Test URL parsing logic."""
        owner, repo = client._parse_github_url("https://github.com/devsebastian44/RepoSentinel")
        assert owner == "devsebastian44"
        assert repo == "RepoSentinel"

        owner, repo = client._parse_github_url("owner/repo")
        assert owner == "owner"
        assert repo == "repo"

        owner, repo = client._parse_github_url("invalid_url")
        assert owner is None
        assert repo is None
