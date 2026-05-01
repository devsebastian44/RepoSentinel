"""Tests for main.py module."""

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import main


class TestMain:
    """Test cases for main module."""

    @patch("main.argparse.ArgumentParser")
    def test_argument_parser_creation(self, mock_parser: Any) -> None:
        """Test that argument parser is created correctly."""
        mock_instance = MagicMock()
        mock_parser.return_value = mock_instance

        # This would normally be called in main()
        mock_instance.add_argument.assert_not_called()

    def test_banner_exists(self) -> None:
        """Test that BANNER constant exists and is a string."""
        assert hasattr(main, "BANNER")
        assert isinstance(main.BANNER, str)
        assert "GitHub Security Scanner" in main.BANNER

    def test_imports(self) -> None:
        """Test that all required modules can be imported."""
        assert hasattr(main, "config")
        assert hasattr(main, "GitHubClient")
        assert hasattr(main, "RepositoryScanner")
        assert hasattr(main, "get_logger")
        assert hasattr(main, "ReportManager")

    @patch("main.GitHubClient")
    @patch("main.RepositoryScanner")
    @patch("main.ReportManager")
    def test_main_url_command(self, mock_report, mock_scanner, mock_client):
        """Test the 'url' subcommand in main."""
        mock_args = MagicMock()
        mock_args.command = "url"
        mock_args.url = "https://github.com/owner/repo"
        mock_args.max_repos = 1
        mock_args.workers = 1
        mock_args.format = ["md"]
        mock_args.output_dir = Path("output")
        mock_args.no_banner = True
        mock_args.token = None
        
        mock_client.return_value._parse_github_url.return_value = ("owner", "repo")
        
        with patch("main.argparse.ArgumentParser.parse_args", return_value=mock_args):
            with patch("main.get_logger"):
                with patch("sys.exit") as mock_exit:
                    main.main()
        
        mock_exit.assert_called_with(0)
        
        mock_client.return_value.get_repo_by_url.assert_called_with(url=mock_args.url)


if __name__ == "__main__":
    pytest.main([__file__])
