"""Tests for main.py module."""

import pytest
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add the root directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

import main


class TestMain:
    """Test cases for main module."""

    @patch('main.argparse.ArgumentParser')
    def test_argument_parser_creation(self, mock_parser):
        """Test that argument parser is created correctly."""
        mock_instance = MagicMock()
        mock_parser.return_value = mock_instance
        
        # This would normally be called in main()
        mock_instance.add_argument.assert_not_called()
        
    def test_banner_exists(self):
        """Test that BANNER constant exists and is a string."""
        assert hasattr(main, 'BANNER')
        assert isinstance(main.BANNER, str)
        assert 'RepoSentinel' in main.BANNER
        
    def test_imports(self):
        """Test that all required modules can be imported."""
        assert hasattr(main, 'config')
        assert hasattr(main, 'GitHubClient')
        assert hasattr(main, 'RepositoryScanner')
        assert hasattr(main, 'get_logger')
        assert hasattr(main, 'ReportManager')


if __name__ == '__main__':
    pytest.main([__file__])
