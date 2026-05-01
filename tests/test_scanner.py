"""Tests for the scanner logic."""

import sys
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.scanner import (
    ContentAnalyzer,
    Finding,
    ScanResult,
)
from rules.sensitive_files import match_sensitive_file


class TestContentAnalyzer:
    """Test cases for ContentAnalyzer."""

    def test_analyze_aws_key(self) -> None:
        """Test detection of AWS access keys in content."""
        analyzer = ContentAnalyzer()
        content = "AKIA1234567890ABCDEF"  # Fake AWS Key pattern
        findings = analyzer.analyze(content, "test.py")

        aws_findings = [f for f in findings if "AWS" in f.rule_name]
        assert len(aws_findings) > 0
        assert aws_findings[0].file_path == "test.py"

    def test_analyze_no_findings(self) -> None:
        """Test content with no sensitive data."""
        analyzer = ContentAnalyzer()
        content = "print('Hello World')"
        findings = analyzer.analyze(content, "test.py")
        assert len(findings) == 0


class TestSensitiveFileMatching:
    """Test cases for sensitive file name detection."""

    def test_match_sensitive_file(self) -> None:
        """Test detection of sensitive file names."""
        assert len(match_sensitive_file(".env")) > 0
        assert len(match_sensitive_file("id_rsa")) > 0
        assert len(match_sensitive_file("README.md")) == 0


class TestScanResult:
    """Test cases for ScanResult calculations."""

    def test_security_score_and_grade(self) -> None:
        """Test security score and grade properties."""
        result = ScanResult(
            repo_name="test",
            repo_full_name="owner/test",
            repo_url="http://...",
            repo_stars=10,
            repo_language="Python",
            scan_timestamp="...",
            scan_duration_s=1.0,
            files_analyzed=5,
        )

        # Initial score
        assert result.security_score == 100
        assert result.security_grade == "A"

        # Add a critical finding
        result.findings.append(
            Finding(
                rule_id="test",
                rule_name="test",
                severity="critical",
                category="test",
                description="test",
                file_path="test.py",
                line_number=1,
                line_content="...",
            )
        )

        assert result.security_score < 100
        assert result.security_grade != "A"
