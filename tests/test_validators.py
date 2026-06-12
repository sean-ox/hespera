"""Tests for input validators."""
import pytest
from python.utils.validators import is_valid_domain, sanitize_domain, is_safe_path


class TestDomainValidator:
    def test_valid_domains(self):
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.example.com") is True
        assert is_valid_domain("example.co.uk") is True
        assert is_valid_domain("a-b.example.com") is True
    
    def test_invalid_domains(self):
        assert is_valid_domain("") is False
        assert is_valid_domain("example") is False
        assert is_valid_domain("example..com") is False
        assert is_valid_domain("-example.com") is False
        assert is_valid_domain("example.com; rm -rf") is False
    
    def test_sanitize_domain(self):
        assert sanitize_domain("Example.COM") == "example.com"
        assert sanitize_domain("example.com/") == "example.com"
        assert sanitize_domain("example.com; malicious") == "example.commalicious"