"""Unit tests for URL normalization and target scope validation."""

import pytest
from webvuln.core.target import TargetValidator, TargetValidationError


def test_target_validation_valid_http():
    target = TargetValidator.validate_and_parse("http://example.local:8080/app")
    assert target.scheme == "http"
    assert target.host == "example.local"
    assert target.port == 8080
    assert target.base_path == "/app"
    assert "example.local" in target.allowed_scope


def test_target_validation_auto_prepend_scheme():
    target = TargetValidator.validate_and_parse("127.0.0.1:5000")
    assert target.scheme == "http"
    assert target.host == "127.0.0.1"
    assert target.port == 5000


def test_target_validation_invalid_scheme():
    with pytest.raises(TargetValidationError):
        TargetValidator.validate_and_parse("ftp://malicious.local")


def test_target_scope_enforcement():
    target = TargetValidator.validate_and_parse("http://app.target.local", custom_scope={"target.local"})
    assert TargetValidator.is_in_scope("http://app.target.local/login", target) is True
    assert TargetValidator.is_in_scope("http://sub.target.local/api", target) is True
    assert TargetValidator.is_in_scope("http://evil-external.com/leak", target) is False
