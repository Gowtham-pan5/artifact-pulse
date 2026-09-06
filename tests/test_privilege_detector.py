"""Unit tests for PrivilegeDetector module."""

from __future__ import annotations

from core.privilege_detector import PrivilegeDetector


def test_is_admin_returns_boolean() -> None:
    is_adm = PrivilegeDetector.is_admin()
    assert isinstance(is_adm, bool)


def test_get_tier_info_structure() -> None:
    info = PrivilegeDetector.get_tier_info()
    assert "is_admin" in info
    assert "tier" in info
    assert info["tier"] in ("ADMIN_ELEVATED", "USER_SCOPE")
    assert "tier_label" in info
    assert "accessible_layers" in info
    assert len(info["accessible_layers"]) > 0
    assert "skipped_artifacts" in info
    assert "elevation_hint" in info
