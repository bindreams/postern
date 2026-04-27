"""Tests for postern.settings -- pydantic-settings configuration parsing."""

import pytest
from pydantic import ValidationError

from postern.settings import Settings


def _kw(**overrides: object) -> dict[str, object]:
    """Minimum viable Settings kwargs; pass overrides via kwargs."""
    base: dict[str, object] = {"secret_key": "test-secret-not-the-placeholder"}
    base.update(overrides)
    return base


# mta_require_dnssec ===================================================================================================
class TestRequireDnssecFromEnv:

    @pytest.mark.parametrize("raw", ["true", "True", "TRUE", "1", "yes", "on"])
    def test_truthy_strings_resolve_to_true(self, monkeypatch: pytest.MonkeyPatch, raw: str):
        monkeypatch.setenv("SECRET_KEY", "test-secret-not-the-placeholder")
        monkeypatch.setenv("MTA_REQUIRE_DNSSEC", raw)
        s = Settings()
        assert s.mta_require_dnssec is True

    @pytest.mark.parametrize("raw", ["false", "False", "FALSE", "0", "no", "off"])
    def test_falsy_strings_resolve_to_false(self, monkeypatch: pytest.MonkeyPatch, raw: str):
        monkeypatch.setenv("SECRET_KEY", "test-secret-not-the-placeholder")
        monkeypatch.setenv("MTA_REQUIRE_DNSSEC", raw)
        s = Settings()
        assert s.mta_require_dnssec is False

    @pytest.mark.parametrize("raw", ["auto", "AUTO", ""])
    def test_auto_strings_resolve_to_auto(self, monkeypatch: pytest.MonkeyPatch, raw: str):
        monkeypatch.setenv("SECRET_KEY", "test-secret-not-the-placeholder")
        monkeypatch.setenv("MTA_REQUIRE_DNSSEC", raw)
        s = Settings()
        assert s.mta_require_dnssec == "auto"

    def test_unset_defaults_to_auto(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRET_KEY", "test-secret-not-the-placeholder")
        monkeypatch.delenv("MTA_REQUIRE_DNSSEC", raising=False)
        s = Settings()
        assert s.mta_require_dnssec == "auto"

    @pytest.mark.parametrize("raw", ["garbage", "maybe"])
    def test_invalid_strings_raise(self, monkeypatch: pytest.MonkeyPatch, raw: str):
        monkeypatch.setenv("SECRET_KEY", "test-secret-not-the-placeholder")
        monkeypatch.setenv("MTA_REQUIRE_DNSSEC", raw)
        with pytest.raises(ValidationError, match="invalid MTA_REQUIRE_DNSSEC"):
            Settings()


class TestRequireDnssecProgrammatic:

    def test_accepts_python_true(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("MTA_REQUIRE_DNSSEC", raising=False)
        s = Settings(**_kw(mta_require_dnssec=True))
        assert s.mta_require_dnssec is True

    def test_accepts_python_false(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("MTA_REQUIRE_DNSSEC", raising=False)
        s = Settings(**_kw(mta_require_dnssec=False))
        assert s.mta_require_dnssec is False

    def test_accepts_auto_literal(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("MTA_REQUIRE_DNSSEC", raising=False)
        s = Settings(**_kw(mta_require_dnssec="auto"))
        assert s.mta_require_dnssec == "auto"

    def test_rejects_garbage(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("MTA_REQUIRE_DNSSEC", raising=False)
        with pytest.raises(ValidationError, match="invalid MTA_REQUIRE_DNSSEC"):
            Settings(**_kw(mta_require_dnssec="not-a-value"))


# secret_key (existing behavior) =======================================================================================
class TestSecretKeyPlaceholder:

    def test_rejects_env_example_placeholder(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRET_KEY", "REPLACE_WITH_HEX_STRING")
        with pytest.raises(ValidationError, match="placeholder"):
            Settings()
