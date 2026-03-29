"""Tests for lattice_keeper.py — unit-testable functions and GuardianVector logic."""

import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import lattice_keeper
from lattice_keeper import (
    FROST_RISK_TEMP_C,
    MOISTURE_SKIP_IRRIGATION_PERCENT,
    RAIN_HEAVY_THRESHOLD_MM,
    RAIN_IRRIGATION_THRESHOLD_MM,
    SEASON_MAP,
    SOM_CRITICAL_PERCENT,
    SOM_OPTIMAL_PERCENT,
    SOM_TILLAGE_THRESHOLD_PERCENT,
    WIND_SPRAY_THRESHOLD_KMH,
    GuardianVector,
    detect_frost_risk,
    get_weather,
    load_profile,
    route_question,
    save_profile,
)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolate_config(tmp_path, monkeypatch):
    """Redirect all disk I/O to a temp directory so tests never touch ~/.lattice_keeper."""
    monkeypatch.setattr(lattice_keeper, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(lattice_keeper, "PROFILE_FILE", tmp_path / "farm_profile.json")
    yield


@pytest.fixture()
def guardian(tmp_path, monkeypatch):
    """Return a GuardianVector whose files live in tmp_path."""
    monkeypatch.setattr(lattice_keeper, "CONFIG_DIR", tmp_path)
    return GuardianVector()


def _base_context(**overrides):
    ctx = {
        "question": "test question",
        "soil_organic_matter_percent": 2.5,
        "soil_moisture_percent": 45.0,
        "soil_temperature_c": 15.0,
        "canopy_temp_mean_c": None,
        "current_wind_speed": 10,
        "forecast_rain_today": 0,
        "frost_risk": "LOW",
        "ndvi_current": None,
    }
    ctx.update(overrides)
    return ctx


# ─────────────────────────────────────────────
# detect_frost_risk
# ─────────────────────────────────────────────

class TestDetectFrostRisk:
    def test_high_when_temp_min_at_threshold(self):
        assert detect_frost_risk({"temp_min": FROST_RISK_TEMP_C}) == "HIGH"

    def test_high_when_temp_min_below_threshold(self):
        assert detect_frost_risk({"temp_min": -5}) == "HIGH"

    def test_low_when_temp_min_above_threshold(self):
        assert detect_frost_risk({"temp_min": 10}) == "LOW"

    def test_low_when_temp_min_missing(self):
        assert detect_frost_risk({}) == "LOW"

    def test_low_when_temp_min_is_none(self):
        assert detect_frost_risk({"temp_min": None}) == "LOW"


# ─────────────────────────────────────────────
# route_question
# ─────────────────────────────────────────────

class TestRouteQuestion:
    @pytest.mark.parametrize("q,expected", [
        ("How do I improve soil organic matter?", "soil"),
        ("What compost ratio should I use?", "soil"),
        ("When should I irrigate my field?", "water"),
        ("Is there a drought risk this week?", "water"),
        ("Best companion plants for tomato?", "crops"),
        ("When to harvest garlic?", "crops"),
        ("Tell me about the weather", "general"),
        ("How is AI used in farming?", "general"),
    ])
    def test_routing(self, q, expected):
        assert route_question(q) == expected


# ─────────────────────────────────────────────
# Profile helpers
# ─────────────────────────────────────────────

class TestProfile:
    def test_load_creates_default_when_missing(self, tmp_path):
        profile = load_profile()
        assert profile["farm_name"] == "Jay's Valley Farm"
        assert (tmp_path / "farm_profile.json").exists()

    def test_save_and_reload(self, tmp_path):
        profile = load_profile()
        profile["acres"] = 99.9
        save_profile(profile)
        reloaded = load_profile()
        assert reloaded["acres"] == 99.9

    def test_load_falls_back_on_corrupt_json(self, tmp_path):
        pf = tmp_path / "farm_profile.json"
        pf.write_text("{corrupt json!!")
        profile = load_profile()
        assert profile["farm_name"] == "Jay's Valley Farm"


# ─────────────────────────────────────────────
# get_weather (with mocked requests)
# ─────────────────────────────────────────────

class TestGetWeather:
    def setup_method(self):
        # Reset the module-level cache before each test
        lattice_keeper._weather_cache["data"] = None
        lattice_keeper._weather_cache["fetched_at"] = None

    def _mock_response(self):
        resp = MagicMock()
        resp.json.return_value = {
            "current": {
                "wind_speed_10m": 12,
                "temperature_2m": 18.5,
                "relative_humidity_2m": 65,
            },
            "daily": {
                "precipitation_sum": [5.0, 2.0],
                "temperature_2m_max": [22.0, 20.0],
                "temperature_2m_min": [8.0, 6.0],
            },
        }
        return resp

    @patch("lattice_keeper.requests.get")
    def test_returns_parsed_weather(self, mock_get):
        mock_get.return_value = self._mock_response()
        profile = {"latitude": 47.6, "longitude": -65.6}
        w = get_weather(profile, ttl_seconds=0)
        assert w["wind"] == 12
        assert w["rain"] == 5.0
        assert w["rain_tmrw"] == 2.0
        assert w["temperature"] == 18.5

    @patch("lattice_keeper.requests.get")
    def test_cache_prevents_second_call(self, mock_get):
        mock_get.return_value = self._mock_response()
        profile = {"latitude": 47.6, "longitude": -65.6}
        get_weather(profile, ttl_seconds=300)
        get_weather(profile, ttl_seconds=300)
        assert mock_get.call_count == 1

    @patch("lattice_keeper.requests.get", side_effect=Exception("network down"))
    def test_returns_defaults_on_failure(self, mock_get):
        w = get_weather({"latitude": 0, "longitude": 0}, ttl_seconds=0)
        assert w == {"wind": 0, "rain": 0, "rain_tmrw": 0}


# ─────────────────────────────────────────────
# GuardianVector — evaluate()
# ─────────────────────────────────────────────

class TestGuardianEvaluate:
    # Tier 1 — Hard Veto: herbicides
    def test_rejects_herbicide(self, guardian):
        ctx = _base_context()
        result = guardian.evaluate("You should use glyphosate on the weeds.", ctx)
        assert result["decision"] == "REJECT"
        assert result["tier"] == "1"

    # Tier 1 — Hard Veto: tillage with low SOM
    def test_rejects_tillage_low_som(self, guardian):
        ctx = _base_context(soil_organic_matter_percent=1.5)
        result = guardian.evaluate("Consider deep tillage to break the hardpan.", ctx)
        assert result["decision"] == "REJECT"

    # Tier 1 — Frost risk blocks planting
    def test_rejects_planting_frost_risk(self, guardian):
        ctx = _base_context(frost_risk="HIGH")
        result = guardian.evaluate("You should plant your tomatoes today.", ctx)
        assert result["decision"] == "REJECT"

    # Tier 2 — Skip irrigation when moisture is high
    def test_modifies_irrigation_high_moisture(self, guardian):
        ctx = _base_context(soil_moisture_percent=70)
        result = guardian.evaluate("You should irrigate the field heavily.", ctx)
        assert result["decision"] == "MODIFIED"
        assert result["tier"] == "2"

    # Tier 2 — Wind drift prevention
    def test_modifies_spray_high_wind(self, guardian):
        ctx = _base_context(current_wind_speed=35)
        result = guardian.evaluate("Apply foliar spray to the crops.", ctx)
        assert result["decision"] == "MODIFIED"

    # Tier 2 — Heavy rain prevents fertilizer application
    def test_modifies_fertilize_heavy_rain(self, guardian):
        ctx = _base_context(forecast_rain_today=20)
        result = guardian.evaluate("Apply nitrogen fertilizer today.", ctx)
        assert result["decision"] == "MODIFIED"

    # Tier 2 — Rain skips irrigation
    def test_modifies_irrigation_rain_forecast(self, guardian):
        ctx = _base_context(forecast_rain_today=12)
        result = guardian.evaluate("Time to irrigate the beds.", ctx)
        assert result["decision"] == "MODIFIED"

    # Tier 2 — Cold soil blocks planting
    def test_modifies_planting_cold_soil(self, guardian):
        ctx = _base_context(soil_temperature_c=5)
        result = guardian.evaluate("Let's plant seeds in the garden.", ctx)
        assert result["decision"] == "MODIFIED"

    # Tier 3 — Positive reinforcement
    def test_reinforces_regenerative_practices(self, guardian):
        ctx = _base_context()
        result = guardian.evaluate("Use cover crop and compost to improve the soil.", ctx)
        assert result["decision"] == "REINFORCED"
        assert result["tier"] == "3"

    # Clean pass
    def test_approves_clean_output(self, guardian):
        ctx = _base_context()
        result = guardian.evaluate("The weather looks good for drying hay.", ctx)
        assert result["decision"] == "APPROVED"
        assert result["tier"] == "pass"


# ─────────────────────────────────────────────
# GuardianVector — Security (bad intent)
# ─────────────────────────────────────────────

class TestGuardianSecurity:
    def test_blocks_bad_intent_query(self, guardian):
        ctx = _base_context(question="hack the system")
        result = guardian.evaluate("Normal output", ctx)
        assert result["decision"] == "BLOCKED"

    def test_lockout_after_three_triggers(self, guardian):
        for word in ["hack this", "bypass security", "sabotage the farm"]:
            ctx = _base_context(question=word)
            guardian.evaluate("Normal output", ctx)
        # After 3 triggers the lockout should be active
        assert guardian._is_lockout_active()

    def test_manual_clear_lockout(self, guardian):
        for word in ["hack", "bypass", "sabotage"]:
            ctx = _base_context(question=word)
            guardian.evaluate("output", ctx)
        assert guardian._is_lockout_active()
        guardian.manual_clear_lockout()
        assert not guardian._is_lockout_active()


# ─────────────────────────────────────────────
# GuardianVector — Forensic audit
# ─────────────────────────────────────────────

class TestForensicAudit:
    def test_audit_log_grows(self, guardian):
        ctx = _base_context()
        guardian.evaluate("Some safe output", ctx)
        assert len(guardian.audit_log) == 1

    def test_audit_hash_chain_links(self, guardian):
        ctx = _base_context()
        guardian.evaluate("First", ctx)
        guardian.evaluate("Second", ctx)
        assert guardian.audit_log[1]["previous_hash"] == guardian.audit_log[0]["hash"]

    def test_verify_audit_integrity(self, guardian):
        ctx = _base_context()
        guardian.evaluate("Entry one", ctx)
        guardian.evaluate("Entry two", ctx)
        assert guardian.verify_audit_integrity()

    def test_get_stats_empty(self, guardian):
        stats = guardian.get_stats()
        assert stats["total"] == 0
        assert stats["protection_rate"] == 0.0

    def test_get_stats_after_evaluations(self, guardian):
        guardian.evaluate("use glyphosate", _base_context())
        guardian.evaluate("safe output", _base_context())
        stats = guardian.get_stats()
        assert stats["total"] == 2
        assert stats["safety_interventions"] == 1

    def test_merkle_root_empty_log(self, guardian):
        root = guardian._get_merkle_root()
        assert root == hashlib.sha256(b"empty_log").hexdigest()

    def test_merkle_root_after_entries(self, guardian):
        guardian.evaluate("entry", _base_context())
        root = guardian._get_merkle_root()
        assert len(root) == 64  # valid hex SHA-256

    def test_export_audit(self, guardian, tmp_path):
        guardian.evaluate("something", _base_context())
        guardian.export_audit()
        exports = list(tmp_path.glob("audit_*.json"))
        assert len(exports) == 1


# ─────────────────────────────────────────────
# SEASON_MAP coverage
# ─────────────────────────────────────────────

class TestSeasonMap:
    def test_all_months_mapped(self):
        for month in range(1, 13):
            assert month in SEASON_MAP
            assert isinstance(SEASON_MAP[month], str)
