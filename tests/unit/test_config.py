import pytest

from bop.config import ROLE_DEFAULTS, load_settings
from bop.errors import ConfigError


def test_defaults_use_verified_model_ids():
    s = load_settings({})
    assert s.model_for("triage") == "nvidia/Nemotron-3_5-Lightning"
    assert s.model_for("deep") == "nvidia/Nemotron-3-Ultra-550b-a55b"
    assert s.model_for("build") == "nvidia/nemotron-3-super-120b-a12b"
    assert s.base_url == "https://api.tokenfactory.nebius.com/v1/"
    assert set(s.models) == set(ROLE_DEFAULTS)


def test_overrides_and_per_role_base_url():
    s = load_settings({"NEBIUS_MODEL_DEEP": "x/y", "NEBIUS_BASE_URL_DEEP": "https://us.example/v1/"})
    assert s.model_for("deep") == "x/y"
    assert s.base_url_for("deep") == "https://us.example/v1/"
    assert s.base_url_for("triage") == s.base_url


def test_redacted_never_contains_secrets():
    s = load_settings({"NEBIUS_API_KEY": "sk-secret", "TAVILY_API_KEY": "tvly-secret", "GITLAB_TOKEN": "glpat-x"})
    text = repr(s.redacted())
    assert "secret" not in text and "glpat" not in text
    assert s.redacted()["NEBIUS_API_KEY"] == "set"


@pytest.mark.parametrize(
    "env",
    [
        {"BOP_CACHE": "sometimes"},
        {"BOP_WARN_USD": "two"},
        {"BOP_WARN_USD": "5", "BOP_BUDGET_USD": "1"},
        {"BOP_BUDGET_USD": "-1"},
    ],
)
def test_invalid_values_are_rejected(env):
    with pytest.raises(ConfigError):
        load_settings(env)


def test_unknown_role_is_an_error():
    with pytest.raises(ConfigError):
        load_settings({}).model_for("nope")
