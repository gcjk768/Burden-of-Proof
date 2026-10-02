import pytest

from bop.errors import BudgetExceeded
from bop.llm.cache import ResponseCache, request_key
from bop.llm.catalog import Catalog, check_models, parse_models_info
from bop.llm.cost import Budget, PriceTable, estimate_tokens

CATALOG = [
    {
        "name": "Nemotron-3_5-Lightning",
        "status": "active",
        "license": {"name": "OpenMDW-1.1"},
        "flavors": [
            {
                "model_id": "nvidia/Nemotron-3_5-Lightning",
                "max_model_len": 1048576,
                "input_price_per_million_tokens": 0.06,
                "output_price_per_million_tokens": 0.24,
                "regions": [{"country_code": "FI", "name": "eu-north1"}],
            }
        ],
    },
    {
        "name": "Nemotron-3-Ultra-550b-a55b",
        "status": "error",
        "flavors": [
            {
                "model_id": "nvidia/Nemotron-3-Ultra-550b-a55b",
                "max_model_len": 1048576,
                "input_price_per_million_tokens": 1.0,
                "output_price_per_million_tokens": 3.0,
            }
        ],
    },
]


def test_parse_uses_flavor_model_ids():
    models = parse_models_info(CATALOG)
    assert set(models) == {"nvidia/Nemotron-3_5-Lightning", "nvidia/Nemotron-3-Ultra-550b-a55b"}
    lightning = models["nvidia/Nemotron-3_5-Lightning"]
    assert lightning.active and lightning.context_tokens == 1048576 and lightning.regions == ("eu-north1",)
    assert parse_models_info({"data": CATALOG}).keys() == models.keys()


def test_check_models_reports_status_and_case_mistakes():
    catalog = Catalog(parse_models_info(CATALOG), source="test")
    checks = {
        c.role: c
        for c in check_models(
            {
                "triage": "nvidia/Nemotron-3_5-Lightning",
                "deep": "nvidia/Nemotron-3-Ultra-550b-a55b",
                "typo": "nvidia/nemotron-3_5-lightning",
            },
            catalog,
        )
    }
    assert checks["triage"].ok
    assert not checks["deep"].ok and "error" in checks["deep"].message
    assert not checks["typo"].ok and "case-sensitive" in checks["typo"].message


def test_prices_from_catalog_and_unknown_models_are_not_free():
    table = PriceTable.from_catalog(parse_models_info(CATALOG))
    assert table.cost("nvidia/Nemotron-3-Ultra-550b-a55b", 1_000_000, 1_000_000) == pytest.approx(4.0)
    assert table.cost("someone/else", 1_000_000, 0) > 0


def test_budget_blocks_overspend():
    budget = Budget(cap_usd=1.0)
    budget.add(0.9)
    budget.check(0.05)
    with pytest.raises(BudgetExceeded):
        budget.check(0.2)


def test_estimate_tokens_is_positive():
    assert estimate_tokens("") == 1 and estimate_tokens("x" * 300) == 100


def test_cache_key_ignores_dict_order_and_modes(tmp_path):
    assert request_key({"a": 1, "b": [1, 2]}) == request_key({"b": [1, 2], "a": 1})
    cache = ResponseCache(tmp_path, "readwrite")
    cache.put("abcd", {"r": 1}, {"content": "x"})
    assert cache.get("abcd") == {"content": "x"}
    assert ResponseCache(tmp_path, "off").get("abcd") is None
    assert ResponseCache(tmp_path, "read").put("efgh", {}, {}) is None
