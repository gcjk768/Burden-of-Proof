"""Prices, token estimates and the per-run spending cap."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from bop.errors import BudgetExceeded

# US dollars per million tokens (input, output), from the public Token Factory catalog on
# 2026-10-01. Used only when the live catalog cannot be read.
FALLBACK_PRICES: dict[str, tuple[float, float]] = {
    "nvidia/Nemotron-3_5-Lightning": (0.06, 0.24),
    "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B": (0.06, 0.24),
    "nvidia/nemotron-3-super-120b-a12b": (0.30, 0.90),
    "nvidia/Nemotron-3-Ultra-550b-a55b": (1.00, 3.00),
}

# Charged when a model is missing from every table, so an unknown model never counts as free.
UNKNOWN_MODEL_PRICE = (1.00, 3.00)


def estimate_tokens(text: str) -> int:
    """Rough token count for budgeting. Source code averages about three characters per token."""
    return max(1, len(text) // 3)


@dataclass
class PriceTable:
    prices: dict[str, tuple[float, float]] = field(default_factory=lambda: dict(FALLBACK_PRICES))
    source: str = "fallback table (2026-10-01)"

    @classmethod
    def from_catalog(cls, catalog: Mapping[str, object]) -> PriceTable:
        prices = dict(FALLBACK_PRICES)
        for model_id, entry in catalog.items():
            inp = getattr(entry, "input_price", None)
            out = getattr(entry, "output_price", None)
            if inp is not None and out is not None:
                prices[model_id] = (float(inp), float(out))
        return cls(prices=prices, source="public catalog")

    def per_million(self, model: str) -> tuple[float, float]:
        return self.prices.get(model, UNKNOWN_MODEL_PRICE)

    def cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        inp, out = self.per_million(model)
        return (prompt_tokens * inp + completion_tokens * out) / 1_000_000


@dataclass
class Budget:
    """Hard cap on spend for one run. Checked before every uncached model call."""

    cap_usd: float
    spent_usd: float = 0.0

    def check(self, estimated_usd: float) -> None:
        if self.spent_usd + estimated_usd > self.cap_usd:
            raise BudgetExceeded(
                f"next call (about ${estimated_usd:.4f}) would take the run past its cap "
                f"(${self.spent_usd:.4f} spent of ${self.cap_usd:.2f})"
            )

    def add(self, usd: float) -> None:
        self.spent_usd += usd

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.cap_usd - self.spent_usd)
