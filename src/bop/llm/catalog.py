"""Reads the public Token Factory model catalog and checks configured model IDs against it.

The catalog at https://tokenfactory.nebius.com/api/public/models_info is a JSON array of
entries. The ID to send to the API is ``entry.flavors[].model_id`` (not ``entry.name``),
and an entry can be listed with ``status: "error"`` while the model is down.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass(frozen=True)
class CatalogModel:
    model_id: str
    name: str
    status: str
    context_tokens: int | None
    input_price: float | None
    output_price: float | None
    regions: tuple[str, ...] = ()
    license: str | None = None

    @property
    def active(self) -> bool:
        return self.status == "active"


@dataclass(frozen=True)
class ModelCheck:
    role: str
    model: str
    ok: bool
    message: str


@dataclass
class Catalog:
    models: dict[str, CatalogModel] = field(default_factory=dict)
    source: str = "none"

    def get(self, model_id: str) -> CatalogModel | None:
        return self.models.get(model_id)


def _entries(payload: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, Mapping):
        for key in ("data", "models", "items"):
            if isinstance(payload.get(key), list):
                return payload[key]
    raise ValueError("unrecognised catalog format")


def parse_models_info(payload: Any) -> dict[str, CatalogModel]:
    models: dict[str, CatalogModel] = {}
    for entry in _entries(payload):
        status = str(entry.get("status", "unknown"))
        license_info = entry.get("license")
        license_name = license_info.get("name") if isinstance(license_info, Mapping) else license_info
        for flavor in entry.get("flavors") or []:
            model_id = flavor.get("model_id")
            if not model_id:
                continue
            regions = tuple(
                str(r.get("name") or r.get("country_code") or "")
                for r in flavor.get("regions") or []
                if isinstance(r, Mapping)
            )
            models[model_id] = CatalogModel(
                model_id=model_id,
                name=str(entry.get("name", model_id)),
                status=status,
                context_tokens=flavor.get("max_model_len"),
                input_price=flavor.get("input_price_per_million_tokens"),
                output_price=flavor.get("output_price_per_million_tokens"),
                regions=regions,
                license=license_name,
            )
    return models


def fetch_catalog(url: str, *, timeout: float = 10.0, http: httpx.Client | None = None) -> Catalog:
    client = http or httpx.Client(timeout=timeout)
    try:
        response = client.get(url)
        response.raise_for_status()
        return Catalog(parse_models_info(response.json()), source=url)
    finally:
        if http is None:
            client.close()


def catalog_from_model_list(model_ids: Iterable[str]) -> Catalog:
    """Fallback when only the authenticated /v1/models list is reachable (no prices or status)."""
    models = {mid: CatalogModel(mid, mid, "active", None, None, None) for mid in model_ids}
    return Catalog(models, source="/v1/models")


def check_models(models: Mapping[str, str], catalog: Catalog) -> list[ModelCheck]:
    checks = []
    for role, model in models.items():
        entry = catalog.get(model)
        if entry is None:
            near = [m for m in catalog.models if m.lower() == model.lower()]
            hint = f" Did you mean {near[0]!r}? IDs are case-sensitive." if near else ""
            checks.append(ModelCheck(role, model, False, f"not in the catalog ({catalog.source}).{hint}"))
        elif not entry.active:
            checks.append(ModelCheck(role, model, False, f"listed with status {entry.status!r}"))
        else:
            ctx = f"{entry.context_tokens:,} tokens" if entry.context_tokens else "context unknown"
            checks.append(ModelCheck(role, model, True, f"active, {ctx}"))
    return checks
