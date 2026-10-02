"""Settings read from the environment (and an optional .env file).

Secrets are only ever held in memory. ``Settings.redacted()`` is what gets logged.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from bop.errors import ConfigError

DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/v1/"
DEFAULT_CATALOG_URL = "https://tokenfactory.nebius.com/api/public/models_info"

# Role name -> (environment variable, default model ID). IDs verified against the public
# Token Factory catalog on 2026-10-01; they are case-sensitive.
ROLE_DEFAULTS: dict[str, tuple[str, str]] = {
    "triage": ("NEBIUS_MODEL_TRIAGE", "nvidia/Nemotron-3_5-Lightning"),
    "triage_alt": ("NEBIUS_MODEL_TRIAGE_ALT", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"),
    "build": ("NEBIUS_MODEL_BUILD", "nvidia/nemotron-3-super-120b-a12b"),
    "deep": ("NEBIUS_MODEL_DEEP", "nvidia/Nemotron-3-Ultra-550b-a55b"),
    "deep_fallback": ("NEBIUS_MODEL_DEEP_FALLBACK", "nvidia/nemotron-3-super-120b-a12b"),
}


@dataclass(frozen=True)
class Settings:
    api_key: str | None
    project_id: str | None
    base_url: str
    models: Mapping[str, str]
    base_urls: Mapping[str, str]
    catalog_url: str
    home: Path
    warn_usd: float
    budget_usd: float
    cache_mode: str
    allow_unsandboxed: bool
    tavily_api_key: str | None = None
    gitlab_url: str | None = None
    gitlab_token: str | None = None
    maven_repo_override: Path | None = None
    extra: Mapping[str, str] = field(default_factory=dict)

    def model_for(self, role: str) -> str:
        try:
            return self.models[role]
        except KeyError as exc:
            raise ConfigError(f"unknown model role {role!r}") from exc

    def base_url_for(self, role: str) -> str:
        return self.base_urls.get(role, self.base_url)

    @property
    def runs_dir(self) -> Path:
        return self.home / "runs"

    @property
    def cache_dir(self) -> Path:
        return self.home / "cache"

    @property
    def maven_repo(self) -> Path:
        return self.maven_repo_override or self.home / "m2"

    @property
    def db_path(self) -> Path:
        return self.home / "bop.sqlite3"

    def with_overrides(self, **changes: object) -> Settings:
        return replace(self, **changes)

    def redacted(self) -> dict[str, object]:
        """A loggable view: secrets are reported only as set or unset."""
        return {
            "NEBIUS_API_KEY": "set" if self.api_key else "unset",
            "NEBIUS_PROJECT_ID": "set" if self.project_id else "unset",
            "TAVILY_API_KEY": "set" if self.tavily_api_key else "unset",
            "GITLAB_TOKEN": "set" if self.gitlab_token else "unset",
            "base_url": self.base_url,
            "models": dict(self.models),
            "base_urls": dict(self.base_urls),
            "home": str(self.home),
            "warn_usd": self.warn_usd,
            "budget_usd": self.budget_usd,
            "cache_mode": self.cache_mode,
        }


def _float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if value < 0:
        raise ConfigError(f"{name} must not be negative")
    return value


def load_settings(env: Mapping[str, str] | None = None, *, dotenv: Path | None = None) -> Settings:
    """Build settings from ``env`` (defaults to ``os.environ`` plus ``.env`` if present)."""
    if env is None:
        if dotenv is None:
            dotenv = Path(".env")
        if dotenv.is_file():
            from dotenv import dotenv_values

            file_values = {k: v for k, v in dotenv_values(dotenv).items() if v is not None}
            env = {**file_values, **os.environ}  # real environment wins over the file
        else:
            env = dict(os.environ)

    def get(name: str) -> str | None:
        value = env.get(name, "").strip()
        return value or None

    models = {role: get(var) or default for role, (var, default) in ROLE_DEFAULTS.items()}
    base_urls = {}
    for role in ROLE_DEFAULTS:
        override = get(f"NEBIUS_BASE_URL_{role.upper()}")
        if override:
            base_urls[role] = override

    cache_mode = (get("BOP_CACHE") or "readwrite").lower()
    if cache_mode not in {"readwrite", "read", "off"}:
        raise ConfigError("BOP_CACHE must be one of readwrite, read, off")

    warn = _float(env, "BOP_WARN_USD", 2.0)
    budget = _float(env, "BOP_BUDGET_USD", 5.0)
    if budget < warn:
        raise ConfigError("BOP_BUDGET_USD must be at least BOP_WARN_USD")

    return Settings(
        api_key=get("NEBIUS_API_KEY"),
        project_id=get("NEBIUS_PROJECT_ID"),
        base_url=get("NEBIUS_BASE_URL") or DEFAULT_BASE_URL,
        models=models,
        base_urls=base_urls,
        catalog_url=get("BOP_CATALOG_URL") or DEFAULT_CATALOG_URL,
        home=Path(get("BOP_HOME") or ".bop").expanduser().resolve(),
        warn_usd=warn,
        budget_usd=budget,
        cache_mode=cache_mode,
        allow_unsandboxed=get("BOP_ALLOW_UNSANDBOXED") == "1",
        tavily_api_key=get("TAVILY_API_KEY"),
        gitlab_url=get("GITLAB_URL"),
        gitlab_token=get("GITLAB_TOKEN"),
        maven_repo_override=Path(get("BOP_MAVEN_REPO")).expanduser().resolve() if get("BOP_MAVEN_REPO") else None,
    )
