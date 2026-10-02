"""Which model handles which stage, and with what settings.

Thinking is off wherever the reply must be JSON: Nemotron reasons by default and the
hidden reasoning counts against max_tokens, which truncates structured output.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from bop.config import Settings
from bop.errors import ConfigError


@dataclass(frozen=True)
class StagePolicy:
    role: str
    thinking: bool
    max_tokens: int
    temperature: float
    top_p: float = 0.95


STAGES: dict[str, StagePolicy] = {
    # Many findings, short answers: the fast model, no thinking, schema-constrained JSON.
    "triage": StagePolicy("triage", thinking=False, max_tokens=4096, temperature=0.2),
    # Reading whole modules and following calls across files: the 1M-context model, thinking on.
    "analyze": StagePolicy("deep", thinking=True, max_tokens=16384, temperature=0.6),
    # Turning that investigation into the verdict schema: same model, thinking off.
    "analyze_verdict": StagePolicy("deep", thinking=False, max_tokens=6144, temperature=0.2),
    # Writing a proof test and a patch: the strongest coder per dollar.
    "prove": StagePolicy("build", thinking=True, max_tokens=16384, temperature=0.6),
    "fix": StagePolicy("build", thinking=True, max_tokens=16384, temperature=0.6),
    # bop doctor --live
    "smoke": StagePolicy("triage", thinking=False, max_tokens=64, temperature=0.0),
}

# A role whose model may fail over to another role's model.
FALLBACKS: dict[str, str] = {"deep": "deep_fallback"}


@dataclass(frozen=True)
class Route:
    stage: str
    role: str
    model: str
    base_url: str
    thinking: bool
    max_tokens: int
    temperature: float
    top_p: float
    fallback: Route | None = None

    def extra_body(self) -> dict[str, object]:
        """Vendor parameters sent alongside the OpenAI request.

        Nemotron 3 and 3.5 read ``enable_thinking`` from the chat template arguments.
        """
        return {"chat_template_kwargs": {"enable_thinking": self.thinking}}


class Router:
    def __init__(self, settings: Settings, *, stages: dict[str, StagePolicy] | None = None) -> None:
        self.settings = settings
        self.stages = stages or STAGES

    def _route_for_role(self, stage: str, policy: StagePolicy, role: str) -> Route:
        return Route(
            stage=stage,
            role=role,
            model=self.settings.model_for(role),
            base_url=self.settings.base_url_for(role),
            thinking=policy.thinking,
            max_tokens=policy.max_tokens,
            temperature=policy.temperature,
            top_p=policy.top_p,
        )

    def route(self, stage: str, *, role: str | None = None) -> Route:
        try:
            policy = self.stages[stage]
        except KeyError as exc:
            raise ConfigError(f"no routing policy for stage {stage!r}") from exc
        chosen_role = role or policy.role
        primary = self._route_for_role(stage, policy, chosen_role)
        fallback_role = FALLBACKS.get(chosen_role)
        if fallback_role:
            fallback = self._route_for_role(stage, policy, fallback_role)
            if fallback.model != primary.model:
                primary = replace(primary, fallback=fallback)
        return primary
