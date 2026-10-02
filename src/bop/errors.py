"""Exceptions shared across Burden of Proof."""


class BopError(Exception):
    """Base class for errors the CLI reports without a traceback."""


class ConfigError(BopError):
    """Configuration is missing or invalid."""


class BudgetExceeded(BopError):
    """A model call would take the run over its spending cap."""


class ModelUnavailable(BopError):
    """The model could not answer after the SDK's retries.

    ``permanent`` marks a model that is gone for the run (404 not found, 409 stopped). Timeouts,
    connection errors and 5xx are transient: one call may go to the fallback, the next tries again.
    """

    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


class RateLimited(BopError):
    """Token Factory kept answering 429 after the SDK's retries. The run stops instead of switching
    models, because the fallback shares the same account limits."""


class ModelOutputError(BopError):
    """The model's reply could not be parsed or failed validation."""


class SandboxError(BopError):
    """The sandbox could not run a command."""
