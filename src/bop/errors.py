"""Exceptions shared across Burden of Proof."""


class BopError(Exception):
    """Base class for errors the CLI reports without a traceback."""


class ConfigError(BopError):
    """Configuration is missing or invalid."""


class BudgetExceeded(BopError):
    """A model call would take the run over its spending cap."""


class ModelUnavailable(BopError):
    """The model answered with an error that retries will not fix (stopped, removed, overloaded)."""


class ModelOutputError(BopError):
    """The model's reply could not be parsed or failed validation."""


class SandboxError(BopError):
    """The sandbox could not run a command."""
