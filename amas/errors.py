"""Shared exception types."""


class AmasError(Exception):
    """Base class for all AMAS errors."""


class ConfigError(AmasError):
    """Invalid configuration."""


class TargetError(AmasError):
    """Repeated failures while talking to the target endpoint."""


class AttackDataError(AmasError):
    """Invalid attack catalogue entries."""