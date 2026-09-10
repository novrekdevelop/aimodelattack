"""Target endpoint adapters."""

from amas.targets.base import (
    ChatMessage,
    ChatResult,
    MockTarget,
    OpenAICompatibleTarget,
    Target,
    build_target,
)

__all__ = [
    "ChatMessage",
    "ChatResult",
    "MockTarget",
    "OpenAICompatibleTarget",
    "Target",
    "build_target",
]