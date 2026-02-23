from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class AIProviderRequest:
    model: str
    prompt: str


@dataclass(frozen=True)
class AIProviderResponse:
    text: str


class AIProviderError(RuntimeError):
    pass


class AIProvider(Protocol):
    def generate(self, request: AIProviderRequest) -> AIProviderResponse:
        ...
