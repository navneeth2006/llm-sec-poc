from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    raw: Any = None


@dataclass
class User:
    name: str
    role: str = "intern"      # intern | admin | customer
    tenant: str = "acme"
