from dataclasses import dataclass

ALL_RISKS = ["LLM01", "LLM02", "LLM03", "LLM08", "LLM10",
             "ASI01", "ASI02", "ASI03", "ASI05", "ASI06", "MCP"]


@dataclass(frozen=True)
class Settings:
    """Which mitigations are switched on. Empty = baseline (vulnerable)."""
    on_set: frozenset = frozenset()

    def on(self, risk: str) -> bool:
        return risk in self.on_set

    @staticmethod
    def only(risk: str) -> "Settings":
        return Settings(frozenset([risk]))
