"""One interface, two real providers (Claude, Gemini) plus an offline mock for pipeline tests."""
import os
import time
import uuid

from .types import LLMResponse, ToolCall


def _retry(fn, tries=4):
    for i in range(tries):
        try:
            return fn()
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(2 ** i)


class ClaudeProvider:
    name = "claude"

    def __init__(self, model=None):
        import anthropic
        self.client = anthropic.Anthropic()          # reads ANTHROPIC_API_KEY
        self.model = model or os.getenv("CLAUDE_MODEL", "claude-haiku-5-5")

    def _convert(self, messages):
        out = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                blocks = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls", []):
                    blocks.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.args})
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": "(no output)"}]})
            elif m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"] or "(empty)"}
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out

    def chat(self, system, messages, tools=None, max_tokens=1024):
        kw = dict(model=self.model, max_tokens=max_tokens, system=system, messages=self._convert(messages))
        if tools:
            kw["tools"] = [{"name": t["name"], "description": t["description"],
                            "input_schema": t["parameters"]} for t in tools]
        r = _retry(lambda: self.client.messages.create(**kw))
        text = "".join(b.text for b in r.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input)) for b in r.content if b.type == "tool_use"]
        if not text and not calls and getattr(r, "stop_reason", "") == "refusal":
            text = "[provider refusal]"
        return LLMResponse(text, calls, r.usage.input_tokens, r.usage.output_tokens, raw=None)


class GeminiProvider:
    name = "gemini"

    def __init__(self, model=None):
        from google import genai
        self.client = genai.Client(api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    def _convert(self, messages):
        from google.genai import types
        out = []
        for m in messages:
            if m["role"] == "user":
                out.append(types.Content(role="user", parts=[types.Part(text=m["content"])]))
            elif m["role"] == "assistant":
                if m.get("raw") is not None:          # keep thought signatures intact
                    out.append(m["raw"])
                    continue
                parts = []
                if m.get("content"):
                    parts.append(types.Part(text=m["content"]))
                for tc in m.get("tool_calls", []):
                    parts.append(types.Part.from_function_call(name=tc.name, args=tc.args))
                out.append(types.Content(role="model", parts=parts or [types.Part(text="(no output)")]))
            elif m["role"] == "tool":
                part = types.Part.from_function_response(name=m["name"], response={"result": m["content"]})
                last = out[-1] if out else None
                if last is not None and last.role == "user" and last.parts and last.parts[0].function_response is not None:
                    last.parts.append(part)
                else:
                    out.append(types.Content(role="user", parts=[part]))
        return out

    def chat(self, system, messages, tools=None, max_tokens=1024):
        from google.genai import types
        cfg = types.GenerateContentConfig(
            system_instruction=system, max_output_tokens=max_tokens,
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True))
        if tools:
            cfg.tools = [types.Tool(function_declarations=[
                types.FunctionDeclaration(name=t["name"], description=t["description"], parameters=t["parameters"])
                for t in tools])]
        r = _retry(lambda: self.client.models.generate_content(
            model=self.model, contents=self._convert(messages), config=cfg))
        cand = r.candidates[0] if r.candidates else None
        parts = (cand.content.parts or []) if cand is not None and cand.content else []
        text = "".join(p.text for p in parts if getattr(p, "text", None) and not getattr(p, "thought", False))
        calls = [ToolCall("g" + uuid.uuid4().hex[:8], p.function_call.name, dict(p.function_call.args or {}))
                 for p in parts if getattr(p, "function_call", None)]
        if not parts:
            text = "[no output / provider safety filter]"
        um = r.usage_metadata
        return LLMResponse(text, calls, getattr(um, "prompt_token_count", 0) or 0,
                           getattr(um, "candidates_token_count", 0) or 0,
                           raw=cand.content if (calls and cand is not None) else None)


def get_provider(name):
    if name == "claude":
        return ClaudeProvider()
    if name == "gemini":
        return GeminiProvider()
    if name == "mock":
        from .mock_provider import MockProvider
        return MockProvider()
    raise ValueError(f"unknown model '{name}' (use claude | gemini | mock)")
