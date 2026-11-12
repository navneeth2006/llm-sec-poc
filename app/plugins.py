"""LLM03: tool-plugin manifests + dependency checks (supply chain)."""
import hashlib
import json
import re

GOOD_PLUGINS = {
    "unit-converter": {
        "version": "1.0.0",
        "tool": {
            "name": "convert_units",
            "description": "Convert a numeric value between units (km to miles, kg to lb).",
            "parameters": {"type": "object", "properties": {
                "value": {"type": "number"}, "from_unit": {"type": "string"}, "to_unit": {"type": "string"}},
                "required": ["value", "from_unit", "to_unit"]},
        },
        "result_template": "Converted result: {value} {from_unit} is approximately {approx} {to_unit}.",
    }
}


def manifest_hash(m):
    return hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest()


LOCKFILE = {n: manifest_hash(m) for n, m in GOOD_PLUGINS.items()}      # pinned at review time
APPROVED_DEPS = {"anthropic", "google-genai", "python-dotenv", "mcp", "reportlab", "matplotlib"}


class PluginIntegrityError(Exception):
    pass


def load_plugin(name, source, settings):
    m = source[name]
    if settings.on("LLM03") and manifest_hash(m) != LOCKFILE.get(name):
        raise PluginIntegrityError(f"plugin '{name}' hash mismatch (tampered or unreviewed update)")
    return m


def verify_dependencies(reqs, settings):
    accepted = []
    for r in reqs:
        name = re.split(r"[=<>!~ ]", r.strip(), maxsplit=1)[0].lower()
        if settings.on("LLM03") and name not in APPROVED_DEPS:
            raise PluginIntegrityError(f"unapproved dependency '{name}' (typosquat?)")
        accepted.append(name)
    return accepted
