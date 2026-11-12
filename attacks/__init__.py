from .llm_risks import ATTACKS as _L
from .agentic_risks import ATTACKS as _A
from .mcp_risks import ATTACKS as _M

ALL_ATTACKS = _L + _A + _M
