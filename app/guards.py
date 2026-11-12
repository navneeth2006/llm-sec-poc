"""Shared detection / sanitising helpers used by the mitigations."""
import base64
import binascii
import re

ZW_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
TAG_RE = re.compile(r"<[^>]+>")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

INJECTION_RE = re.compile(
    r"(ignore\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous\s+|prior\s+|above\s+)*(?:instructions|rules)"
    r"|disregard|system\s+(?:notice|note|override|message)|new\s+(?:instructions|objective)"
    r"|you\s+are\s+now|developer\s+mode|debug\s+mode|reveal|print\s+(?:the\s+)?(?:internal|system)"
    r"|discount\s+code|api[_\s-]?key|instead\s+of|<important>|note\s+to\s+assistant"
    r"|remember\s+permanently|(?:send|email|forward)\b.{0,100}?@)", re.I | re.S)

MEM_INSTR_RE = re.compile(
    r"(from now on|always|never|ignore|every reply|must be|include the contents|/secrets|override)", re.I)

DLP = [
    (re.compile(r"sk-[A-Za-z0-9-]{6,}"), "[REDACTED_KEY]"),
    (re.compile(r"STAFF-\d+-\w+"), "[REDACTED_CODE]"),
    (re.compile(r"ID-\d{4}-\d{4}-\d{4}"), "[REDACTED_ID]"),
    (re.compile(r"GLOBEX-[A-Z0-9-]+"), "[REDACTED]"),
    (re.compile(r"AKIA-[A-Z0-9-]+"), "[REDACTED]"),
    (re.compile(r"[\w.+-]+@(?!corp\.test)[\w-]+(?:\.[\w-]+)+"), "[REDACTED_EMAIL]"),
]


def dlp_redact(text: str) -> str:
    for rx, rep in DLP:
        text = rx.sub(rep, text)
    return text


def decode_b64(text: str):
    out = []
    for blob in re.findall(r"[A-Za-z0-9+/=]{16,}", text):
        try:
            out.append(base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            pass
    return out


def injection_scan(text: str) -> bool:
    return bool(INJECTION_RE.search(text))


def input_filter(text: str):
    """LLM01 input filter. Also scans base64-decoded payloads."""
    for cand in [text] + decode_b64(text):
        m = INJECTION_RE.search(cand)
        if m:
            return True, m.group(0)[:40]
    return False, ""


def sanitize_doc(text: str) -> str:
    """LLM08 ingestion sanitiser: strip hidden/invisible content."""
    text = COMMENT_RE.sub("", text)
    text = ZW_RE.sub("", text)
    return TAG_RE.sub("", text)


def external_addresses(text: str):
    return [e for e in EMAIL_RE.findall(text) if not e.lower().endswith("@corp.test")]


def validate_note(note: str) -> bool:
    """ASI06: memory entries may not hold external addresses or instruction-like text."""
    return not (external_addresses(note) or MEM_INSTR_RE.search(note) or INJECTION_RE.search(note))
