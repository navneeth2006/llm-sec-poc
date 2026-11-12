import re
from .guards import injection_scan, sanitize_doc

STOP = {"the", "a", "an", "is", "are", "what", "of", "to", "and", "for", "in", "on", "me", "my", "your",
        "how", "do", "does", "i", "you", "it", "about", "tell", "show", "please", "with", "can", "give"}


def toks(s):
    return [w for w in re.findall(r"[a-z0-9]+", s.lower()) if w not in STOP]


class KnowledgeBase:
    """Toy retriever: keyword overlap stands in for embedding similarity.
    The attack surface (poisoned docs, missing ACLs) is identical to a real vector DB."""

    def __init__(self, docs):
        self.docs = [dict(d) for d in docs]
        self.quarantined = []

    def ingest(self, doc, settings):
        doc = dict(doc)
        if settings.on("LLM08"):
            if doc.get("source") != "internal":
                self.quarantined.append((doc["id"], "untrusted source"))
                return False
            doc["text"] = sanitize_doc(doc["text"])
            if injection_scan(doc["text"]):
                self.quarantined.append((doc["id"], "injection pattern"))
                return False
        self.docs.append(doc)
        return True

    def retrieve(self, query, user, settings, k=3):
        q = set(toks(query))
        scored = []
        for d in self.docs:
            if settings.on("LLM08") and d["tenant"] not in ("public", user.tenant):
                continue
            s = len(q & set(toks(d["title"] + " " + d["text"])))
            if s:
                scored.append((s, d))
        scored.sort(key=lambda x: -x[0])
        return [d for _, d in scored[:k]]
