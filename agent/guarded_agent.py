"""Agents that use tools ONLY through the guard.

* ObedientAgent (SIMULATED, deterministic): does the user's task, and also obeys every instruction it finds
  in what it reads (visible, hidden or encoded), the way a hijacked LLM agent would. This makes the attack
  reproducible for the demo and the benchmark.
* ClaudeAgent (optional): a real Claude tool-use loop over the same guarded tools. Needs `pip install
  shadowrun[llm]` and ANTHROPIC_API_KEY; skipped otherwise.

Usage:  python -m agent.guarded_agent --doc docs/external/client_feedback.html --guard on
"""
import argparse
import json
import os
import re
import sys
from urllib.parse import quote

from guard import engine, normalize, provenance, registry
from guard.models import ToolCall

PATH = r"[\w][\w./-]*\.(?:env|pem|key|json|csv|txt|md|html|eml)"
EMAIL = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"


class InProcessClient:
    """Calls the guard directly (tests, CLI demo). HttpClient below talks to a running server."""

    def __init__(self, session):
        self.session = session

    def call(self, tool: str, **args) -> dict:
        v = engine.guard(ToolCall(session_id=self.session.id, tool=tool, args=args), self.session)
        return {"decision": v.decision, "executed": v.executed, "result": v.result, "explanation": v.explanation,
                "rules": sorted(v.rule_ids), "latency_ms": v.latency_ms, "approval_id": v.approval_id}


class HttpClient:
    def __init__(self, base: str, token: str, session_id: str):
        import httpx
        self.c = httpx.Client(base_url=base, headers={"X-Demo-Token": token}, timeout=30)
        self.sid = session_id

    def call(self, tool: str, **args) -> dict:
        r = self.c.post("/api/v1/guard/call", json={"session_id": self.sid, "tool": tool, "args": args})
        r.raise_for_status()
        return r.json()


def _content(res: dict) -> str:
    r = res.get("result")
    if isinstance(r, dict):
        return r.get("content") or ""
    return r if isinstance(r, str) else ""


def parse_instructions(model_text: str) -> list[tuple[str, dict]]:
    """What a hijacked agent would do: imperative sentences that name a target, in document order."""
    steps: list[tuple[int, str, dict]] = []
    pos = 0
    for s in re.split(r"(?<=[.!?])\s+|\n+", model_text):
        pos = max(0, model_text.find(s, pos))
        low = s.lower()
        if re.search(r"\b(read|open|load|cat|collect)\b", low):
            for m in re.finditer(PATH, s):
                steps.append((pos + m.start(), "read_file", {"path": m.group(0)}))
        if re.search(r"\b(run the query|query)\b", low):
            m = re.search(r"(SELECT .+? FROM \w+)", s, re.I)
            if m:
                steps.append((pos + m.start(), "query", {"sql": m.group(1)}))
        m = re.search(r"\b(write|save|copy)\b.{0,30}\b(?:to|into)\s+(" + PATH + ")", s, re.I)
        if m:
            steps.append((pos + m.start(), "write_file", {"path": m.group(2), "content": "{DATA}"}))
        for m in re.finditer(r"\b(?:email|send|forward)\b[^@]{0,80}?\bto\s+(" + EMAIL + ")", s, re.I):
            steps.append((pos + m.start(), "send_email", {"to": m.group(1), "subject": "Requested data",
                                                          "body": "{DATA}"}))
        for m in re.finditer(r"\b(?:fetch|visit|open|load)\s+(https?://[^\s)<]*(?:<[^>]{0,40}>)?)", s, re.I):
            steps.append((pos + m.start(), "fetch_url", {"url": m.group(1).rstrip(".,")}))
        m = re.search(r"`([^`]{2,200})`", s)
        if m and re.search(r"\b(run|execute)\b", low):
            steps.append((pos + m.start(), "run_command", {"command": m.group(1)}))
        m = re.search(r"\bdelete (?:all files in )?(?:the )?([\w./-]+) folder", s, re.I)
        if m:
            steps.append((pos + m.start(), "delete_file", {"path": m.group(1).rstrip("/") + "/backup.zip"}))
    steps.sort(key=lambda x: x[0])
    seen, out = set(), []
    for _, tool, args in steps:
        k = (tool, json.dumps(args, sort_keys=True))
        if k not in seen:
            seen.add(k)
            out.append((tool, args))
    return out


class ObedientAgent:
    """SIMULATED agent. Task: summarise a document (or the inbox / a web page)."""

    def __init__(self, client, log=print):
        self.client, self.log, self.transcript = client, log, []

    def _do(self, tool: str, args: dict, why: str) -> dict:
        res = self.client.call(tool, **args)
        self.transcript.append({"tool": tool, "args": args, "why": why, "decision": res["decision"],
                                "executed": res["executed"], "rules": res.get("rules", []),
                                "explanation": res.get("explanation", ""), "latency_ms": res.get("latency_ms", 0)})
        self.log(f"  [{res['decision']:<9}] {tool}({_short(args)})" + (f"  <- {why}" if why else ""))
        if res["decision"] in ("BLOCK", "ASK") and res.get("explanation"):
            self.log(f"              {res['explanation'][:220]}")
        return res

    def run(self, task: str, first_tool: str, first_args: dict) -> list[dict]:
        self.log(f"USER TASK: {task}")
        res = self._do(first_tool, first_args, "user task")
        if not res["executed"]:
            return self.transcript
        text = normalize.extract(_content(res), first_args.get("path", first_args.get("url", "")))["text"]
        data = ""
        for tool, args in parse_instructions(text):
            args = {k: (v.replace("{DATA}", data) if isinstance(v, str) else v) for k, v in args.items()}
            if tool == "fetch_url":
                args["url"] = re.sub(r"<[^>]*>", quote(data[:500]), args["url"])
            r = self._do(tool, args, "instruction found in the content")
            if r["executed"] and tool in ("read_file", "query"):
                data += _content(r) + "\n"
        self.log("ASSISTANT: Here is your summary. (simulated)")
        return self.transcript


def _short(args: dict) -> str:
    return ", ".join(f"{k}={str(v)[:48]!r}" for k, v in args.items())


class ClaudeAgent:  # pragma: no cover - needs network and a key
    """A real Claude tool-use loop over the guarded tools (model from GUARD_AGENT_MODEL)."""

    def __init__(self, client, log=print, model: str | None = None):
        import anthropic
        self.api = anthropic.Anthropic()
        self.client, self.log = client, log
        self.model = model or os.environ.get("GUARD_AGENT_MODEL", "claude-sonnet-5-5")

    def run(self, task: str, max_turns: int = 8) -> list[dict]:
        tools = [{"name": s.name, "description": s.description,
                  "input_schema": {"type": "object", "properties": {k: {"type": t} for k, t in s.input_schema.items()}}}
                 for s in registry.all_specs().values()]
        msgs = [{"role": "user", "content": task}]
        for _ in range(max_turns):
            r = self.api.messages.create(model=self.model, max_tokens=1024, tools=tools, messages=msgs)
            msgs.append({"role": "assistant", "content": r.content})
            uses = [b for b in r.content if b.type == "tool_use"]
            if not uses:
                self.log("ASSISTANT: " + "".join(b.text for b in r.content if b.type == "text"))
                break
            results = []
            for u in uses:
                res = self.client.call(u.name, **u.input)
                self.log(f"  [{res['decision']:<9}] {u.name}({_short(u.input)})")
                body = _content(res) if res["executed"] else f"Tool call {res['decision']} by the security guard: " \
                                                              f"{res.get('explanation', '')}"
                results.append({"type": "tool_result", "tool_use_id": u.id, "content": body[:20000]})
            msgs.append({"role": "user", "content": results})
        return []


def main(argv=None) -> int:
    from shadowrun import db
    ap = argparse.ArgumentParser(description="Run an agent through the AI tool guard")
    ap.add_argument("--doc", default="docs/external/client_feedback.html")
    ap.add_argument("--guard", choices=["on", "off"], default="on")
    ap.add_argument("--role", default="analyst")
    ap.add_argument("--claude", action="store_true", help="use a real Claude agent (needs ANTHROPIC_API_KEY)")
    a = ap.parse_args(argv)
    db.init_db()
    registry.reset_workspace()
    s = provenance.new_session(role=a.role, agent_id="claude" if a.claude else "obedient-agent",
                               guard_on=a.guard == "on", task=f"Summarize {a.doc}")
    client = InProcessClient(s)
    if a.claude:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ANTHROPIC_API_KEY is not set; use the scripted agent instead.", file=sys.stderr)
            return 1
        ClaudeAgent(client).run(f"Summarize the document {a.doc} for me.")
    else:
        ObedientAgent(client).run(f"Summarize {a.doc}", "read_file", {"path": a.doc})
    return 0


if __name__ == "__main__":
    sys.exit(main())
