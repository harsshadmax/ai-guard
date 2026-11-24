"""MCP stdio proxy: put the guard between an MCP client (Claude Desktop, Claude Code, an IDE) and any MCP server.

    shadowguard mcp --role mcp-agent -- python -m some_mcp_server

The proxy forwards JSON-RPC messages unchanged, except:
  * tools/list responses: every tool is pinned (description + schema hash); rug pulls, poisoned descriptions
    and shadowed names are flagged and the tool is quarantined;
  * tools/call requests: decided by the guard first; BLOCK / ASK return an MCP error result to the client and
    the upstream server never sees the call;
  * tools/call responses: the result text is registered as untrusted content (taint), scanned for injection,
    and secrets are redacted before the model sees them.
Messages are newline-delimited JSON (MCP stdio transport). Logs go to stderr."""
import json
import subprocess
import sys
import threading

from shadowrun import db

from . import engine, provenance, redact, registry
from .detectors import integrity
from .models import ToolCall, ToolSpec


class Proxy:
    def __init__(self, upstream_cmd: list[str], role: str = "analyst", server_name: str | None = None,
                 client_out=None):
        db.init_db()
        self.server = server_name or (upstream_cmd[-1] if upstream_cmd else "mcp")
        self.session = provenance.new_session(role=role, agent_id="mcp-client", guard_on=True,
                                              task=f"MCP session via {self.server}")
        self.proc = subprocess.Popen(upstream_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=sys.stderr, text=True, encoding="utf-8", bufsize=1)
        self.out = client_out or sys.stdout
        self.lock = threading.Lock()
        self.pending: dict = {}   # request id -> ("list", None) | ("call", (call, verdict, spec))

    # ------------------------------------------------------------ plumbing
    def _to_client(self, msg: dict) -> None:
        with self.lock:
            self.out.write(json.dumps(msg) + "\n")
            self.out.flush()

    def _to_upstream(self, msg: dict) -> None:
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _log(self, s: str) -> None:
        sys.stderr.write(f"[shadowguard] {s}\n")

    # ------------------------------------------------------------ client -> upstream
    def handle_client(self, msg: dict) -> None:
        method = msg.get("method")
        if method == "tools/list" and "id" in msg:
            self.pending[msg["id"]] = ("list", None)
        elif method == "tools/call" and "id" in msg:
            p = msg.get("params") or {}
            name, args = p.get("name", ""), p.get("arguments") or {}
            if registry.get(name) is None:  # never listed: register with a guessed class, pin it now
                spec = ToolSpec(name=name, description="", tool_class=registry.guess_class(name), server=self.server)
                registry.register(spec)
            call = ToolCall(session_id=self.session.id, tool=name, args=args)
            self.session.call_times.append(call.ts)
            v, spec = engine.check(call, self.session)
            if v.decision != "ALLOW":
                if v.decision == "ASK":
                    from . import approvals
                    v.approval_id = approvals.create(call, self.session, v)
                engine._record(call, self.session, v)
                self._log(f"{v.decision} {name}: {v.explanation}")
                self._to_client({"jsonrpc": "2.0", "id": msg["id"], "result": {
                    "isError": True, "content": [{"type": "text", "text": f"[Shadow-Run guard] {v.explanation}"}]}})
                return
            self.pending[msg["id"]] = ("call", (call, v, spec))
        self._to_upstream(msg)

    # ------------------------------------------------------------ upstream -> client
    def handle_upstream(self, msg: dict) -> None:
        kind, ctx = self.pending.pop(msg.get("id"), (None, None)) if "id" in msg else (None, None)
        if kind == "list" and isinstance(msg.get("result"), dict):
            for t in msg["result"].get("tools", []):
                spec = ToolSpec(name=t.get("name", ""), description=t.get("description") or "",
                                tool_class=registry.guess_class(t.get("name", ""), t.get("description") or ""),
                                server=self.server, input_schema=t.get("inputSchema") or {})
                registry.register(spec)
                fs = integrity.observe(spec)
                if fs:
                    self._log(f"tool {spec.name}: {', '.join(f.rule_id for f in fs)}")
        elif kind == "call":
            call, v, spec = ctx
            v.executed = True
            res = msg.get("result") or {}
            texts = [c.get("text", "") for c in res.get("content", []) if isinstance(c, dict) and c.get("type") == "text"]
            engine.after_result(call, self.session, spec, v, {"content": "\n".join(texts)})
            if v.redactions:
                for c in res.get("content", []):
                    if isinstance(c, dict) and c.get("type") == "text":
                        c["text"], _ = redact.redact_text(c["text"], entropy=False)
            engine._record(call, self.session, v)
        self._to_client(msg)

    def pump_upstream(self) -> None:
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.handle_upstream(json.loads(line))
            except ValueError:
                self._log(f"non-JSON from upstream dropped: {line[:80]}")

    def serve(self, client_in=None) -> int:
        t = threading.Thread(target=self.pump_upstream, daemon=True)
        t.start()
        for line in client_in or sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            try:
                self.handle_client(msg)
            except Exception as e:  # fail closed for calls, keep the session alive
                self._log(f"guard error: {e}")
                if msg.get("method") == "tools/call" and "id" in msg:
                    self._to_client({"jsonrpc": "2.0", "id": msg["id"], "result": {
                        "isError": True, "content": [{"type": "text", "text": "[Shadow-Run guard] blocked: guard error"}]}})
        self.proc.stdin.close()
        self.proc.wait(timeout=5)
        t.join(timeout=2)
        return 0


def run_proxy(upstream_cmd: list[str], role: str = "mcp-agent") -> int:
    return Proxy(upstream_cmd, role=role).serve()
