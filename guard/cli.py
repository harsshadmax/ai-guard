"""shadowguard: command line for the AI tool guard (no Docker needed).

  shadowguard demo [--scenario hidden-text|all] [--mode both|on|off]
  shadowguard serve [--port 8000]
  shadowguard eval
  shadowguard doctor
  shadowguard policy lint [PATH]
  shadowguard verify-audit
  shadowguard mcp -- <upstream MCP server command...>
"""
import argparse
import json
import sys

from shadowrun import audit, config, db, policy

from . import registry, scenarios


def _print(s: str) -> None:
    try:
        print(s)
    except UnicodeEncodeError:  # old Windows consoles
        print(s.encode("ascii", "replace").decode())


def cmd_demo(a) -> int:
    db.init_db()
    names = list(scenarios.SCENARIOS) if a.scenario == "all" else [a.scenario]
    modes = {"both": [False, True], "on": [True], "off": [False]}[a.mode]
    summary = []
    for name in names:
        _print(f"\n=== {name}: {scenarios.SCENARIOS[name]['title']} ===")
        for on in modes:
            registry.reset_workspace()
            _print(f"\n--- guard {'ON' if on else 'OFF'} ---")
            r = scenarios.run(name, on, log=_print)
            verdict = (f"LEAKED via {', '.join(r['leak_channels'])}" if r["leaked"] else
                       "HARMED: an injected action ran" if r["harmed"] else "safe: no injected action ran")
            _print(f"RESULT: {verdict}")
            summary.append((name, on, "LEAKED" if r["leaked"] else "HARMED" if r["harmed"] else "safe",
                            [t["decision"] for t in r["transcript"]]))
    if len(summary) > 2:
        _print("\nSummary")
        for name, on, outcome, ds in summary:
            _print(f"  {name:16} guard {'ON ' if on else 'OFF'}  {outcome:6}  {' '.join(ds)}")
    res = audit.verify()
    _print(f"\nAudit chain: {'intact' if res['ok'] else 'BROKEN at row ' + str(res['broken_id'])} ({res['checked']} entries)")
    return 0


def cmd_doctor(_a) -> int:
    from .doctor import run_guard_checks
    ok = True
    for c in run_guard_checks():
        ok &= c["ok"]
        _print(f"[{'PASS' if c['ok'] else 'FAIL'}] {c['name']}: {c['detail']}")
    _print("GUARD DOCTOR: " + ("ALL PASS" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="shadowguard", description="Live security guard for AI assistants and tools")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="run attack scenarios without and with the guard")
    d.add_argument("--scenario", default="hidden-text", choices=["all", *scenarios.SCENARIOS])
    d.add_argument("--mode", default="both", choices=["both", "on", "off"])
    s = sub.add_parser("serve", help="start the dashboard and the HTTP proxy on 127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    sub.add_parser("eval", help="run the guard benchmark")
    sub.add_parser("doctor", help="self-test of the guard (no Docker needed)")
    pl = sub.add_parser("policy")
    pl_sub = pl.add_subparsers(dest="pcmd", required=True)
    lint = pl_sub.add_parser("lint")
    lint.add_argument("path", nargs="?", default=str(config.GUARD_POLICY))
    sub.add_parser("verify-audit")
    m = sub.add_parser("mcp", help="run as an MCP stdio proxy in front of an upstream MCP server")
    m.add_argument("--role", default="mcp-agent")
    m.add_argument("upstream", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)

    if a.cmd == "demo":
        return cmd_demo(a)
    if a.cmd == "serve":
        import uvicorn
        db.init_db()
        if not config.GUARD_ROOT.exists():
            registry.reset_workspace()
        _print(f"Shadow-Run AI tool guard: http://127.0.0.1:{a.port}/guard")
        uvicorn.run("shadowrun.api:app", host="127.0.0.1", port=a.port, log_level="warning")
        return 0
    if a.cmd == "eval":
        from eval_guard.run_eval import main as eval_main
        return eval_main()
    if a.cmd == "doctor":
        return cmd_doctor(a)
    if a.cmd == "policy":
        from pathlib import Path
        probs = policy.lint_policy(Path(a.path))
        _print("policy OK" if not probs else "\n".join(f"problem: {x}" for x in probs))
        return 0 if not probs else 1
    if a.cmd == "verify-audit":
        db.init_db()
        res = audit.verify()
        _print(json.dumps(res))
        return 0 if res["ok"] else 1
    if a.cmd == "mcp":
        from .proxy_mcp import run_proxy
        cmd = [x for x in a.upstream if x != "--"]
        if not cmd:
            p.error("give the upstream MCP server command after --")
        return run_proxy(cmd, role=a.role)
    return 1


if __name__ == "__main__":
    sys.exit(main())
