"""Shadow-Run AI tool guard (PS-CYB-02): inspects every tool call an AI assistant makes, before it runs.

Pipeline (guard.engine): normalise -> provenance/taint -> detectors -> RBAC -> policy.decide_call ->
approval (ASK) -> execute (ALLOW) -> scan + redact result -> hash-chained audit.
Detectors only produce scored findings; the deterministic policy decides. Everything fails closed.
All tools, secrets and attacks in this package are simulated.
"""
