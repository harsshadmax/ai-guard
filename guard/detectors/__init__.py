"""Detectors. Each returns list[Finding]; run_all enforces a time budget and fails closed."""
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutTimeout

from shadowrun.models import Finding

_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="guard-det")


def run_all(jobs: dict, budget_ms: int) -> list[Finding]:
    """jobs: name -> zero-arg callable. Cheap detectors run inline; a slow or crashing one becomes a finding."""
    out: list[Finding] = []
    deadline = time.perf_counter() + budget_ms / 1000
    futs = {name: _POOL.submit(fn) for name, fn in jobs.items()}
    for name, fut in futs.items():
        try:
            out += fut.result(timeout=max(0.0, deadline - time.perf_counter()))
        except FutTimeout:
            out.append(Finding(rule_id="GUARD_TIMEOUT", severity="medium", score=1.0, detector=name,
                               message=f"Detector '{name}' exceeded the {budget_ms} ms budget (fail closed)"))
        except Exception as e:
            out.append(Finding(rule_id="GUARD_ERROR", severity="medium", score=1.0, detector=name,
                               message=f"Detector '{name}' failed: {type(e).__name__}: {e} (fail closed)"))
    return out
