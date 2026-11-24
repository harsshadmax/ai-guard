import pytest

from shadowrun import config, db


@pytest.fixture
def gw(tmp_path, monkeypatch):
    """Isolated guard world: temp DB, workspace, sink and fresh in-memory state."""
    from guard import approvals, registry
    from guard.detectors import integrity
    from guard.models import STORE

    monkeypatch.setattr(config, "DB_PATH", tmp_path / "g.db")
    monkeypatch.setattr(config, "GUARD_DIR", tmp_path / "guard")
    monkeypatch.setattr(config, "GUARD_ROOT", tmp_path / "guard" / "workspace")
    monkeypatch.setattr(config, "GUARD_SINK_LOG", tmp_path / "guard" / "sink.jsonl")
    db.init_db()
    STORE.sessions.clear()
    approvals.PENDING.clear()
    integrity.reset_cache()
    registry.EXTRA.clear()
    canaries = registry.reset_workspace()
    yield canaries
    integrity.reset_cache()
    registry.EXTRA.clear()


@pytest.fixture
def session(gw):
    from guard import provenance
    return lambda role="analyst", guard_on=True: provenance.new_session(role=role, guard_on=guard_on, task="test")


@pytest.fixture
def call(gw):
    from guard import engine
    from guard.models import ToolCall
    return lambda s, tool, **args: engine.guard(ToolCall(session_id=s.id, tool=tool, args=args), s)
