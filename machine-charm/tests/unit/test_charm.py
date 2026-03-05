# Copyright 2026 Samuel Olwe
# See LICENSE file for licensing details.

"""Unit tests for the MachineCharmCharm."""

from unittest.mock import MagicMock

import pytest
from ops import testing

from charm import MachineCharmCharm


def _db_relation(*, uris: str = "postgresql://host:5432/db") -> testing.Relation:
    """Return a Relation pre-populated with database credentials."""
    return testing.Relation(
        endpoint="postgresql",
        interface="postgresql_client",
        remote_app_data={
            "username": "user",
            "password": "pass",
            "endpoints": "host:5432",
            "database": "postgresql",
            "uris": uris,
        },
    )


def _full_config() -> dict:
    """Return a config dict with all required options set."""
    return {
        "oauth-token-salt": "test-salt-value",
        "secret_key": "test-secret-key",
        "workers": "2",
        "timeout": "15",
    }


@pytest.fixture(autouse=True)
def mock_workload(monkeypatch: pytest.MonkeyPatch):
    """Patch all workload functions used by the charm."""
    monkeypatch.setattr("charm.workload.install", lambda *a, **kw: None)
    monkeypatch.setattr("charm.workload.migrate", lambda *a, **kw: None)
    monkeypatch.setattr("charm.workload.start", lambda *a, **kw: None)
    monkeypatch.setattr("charm.workload.is_running", lambda: True)


class TestInstallEvent:
    """Tests for the _on_install handler."""

    def test_install_no_database_sets_blocked(self):
        """Without a database relation, install sets BlockedStatus."""
        ctx = testing.Context(MachineCharmCharm)
        state_in = testing.State()

        state_out = ctx.run(ctx.on.install(), state_in)

        assert state_out.unit_status == testing.BlockedStatus("waiting for database relation")

    def test_install_calls_workload_install(self, monkeypatch: pytest.MonkeyPatch):
        """Verify workload.install is called during the install event."""
        install_called = False

        def fake_install(charm_dir):
            nonlocal install_called
            install_called = True

        monkeypatch.setattr("charm.workload.install", fake_install)

        ctx = testing.Context(MachineCharmCharm)
        state_in = testing.State()

        ctx.run(ctx.on.install(), state_in)
        assert install_called


class TestStartEvent:
    """Tests for the _on_start / _start handler."""

    def test_start_without_database_sets_blocked(self):
        """Start without a database relation should set BlockedStatus."""
        ctx = testing.Context(MachineCharmCharm)
        state_in = testing.State()

        state_out = ctx.run(ctx.on.start(), state_in)

        assert state_out.unit_status == testing.BlockedStatus("waiting for database relation")

    def test_start_not_running_sets_blocked(self, monkeypatch: pytest.MonkeyPatch):
        """When workload fails to start, status should be BlockedStatus."""
        monkeypatch.setattr("charm.workload.is_running", lambda: False)

        ctx = testing.Context(MachineCharmCharm)
        state_in = testing.State()

        state_out = ctx.run(ctx.on.start(), state_in)

        assert isinstance(state_out.unit_status, testing.BlockedStatus)


class TestStopEvent:
    """Tests for the _on_stop handler."""

    def test_stop_sets_maintenance_status(self, monkeypatch: pytest.MonkeyPatch):
        """Stop event should transition through MaintenanceStatus."""
        monkeypatch.setattr("charm.workload.stop_gunicorn", lambda: None)

        ctx = testing.Context(MachineCharmCharm)
        state_in = testing.State()

        state_out = ctx.run(ctx.on.stop(), state_in)

        assert state_out.unit_status == testing.MaintenanceStatus("stopping workload")


class TestConfigChangedEvent:
    """Tests for the _on_config_changed handler."""

    def test_config_changed_without_database_sets_blocked(self, monkeypatch: pytest.MonkeyPatch):
        """Config changed without DB relation should end up blocked."""

        monkeypatch.setattr("charm.workload.start", lambda: None)
        monkeypatch.setattr("charm.workload.stop_gunicorn", lambda: None)

        ctx = testing.Context(MachineCharmCharm)
        state_in = testing.State()

        state_out = ctx.run(ctx.on.config_changed(), state_in)

        assert isinstance(state_out.unit_status, testing.BlockedStatus)


class TestGetWriteableUri:
    """Tests for the _get_writeable_uri static method."""

    def test_single_uri(self):
        """With a single URI, it should be returned as-is."""
        event = MagicMock()
        event.uris = "postgresql://primary:5432/db"
        event.read_only_uris = None

        result = MachineCharmCharm._get_writeable_uri(event)

        assert result == "postgresql://primary:5432/db"

    def test_multiple_uris_filters_readonly(self):
        """With multiple URIs and read-only URIs, return only the writeable one."""
        event = MagicMock()
        event.uris = "postgresql://primary:5432/db,postgresql://replica:5432/db"
        event.read_only_uris = "postgresql://replica:5432/db"

        result = MachineCharmCharm._get_writeable_uri(event)

        assert result == "postgresql://primary:5432/db"

    def test_no_uris_raises(self):
        """With no URIs, a RuntimeError should be raised."""
        event = MagicMock()
        event.uris = ""

        with pytest.raises(RuntimeError, match="No database URIs"):
            MachineCharmCharm._get_writeable_uri(event)

    def test_no_uris_none_raises(self):
        """With None URIs, a RuntimeError should be raised."""
        event = MagicMock()
        event.uris = None

        with pytest.raises(RuntimeError, match="No database URIs"):
            MachineCharmCharm._get_writeable_uri(event)

    def test_multiple_uris_no_readonly(self):
        """With multiple URIs but no read-only info, return the full uris string."""
        event = MagicMock()
        event.uris = "postgresql://a:5432/db,postgresql://b:5432/db"
        event.read_only_uris = ""

        result = MachineCharmCharm._get_writeable_uri(event)

        assert result == "postgresql://a:5432/db,postgresql://b:5432/db"
