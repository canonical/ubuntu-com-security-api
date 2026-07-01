# Copyright 2026 Samuel Olwe
# See LICENSE file for licensing details.

"""Unit tests for the workload module."""

import os
import subprocess
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

import workload


class TestRunCommand:
    """Tests for the run_command function."""

    @patch("workload.subprocess.run")
    def test_run_command_success(self, mock_run):
        """A successful command should complete without error."""
        mock_run.return_value = MagicMock(returncode=0)

        workload.run_command("echo", "hello")

        mock_run.assert_called_once_with(
            ("echo", "hello"),
            check=True,
            text=True,
            cwd=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    @patch("workload.subprocess.run", side_effect=subprocess.CalledProcessError(1, "fail"))
    def test_run_command_raises_runtime_error_on_failure(self, mock_run):
        """run_command should raise RuntimeError when the subprocess fails."""
        with pytest.raises(RuntimeError):
            workload.run_command("fail")


class TestIsRunning:
    """Tests for the is_running function."""

    @patch("workload.subprocess.run")
    def test_is_running_returns_true_when_active(self, mock_run):
        """is_running should return True when systemctl reports 'active'."""
        mock_run.return_value = MagicMock(stdout="active\n")

        assert workload.is_running() is True

    @patch("workload.subprocess.run")
    def test_is_running_returns_false_when_inactive(self, mock_run):
        """is_running should return False when systemctl reports 'inactive'."""
        mock_run.return_value = MagicMock(stdout="inactive\n")

        assert workload.is_running() is False

    @patch("workload.subprocess.run")
    def test_is_running_returns_false_when_failed(self, mock_run):
        """is_running should return False when systemctl reports 'failed'."""
        mock_run.return_value = MagicMock(stdout="failed\n")

        assert workload.is_running() is False


class TestInstallSystemdService:
    """Tests for the install_systemd_service function."""

    @patch("workload.run_command")
    @patch("builtins.open", mock_open())
    @patch("workload.os.path.exists", return_value=False)
    def test_creates_systemd_unit_file(self, mock_exists, mock_run_cmd):
        """install_systemd_service should write the gunicorn.service unit file."""
        workload.install_systemd_service(
            "/charm", "4", "60", "secret", "salt", "postgresql://host/db"
        )

        # open is called twice: once for gunicorn log, once for service file
        handle = open()
        handle.write.assert_called_once()
        written = handle.write.call_args.args[0]
        assert "gunicorn" in written.lower() or "Gunicorn" in written


class TestStart:
    """Tests for the start function."""

    @patch("workload.is_running", return_value=True)
    @patch("workload.time.sleep")
    @patch("workload.start_gunicorn")
    @patch("workload.stop_gunicorn")
    @patch("workload.install_systemd_service")
    def test_start_stops_then_starts_gunicorn(
        self, mock_install_svc, mock_stop, mock_start_g, mock_sleep, mock_running
    ):
        """start should stop gunicorn then start it again."""
        workload.start("/charm", "4", "60", "secret", "salt", "postgresql://host/db")

        mock_stop.assert_called_once()
        mock_start_g.assert_called_once()

    @patch("workload.is_running", return_value=False)
    @patch("workload.time.sleep")
    @patch("workload.start_gunicorn")
    @patch("workload.stop_gunicorn")
    @patch("workload.install_systemd_service")
    def test_start_raises_if_not_running_after_start(
        self, mock_install_svc, mock_stop, mock_start_g, mock_sleep, mock_running
    ):
        """start should raise RuntimeError if the service is not running after starting."""
        with pytest.raises(RuntimeError, match="Failed to start the workload"):
            workload.start("/charm", "4", "60", "secret", "salt", "postgresql://host/db")


class TestRestoreDatabaseFromFile:
    """Tests for the restore_database_from_file function."""

    @patch("workload.start_gunicorn")
    @patch("workload.os.remove")
    @patch("workload.run_command")
    @patch("workload.os.path.exists", return_value=True)
    def test_restore_creates_backup(self, mock_exists, mock_run_cmd, mock_remove, mock_start):
        """restore_database_from_file should create a backup before restoring."""
        workload.restore_database_from_file("dump.sql", "postgresql://host/db")

        backup_calls = [c for c in mock_run_cmd.call_args_list if "pg_dump" in c.args]
        assert len(backup_calls) == 1
        assert "/tmp/backup_dump.sql" in backup_calls[0].args

    @patch("workload.start_gunicorn")
    @patch("workload.os.remove")
    @patch("workload.run_command")
    @patch("workload.os.path.exists", return_value=True)
    def test_restore_starts_gunicorn_after_success(
        self, mock_exists, mock_run_cmd, mock_remove, mock_start
    ):
        """restore_database_from_file should start gunicorn after a successful restore."""
        workload.restore_database_from_file("dump.sql", "postgresql://host/db")

        mock_start.assert_called_once()

    @patch("workload.start_gunicorn")
    @patch("workload.os.remove")
    @patch("workload.run_command")
    @patch("workload.os.path.exists", return_value=True)
    def test_restore_rolls_back_on_failure(
        self, mock_exists, mock_run_cmd, mock_remove, mock_start
    ):
        """If restore fails, the original database should be restored from the backup."""

        def side_effect(*args, **kwargs):
            # Let terminate, pg_dump, and drop succeed; fail on psql -f (the 4th call)
            if args == ("psql", "postgresql://host/db", "-f", "/tmp/dump.sql"):
                raise RuntimeError("restore failed")

        mock_run_cmd.side_effect = side_effect

        with pytest.raises(RuntimeError, match="Failed to restore the database"):
            workload.restore_database_from_file("dump.sql", "postgresql://host/db")

        # pg_restore should have been called to roll back
        pg_restore_calls = [
            c for c in mock_run_cmd.call_args_list if "pg_restore" in c.args
        ]
        assert len(pg_restore_calls) == 1
        assert "/tmp/backup_dump.sql" in pg_restore_calls[0].args
