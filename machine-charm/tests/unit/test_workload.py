# Copyright 2026 Samuel Olwe
# See LICENSE file for licensing details.

"""Unit tests for the workload module."""

import os
from unittest.mock import patch

import pytest

import workload


class TestInstall:
    """Tests for the install function."""

    @patch("workload.run_command")
    @patch("workload.apt")
    def test_install_calls_apt_update(self, mock_apt, mock_run_cmd):
        """Install should call apt.update first."""
        workload.install("/charm")

        mock_apt.update.assert_called_once()

    @patch("workload.run_command")
    @patch("workload.apt")
    def test_install_adds_required_packages(self, mock_apt, mock_run_cmd):
        """Install should install the three required apt packages."""
        workload.install("/charm")

        assert mock_apt.add_package.call_count == 3
        package_names = [c.args[0] for c in mock_apt.add_package.call_args_list]
        assert "libsodium-dev" in package_names
        assert "python3-venv" in package_names
        assert "postgresql-16" in package_names

    @patch("workload.run_command")
    @patch("workload.apt")
    def test_install_creates_venv(self, mock_apt, mock_run_cmd):
        """Install should create a virtual environment."""
        workload.install("/charm")

        mock_run_cmd.assert_any_call("python3", "-m", "venv", "/venv")

    @patch("workload.run_command")
    @patch("workload.apt")
    def test_install_installs_setuptools(self, mock_apt, mock_run_cmd):
        """Install should install setuptools in the venv."""
        workload.install("/charm")

        mock_run_cmd.assert_any_call(
            "/venv/bin/python", "-m", "pip", "install", "setuptools==80.10.2"
        )

    @patch("workload.run_command")
    @patch("workload.apt")
    def test_install_installs_requirements(self, mock_apt, mock_run_cmd):
        """Install should pip install from the app requirements.txt."""
        workload.install("/charm")

        mock_run_cmd.assert_any_call(
            "/venv/bin/python",
            "-m",
            "pip",
            "install",
            "-r",
            "/charm/src/flask/app/requirements.txt",
        )


class TestMigrate:
    """Tests for the migrate function."""

    @patch("workload.run_command")
    def test_migrate_creates_pg_trgm_extension(self, mock_run_cmd):
        """Migrate should install the pg_trgm extension first."""
        workload.migrate("/charm", "postgresql://host/db")

        mock_run_cmd.assert_any_call(
            "psql", "-c", "CREATE EXTENSION IF NOT EXISTS pg_trgm;", "postgresql://host/db"
        )

    @patch("workload.run_command")
    def test_migrate_sets_environment_variables(self, mock_run_cmd):
        """Migrate should set DATABASE_URL and SECRET_KEY env vars."""
        workload.migrate("/charm", "postgresql://host/db")

        assert os.environ["DATABASE_URL"] == "postgresql://host/db"
        assert os.environ["SECRET_KEY"] == "placeholder"


class TestStart:
    """Tests for the start function."""

    @patch("workload.run_command")
    def test_start_sets_environment_variables(self, mock_run_cmd):
        """Start should set SECRET_KEY, DATABASE_URL and OAUTH_TOKEN_SALT env vars."""
        workload.start("/charm", "4", "60", "my-secret", "my-salt", "postgresql://host/db")

        assert os.environ["SECRET_KEY"] == "my-secret"
        assert os.environ["DATABASE_URL"] == "postgresql://host/db"
        assert os.environ["OAUTH_TOKEN_SALT"] == "my-salt"

    @patch("workload.run_command")
    def test_start_runs_gunicorn(self, mock_run_cmd):
        """Start should invoke talisker.gunicorn with correct arguments."""
        workload.start("/charm", "4", "60", "my-secret", "my-salt", "postgresql://host/db")

        mock_run_cmd.assert_called_once_with(
            "/venv/bin/python",
            "-m",
            "talisker.gunicorn",
            "webapp.app:app",
            "--chdir",
            "/charm/src/flask/app/",
            "--bind",
            "0.0.0.0:8000",
            "--workers",
            "4",
            "--timeout",
            "60",
        )

    @patch("workload.run_command")
    def test_start_passes_workers_and_timeout(self, mock_run_cmd):
        """Start should forward workers and timeout to gunicorn."""
        workload.start("/charm", "8", "120", "key", "salt", "postgres://x/y")

        args = mock_run_cmd.call_args.args
        # Find the position of --workers and --timeout flags
        assert "--workers" in args
        assert args[args.index("--workers") + 1] == "8"
        assert "--timeout" in args
        assert args[args.index("--timeout") + 1] == "120"

    @patch("workload.run_command")
    def test_start_missing_database_url_raises(self, mock_run_cmd):
        """Start without database_url should raise RuntimeError."""
        with pytest.raises(RuntimeError, match="DATABASE_URL"):
            workload.start("/charm", "4", "60", "key", "salt", "")

    @patch("workload.run_command")
    def test_start_missing_secret_key_raises(self, mock_run_cmd):
        """Start without secret_key should raise RuntimeError."""
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            workload.start("/charm", "4", "60", "", "salt", "postgres://x/y")

    @patch("workload.run_command")
    def test_start_missing_oauth_token_salt_raises(self, mock_run_cmd):
        """Start without oauth_token_salt should raise RuntimeError."""
        with pytest.raises(RuntimeError, match="OAUTH_TOKEN_SALT"):
            workload.start("/charm", "4", "60", "key", "", "postgres://x/y")
