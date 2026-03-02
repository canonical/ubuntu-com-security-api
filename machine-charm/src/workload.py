# Copyright 2026 Samuel Olwe
# See LICENSE file for licensing details.

"""Functions for managing and interacting with the workload.

The intention is that this module could be used outside the context of a charm.
"""

import logging
import os
import subprocess
from contextlib import contextmanager
from typing import Generator

from charmlibs import apt

logger = logging.getLogger(__name__)

GUNICORN_LOG_FILE = "/var/log/gunicorn.log"
INSTALL_LOG_FILE = "/var/log/install.log"


@contextmanager
def use_path(path: str) -> Generator:
    """Execute a function within the specified directory."""
    cwd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(cwd)


def run_command(*args, cwd=None, log_file=None) -> None:
    """Run a subprocess and raise a RuntimeError if the subprocess result indicates an error.

    We do this to bubble up the error message from the subprocess to the debug-log.
    """
    try:
        subprocess.run(
            args,
            check=True,
            text=True,
            cwd=cwd,
            stdout=log_file or subprocess.PIPE,
            stderr=log_file or subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(str(e)) from e


def install(charm_dir: str) -> None:
    """Install the workload (by installing a snap, for example)."""
    # Install apt packages
    apt.update()
    apt.add_package("libsodium-dev", "1.0.18-1ubuntu0.24.04.1")
    apt.add_package("python3-venv", "3.12.3-0ubuntu2.1")
    apt.add_package("postgresql-16", "16.11-0ubuntu0.24.04.1")

    with open(INSTALL_LOG_FILE, "a") as log_file:
        # Create a virtual environment
        run_command("python3", "-m", "venv", "/venv", log_file=log_file)

        # Install setuptools to support pkg_resources
        run_command(
            "/venv/bin/python", "-m", "pip", "install", "setuptools==80.10.2", log_file=log_file
        )

        # Install workload python packages
        run_command(
            "/venv/bin/python",
            "-m",
            "pip",
            "install",
            "-r",
            f"{charm_dir}/src/flask/app/requirements.txt",
            log_file=log_file,
        )


def migrate(charm_dir: str, database_url: str) -> None:
    """Run database migrations."""
    with open(INSTALL_LOG_FILE, "a") as log_file:
        # Install the pg_trgm extension
        run_command(
            "psql",
            "-c",
            "CREATE EXTENSION IF NOT EXISTS pg_trgm;",
            database_url,
            log_file=log_file,
        )
        # Then run migrations
        os.environ["DATABASE_URL"] = database_url
        os.environ["SECRET_KEY"] = (
            "placeholder"  # SECRET_KEY must be set, the actual value is not relevant for migrations
        )
        run_command(
            "/venv/bin/python",
            "-m",
            "flask",
            "--app",
            f"{charm_dir}/src/flask/app/webapp.app",
            "db",
            "upgrade",
            cwd=f"{charm_dir}/src/flask/app/",
            log_file=log_file,
        )


def start(
    charm_dir: str,
    workers: str,
    timeout: str,
    secret_key: str,
    oauth_token_salt: str,
    database_url: str,
) -> None:
    """Start the webapp."""
    if not database_url:
        raise RuntimeError("DATABASE_URL must be provided to start the workload")
    if not secret_key:
        raise RuntimeError("SECRET_KEY must be provided to start the workload")
    if not oauth_token_salt:
        raise RuntimeError("OAUTH_TOKEN_SALT must be provided to start the workload")
    os.environ["SECRET_KEY"] = secret_key
    os.environ["DATABASE_URL"] = database_url
    os.environ["OAUTH_TOKEN_SALT"] = oauth_token_salt

    # Add logging for gunicorn
    with open(GUNICORN_LOG_FILE, "a") as log_file:
        run_command(
            "/venv/bin/python",
            "-m",
            "talisker.gunicorn",
            "webapp.app:app",
            "--chdir",
            f"{charm_dir}/src/flask/app/",
            "--bind",
            "0.0.0.0:8000",
            "--workers",
            workers,
            "--timeout",
            timeout,
            log_file=log_file,
        )


def stop() -> None:
    """Stop the webapp."""
    run_command("pkill", "-9", "gunicorn")


def is_running() -> bool:
    """Return whether the webapp is running."""
    try:
        run_command("pgrep", "-f", "gunicorn")
    except RuntimeError:
        return False

    return True


def restore_database_from_file(file_name: str, database_url: str) -> None:
    """Restore the database from a file."""
    if is_running():
        stop()

    file_path = f"/tmp/{file_name}"
    if not os.path.exists(file_path):
        raise RuntimeError(f"Database file {file_path} does not exist")

    # Terminate existing connections to the database to allow for restore.
    run_command(
        "psql",
        database_url,
        "-c",
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database()"
        " AND pid <> pg_backend_pid();",
    )

    # Backup the existing database before restoring the new one, in case we need to roll back.
    backup_file_path = f"/tmp/backup_{file_name}"
    run_command(
        "pg_dump",
        database_url,
        "-Fc",
        "-f",
        backup_file_path,
    )
    try:
        # Clear out the existing database before restoring the new one.
        run_command(
            "psql",
            database_url,
            "-c",
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        )
        # Upload the new file.
        run_command("psql", database_url, "-f", file_path)
    except Exception as e:
        # If restore fails, restore the original database from the backup file.
        run_command(
            "pg_restore",
            database_url,
            "-Fc",
            backup_file_path,
        )
        raise RuntimeError("Failed to restore the database from the uploaded file") from e
    finally:
        # Clean up the backup file.
        os.remove(backup_file_path)
