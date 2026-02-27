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


@contextmanager
def use_path(path: str) -> Generator:
    """Execute a function within the specified directory."""
    cwd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(cwd)


def run_command(*args) -> None:
    """Run a subprocess and raise a RuntimeError if the subprocess result indicates an error.

    We do this to bubble up the error message from the subprocess to the debug-log.
    """
    try:
        subprocess.run(args, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(e.stderr) from e


def ensure_config(port: int, slug: str) -> bool:
    """Ensure that required config variables are supplied."""
    if os.getenv("DATABASE_URL"):
        return True
    return False


def run_migrations() -> None:
    """Run database migrations."""
    with use_path("../.."):
        subprocess.run(
            ["flask", "--app", "webapp.app", "db", "upgrade"],
            check=True,
            capture_output=True,
            text=True,
        )


def install(charm_dir: str) -> None:
    """Install the workload (by installing a snap, for example)."""
    # Install apt packages
    apt.update()
    apt.add_package("libsodium-dev", "1.0.18-1ubuntu0.24.04.1")
    apt.add_package("python3-virtualenv", "20.25.0+ds-2")
    apt.add_package("postgresql-16", "16.11-0ubuntu0.24.04.1")

    # Create a virtual environment
    run_command("virtualenv", "/venv")

    # Install workload python packages
    run_command(
        "/venv/bin/python",
        "-m",
        "pip",
        "install",
        "-r",
        f"{charm_dir}/src/flask/app/requirements.txt",
    )


def migrate(charm_dir: str, database_url: str) -> None:
    """Run database migrations."""
    # Install the pg_trgm extension
    run_command("psql", "-c", "CREATE EXTENSION IF NOT EXISTS pg_trgm;", database_url)
    # Then run migrations
    run_command(
        "/venv/bin/python",
        "-m",
        "flask",
        "--app",
        f"{charm_dir}/src/flask/app/webapp.app",
        "db",
        "upgrade",
    )


def start(address: str, workers: str, timeout: str) -> None:
    """Start the webapp."""
    run_command(
        "/venv/bin/python",
        "-m",
        "talisker.gunicorn",
        "webapp.app:app",
        "--bind",
        address,
        "--workers",
        workers,
        "--timeout",
        timeout,
    )


def stop() -> None:
    """Stop the webapp."""
    run_command("pkill", "-f", "gunicorn")


# def is_installed() -> bool:
#     """Return whether the tinyproxy executable is available."""
#     return shutil.which("tinyproxy") is not None


# def is_running() -> bool:
#     """Return whether tinyproxy is running."""
#     return bool(_get_pid())


# def reload_config() -> None:
#     """Ask tinyproxy to reload config."""
#     pid = _get_pid()
#     if not pid:
#         raise RuntimeError("tinyproxy is not running")
#     # Sending signal SIGUSR1 doesn't terminate the process. It asks the process to reload config.
#     # See https://manpages.ubuntu.com/manpages/jammy/en/man8/tinyproxy.8.html#signals
#     os.kill(pid, signal.SIGUSR1)


# def stop() -> None:
#     """Stop tinyproxy."""
#     pid = _get_pid()
#     if pid:
#         os.kill(pid, signal.SIGTERM)


# def uninstall() -> None:
#     """Uninstall the tinyproxy executable and remove files."""
#     apt.remove_package("tinyproxy-bin")
#     PID_FILE.unlink(missing_ok=True)
#     CONFIG_FILE.unlink(missing_ok=True)
#     CONFIG_FILE.parent.rmdir()


# def _get_pid() -> int | None:
#     """Return the PID of the tinyproxy process, or None if the process can't be found."""
#     if not PID_FILE.exists():
#         return None
#     pid = int(PID_FILE.read_text())
#     try:
#         # Sending signal 0 doesn't terminate the process. It just checks whether the PID exists.
#         os.kill(pid, 0)
#     except ProcessLookupError:
#         return None
#     return pid
