# Copyright 2026 Samuel Olwe
# See LICENSE file for licensing details.

"""Functions for managing and interacting with the workload.

The intention is that this module could be used outside the context of a charm.
"""

import logging
import os
import subprocess
import time

from charmlibs import apt

logger = logging.getLogger(__name__)

GUNICORN_LOG_FILE = "/var/log/gunicorn.log"
INSTALL_LOG_FILE = "/var/log/install.log"


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
            stderr=log_file or subprocess.STDOUT,
        )
    except Exception as e:
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
        try:
            os.environ["DATABASE_URL"] = database_url
            os.environ["SECRET_KEY"] = (
                "placeholder"  # SECRET_KEY must be set, the actual value is not relevant for migration
            )
            # Check whether the database is consistent before running migrations
            run_command(
                "/venv/bin/python",
                "-m",
                "flask",
                "--app",
                f"{charm_dir}/src/flask/app/webapp.app",
                "db",
                "current",
                cwd=f"{charm_dir}/src/flask/app/",
                log_file=log_file,
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
        finally:
            # Clean up environment variables
            del os.environ["DATABASE_URL"]
            del os.environ["SECRET_KEY"]


def is_running():
    """Return whether the webapp is running."""
    result = subprocess.run(["systemctl", "is-active", "gunicorn"], capture_output=True, text=True)
    return result.stdout.strip() == "active"


SYSTEMD_UNIT = """[Unit]
Description=Gunicorn Python Application
After=network.target postgresql.service

[Service]
User=root
Group=root
WorkingDirectory={charm_dir}/src/flask/app
Environment="DATABASE_URL={database_url}"
Environment="SECRET_KEY={secret_key}"
Environment="OAUTH_TOKEN_SALT={oauth_token_salt}"
ExecStart=/venv/bin/python -m gunicorn webapp.app:app --bind 0.0.0.0:8000 --workers {workers} --timeout {timeout} --access-logfile {gunicorn_log} --error-logfile {gunicorn_log}
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def install_systemd_service(
    charm_dir, workers, timeout, secret_key, oauth_token_salt, database_url
):
    """Install the systemd service for the workload."""
    # delete existing service if it exists
    if os.path.exists("/etc/systemd/system/gunicorn.service"):
        os.remove("/etc/systemd/system/gunicorn.service")

    with open(GUNICORN_LOG_FILE, "a") as log_file:
        unit_content = SYSTEMD_UNIT.format(
            charm_dir=charm_dir,
            database_url=database_url,
            secret_key=secret_key,
            oauth_token_salt=oauth_token_salt,
            workers=workers,
            timeout=timeout,
            gunicorn_log=GUNICORN_LOG_FILE,
        )
        with open("/etc/systemd/system/gunicorn.service", "w") as f:
            f.write(unit_content)

        run_command("systemctl", "daemon-reload", log_file=log_file)


def start_gunicorn():
    """Start the gunicorn service."""
    with open(GUNICORN_LOG_FILE, "a") as log_file:
        run_command("systemctl", "start", "gunicorn", log_file=log_file)


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

    install_systemd_service(
        charm_dir, workers, timeout, secret_key, oauth_token_salt, database_url
    )
    stop_gunicorn()
    start_gunicorn()
    time.sleep(5)  # Give the service a moment to start
    if not is_running():
        raise RuntimeError("Failed to start the workload, check gunicorn logs for details")


def stop_gunicorn() -> None:
    """Stop the webapp."""
    if is_running():
        run_command("systemctl", "stop", "gunicorn")


def restore_database_from_file(file_name: str, database_url: str) -> None:
    """Restore the database from a file."""
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
            "--dbname",
            database_url,
            "-Fc",
            backup_file_path,
        )
        raise RuntimeError("Failed to restore the database from the uploaded file") from e
    finally:
        # Clean up the backup file.
        os.remove(backup_file_path)

    # Start the service again after restoring the database.
    start_gunicorn()
