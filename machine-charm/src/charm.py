#!/usr/bin/env python3
# Copyright 2026 Samuel Olwe
# See LICENSE file for licensing details.

"""Charm the application."""

import logging

import ops
import pydantic
from charms.data_platform_libs.v0.data_interfaces import (
    DatabaseCreatedEvent,
    DatabaseRequires,
)

# A standalone module for workload-specific logic (no charming concerns):
import workload

logger = logging.getLogger(__name__)


class WorkloadConfig(pydantic.BaseModel):
    """Pydantic model for charm configuration."""

    workers: str = pydantic.Field("3", description="Number of workers for the webapp")
    timeout: str = pydantic.Field("30", description="Worker timeout for the webapp")


class MachineCharmCharm(ops.CharmBase):
    """Charm the application."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on.start, self._on_start)
        framework.observe(self.on.stop, self._on_stop)
        framework.observe(self.on.config_changed, self._on_config_changed)
        # Charm events defined in the database requires charm library.
        self.database = DatabaseRequires(
            self, relation_name="postgresql", database_name="postgresql"
        )
        framework.observe(self.database.on.database_created, self._on_database_created)
        framework.observe(self.on["upload-database"].action, self._on_upload_database_action)
        framework.observe(self.on["show-install-logs"].action, self._show_install_logs)
        framework.observe(self.on["show-gunicorn-logs"].action, self._show_gunicorn_logs)

    def _get_database_uri(self) -> str:
        """Get the writeable database URI from the relation data.

        This reads from the relation data bag on every event, since charm
        instances are ephemeral and cannot persist state across events.
        """
        if not self.database.relations:
            return ""

        relation = self.database.relations[0]
        relation_id = relation.id
        relation_data = self.database.fetch_relation_data([relation_id]).get(relation_id, {})

        uris = relation_data.get("uris", "")
        if not uris:
            return ""

        # Filter out read-only URIs to get the writeable one
        uri_set = set(uris.split(","))
        read_only_uris = relation_data.get("read-only-uris", "")
        if len(uri_set) > 1 and read_only_uris:
            uri_set -= set(read_only_uris.split(","))

        return uri_set.pop() if uri_set else ""

    @staticmethod
    def _get_writeable_uri(event: DatabaseCreatedEvent) -> str:
        """Extract the writeable database URI from a database event.

        When multiple URIs are provided, the read-only URIs are subtracted
        to determine the writeable one.
        """
        if not event.uris:
            raise RuntimeError("No database URIs provided in the event.")

        uri_list = set(event.uris.split(","))
        if len(uri_list) > 1 and event.read_only_uris:
            read_only_uris = set(event.read_only_uris.split(","))
            writeable_uris = uri_list - read_only_uris
            return writeable_uris.pop()
        return event.uris

    def _on_install(self, event: ops.InstallEvent):
        """Install the workload on the machine."""
        workload.install(self.charm_dir.absolute().as_posix())
        if not self.database.is_resource_created():
            self.unit.status = ops.BlockedStatus("waiting for database relation")
            return

    def _on_database_created(self, event: DatabaseCreatedEvent) -> None:
        """Handle database created event."""
        logger.info("Database created with name: %s", event.database)

        connection_string = self._get_writeable_uri(event)
        self.unit.status = ops.MaintenanceStatus("running migrations")

        # Run migrations before starting the workload to ensure the database is ready.
        workload.migrate(self.charm_dir.absolute().as_posix(), connection_string)
        # Start workload when database is ready.
        self._restart()

    def _start(self) -> None:
        """Start the workload."""
        self.unit.status = ops.MaintenanceStatus("starting workload")
        if not self.database.is_resource_created():
            self.unit.status = ops.BlockedStatus("waiting for database relation")
            return

        database_uri = self._get_database_uri()
        if not database_uri:
            self.unit.status = ops.BlockedStatus("waiting for database URI")
            return

        try:
            oauth_token_salt_id: str = self.config.get("oauth-token-salt")  # type: ignore
            secret_key_id: str = self.config.get("secret-key")  # type: ignore

            oauth_token_salt = (
                self.model.get_secret(id=oauth_token_salt_id)
                .get_content(refresh=True)
                .get("oauth-token-salt", "")
            )
            secret_key = (
                self.model.get_secret(id=secret_key_id)
                .get_content(refresh=True)
                .get("secret-key", "")
            )
        except ops.SecretNotFoundError as e:
            logger.error("Required secret not found: %s", e)
            self.unit.status = ops.BlockedStatus("missing secret: %s" % str(e))
            return

        workload.start(
            self.charm_dir.absolute().as_posix(),
            self.config.get("workers", "3"),  # type: ignore
            self.config.get("timeout", "60"),  # type: ignore
            secret_key,
            oauth_token_salt,
            database_uri,
        )
        # Expose the webapp port.
        self.unit.set_ports(8000)

        if workload.is_running():
            self.unit.status = ops.ActiveStatus("application has started")
        else:
            self.unit.status = ops.BlockedStatus("failed to start workload")
            logger.error("Failed to start workload")

    def _on_config_changed(self, event: ops.ConfigChangedEvent):
        """Handle config changes."""
        # For simplicity, we will just restart the workload on any config change.
        self.unit.status = ops.MaintenanceStatus("config changed")
        self.load_config(WorkloadConfig)  # Validate config before restarting
        self._restart()

    def _stop(self) -> None:
        """Stop the workload."""
        self.unit.status = ops.MaintenanceStatus("stopping workload")
        workload.stop()

    def _restart(self) -> None:
        """Restart the workload."""
        self.unit.status = ops.MaintenanceStatus("restarting workload")
        if workload.is_running():
            self._stop()
        self._start()

    def _on_start(self, event: ops.StartEvent):
        """Handle the start event."""
        self._start()

    def _on_stop(self, event: ops.StopEvent):
        """Handle the stop event."""
        self._stop()

    def _on_upload_database_action(self, event: ops.ActionEvent) -> None:
        """Handle the upload-database action."""
        params = event.load_params(UploadDatabaseAction, errors="fail")
        event.log(f"Uploading database file: {params.filename}")

        if not self.database.is_resource_created():
            event.fail("Database relation is not ready")
            return

        # Dump new database from the uploaded file
        database_uri = self._get_database_uri()

        workload.restore_database_from_file(params.filename, database_uri)
        try:
            # Run migrations to verify the database is in a good state after the restore.
            workload.migrate(self.charm_dir.absolute().as_posix(), database_uri)
            event.set_results({"message": "Database migrated successfully"})
        except Exception as e:
            logger.error("Failed to migrate database: %s", e)
            event.fail(f"Failed to migrate database: {e}")

    def _show_install_logs(self, event: ops.ActionEvent) -> None:
        """Show logs from the install process."""
        with open(workload.INSTALL_LOG_FILE, "r") as log_file:
            event.set_results({"install-logs": log_file.read()})

    def _show_gunicorn_logs(self, event: ops.ActionEvent) -> None:
        """Show the gunicorn logs."""
        with open(workload.GUNICORN_LOG_FILE, "r") as log_file:
            event.set_results({"gunicorn-logs": log_file.read()})


class UploadDatabaseAction(pydantic.BaseModel):
    """Upload a zip file containing a snapshot of the application data to the machine."""

    filename: str = pydantic.Field(description="The name of the snapshot file.")


if __name__ == "__main__":  # pragma: nocover
    ops.main(MachineCharmCharm)
