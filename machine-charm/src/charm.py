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
    database: str = pydantic.Field("", description="Configures the database url")
    replica_one: str = pydantic.Field(
        "", description="Configures the database url for a replica if available."
    )
    replica_two: str = pydantic.Field(
        "", description="Configures the database url for a second replica if available."
    )
    oauth_token_salt: str = pydantic.Field(
        "", description="Salt used to encode and decode OAuth tokens"
    )
    bind_address: str = pydantic.Field("0.0.0.0:8000", description="Address to bind the webapp to")
    workers: str = pydantic.Field("3", description="Number of workers for the webapp")
    timeout: str = pydantic.Field("30", description="Worker timeout for the webapp")


class MachineCharmCharm(ops.CharmBase):
    """Charm the application."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on.config_changed, self._on_config_changed)
        self.unit.status = ops.MaintenanceStatus("waiting for database relation")
        # Charm events defined in the database requires charm library.
        self.database = DatabaseRequires(
            self, relation_name="postgresql", database_name="postgresql"
        )
        framework.observe(self.database.on.database_created, self._on_database_created)

    def _on_database_created(self, event: DatabaseCreatedEvent) -> None:
        """Handle database created event."""
        logger.info("Database created with connection string: %s", event.connection_string)
        self.unit.status = ops.MaintenanceStatus("running migrations")
        # Run migrations before starting the workload to ensure the database is ready.
        workload.migrate(self.charm_dir.absolute().as_posix(), event.connection_string)
        # Start workload when database is ready.
        self._start()

    def _on_install(self, event: ops.InstallEvent):
        """Install the workload on the machine."""
        workload.install(self.charm_dir.absolute().as_posix())

    def _start(self) -> None:
        """Start the workload."""
        self.unit.status = ops.MaintenanceStatus("starting workload")
        config = self.load_config(WorkloadConfig)
        workload.start(config.bind_address, config.workers, config.timeout)
        self.unit.status = ops.ActiveStatus()

    def _on_config_changed(self, event: ops.ConfigChangedEvent):
        """Handle config changes."""
        # For simplicity, we will just restart the workload on any config change.
        self.unit.status = ops.MaintenanceStatus("config changed, restarting workload")
        self._stop()
        self._start()

    def _stop(self) -> None:
        """Stop the workload."""
        self.unit.status = ops.MaintenanceStatus("stopping workload")
        workload.stop()


if __name__ == "__main__":  # pragma: nocover
    ops.main(MachineCharmCharm)
