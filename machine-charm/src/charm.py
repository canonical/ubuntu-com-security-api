#!/usr/bin/env python3
# Copyright 2026 Samuel Olwe
# See LICENSE file for licensing details.

"""Charm the application."""

import logging
import os

import ops
import pydantic
from charms.data_platform_libs.v0.data_interfaces import (
    DatabaseCreatedEvent,
    DatabaseEntityCreatedEvent,
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
        # framework.observe(self.on.start, self._on_start)
        framework.observe(self.on.config_changed, self._on_config_changed)
        # Charm events defined in the database requires charm library.
        self.database = DatabaseRequires(
            self, relation_name="postgresql", database_name="postgresql"
        )
        self.framework.observe(self.database.on.database_created, self._on_database_created)
        self.framework.observe(
            self.database.on.database_entity_created, self._on_database_entity_created
        )

    def _on_database_created(self, event: DatabaseCreatedEvent) -> None:
        """Handle database created event."""
        logger.info("Database created with connection string: %s", event.connection_string)

        # Add env variable for flask-base
        os.environ["DATABASE_URL"] = event.connection_string
        # Start workload when database is ready.
        self._start()

    def _on_database_entity_created(self, event: DatabaseEntityCreatedEvent) -> None:
        """Handle database entity created event."""
        logger.info("Database entity created with connection string: %s", event.connection_string)

    def _on_install(self, event: ops.InstallEvent):
        """Install the workload on the machine."""
        workload.install(self.charm_dir.absolute().as_posix())

    def _start(self):
        """Start the workload."""
        self.unit.status = ops.MaintenanceStatus("starting workload")
        config = self.load_config(WorkloadConfig)
        workload.start(config.bind_address, config.workers, config.timeout)
        self.unit.status = ops.ActiveStatus()

    def _on_start(self, event: ops.StartEvent):
        """Handle start event."""
        self._start()

    def _on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        """Handle config-changed event."""
        self.configure_and_run()

    def configure_and_run(self) -> None:
        """Ensure that the workload is running with the correct config."""
        try:
            config = self.load_config(WorkloadConfig)
        except pydantic.ValidationError:
            # The collect-status handler will run next and will set status for the user to see.
            return


if __name__ == "__main__":  # pragma: nocover
    ops.main(MachineCharmCharm)
