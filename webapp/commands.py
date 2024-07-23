import click
from webapp.models import (
    upsert_numerical_cve_ids,
)


@click.command("insert_numerical_cve_ids")
def insert_numerical_cve_ids():
    """
    For each cve, update cves.numerical_field with the numerical value
    of the CVE id e.g 'CVE-2025-12345' -> 202512345.
    """

    upsert_numerical_cve_ids()

    click.echo("Numerical CVE ids inserted successfully.")


def register_commands(app):
    """Register Click commands."""
    # Set up app context
    app.app_context().push()

    app.cli.add_command(insert_numerical_cve_ids)
