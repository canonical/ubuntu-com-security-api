import click
from webapp.app import app
from webapp.models import (
    upsert_numerical_cve_ids,
)


@app.cli.command("insert-numerical-cve-ids")
def insert_numerical_cve_ids():
    """Management script for the Wiki application."""
    upsert_numerical_cve_ids()
    click.echo("Numerical CVE ids inserted successfully.")
