#!/bin/bash

set -e

# Set RUN_MIGRATIONS=false where another app that shares the database
# runs the migrations. The charm sets it as FLASK_RUN_MIGRATIONS.
RUN_MIGRATIONS="${FLASK_RUN_MIGRATIONS:-${RUN_MIGRATIONS:-true}}"
if [ "${RUN_MIGRATIONS}" != "true" ]; then
    echo "RUN_MIGRATIONS=${RUN_MIGRATIONS}: skipping database migrations"
    exit 0
fi

FLASK_APP=webapp.app flask db upgrade
