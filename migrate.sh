#!/bin/bash

set -e

# Set RUN_MIGRATIONS=false where another app that shares the database runs
# the migrations. The charm sets it as FLASK_RUN_MIGRATIONS. Any value other
# than false/0/no runs them, so a typo does not silently skip migrations.
RUN_MIGRATIONS="${FLASK_RUN_MIGRATIONS:-${RUN_MIGRATIONS:-true}}"
case "$(printf '%s' "${RUN_MIGRATIONS}" | tr '[:upper:]' '[:lower:]')" in
    false | 0 | no)
        echo "RUN_MIGRATIONS=${RUN_MIGRATIONS}: skipping database migrations"
        exit 0
        ;;
esac

FLASK_APP=webapp.app flask db upgrade
