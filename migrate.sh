#!/usr/bin/env bash
set -e

# Set FLASK_APP to the app entrypoint
export FLASK_APP=webapp.app

# Print debug info
if [ "${FLASK_DEBUG}" = true ] || [ "${FLASK_DEBUG}" = 1 ]; then
    echo "Running in debug mode"
fi

# Run database migrations
echo "Running flask db upgrade..."
flask db upgrade
