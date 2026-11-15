#!/bin/bash
# Refresh the Juju apps that run this charm. Needs a logged-in juju client
# that is switched to the model.
#
#   APP_NAME            the read app. Created if it does not exist.
#   PUBLISH_APP_NAME    the app that serves /security/updates. Optional. It is
#                       only refreshed, never created: it needs secrets that
#                       someone must set by hand first.
#   IMAGE_URL           the image for the flask-app-image resource.
#   READ_APP_CONFIG     "key=value ..." applied to the read app, and
#   PUBLISH_APP_CONFIG  to the publish app, when the publish app exists.
set -euo pipefail

CHARM_FILE=$(find . -maxdepth 1 -name "*.charm" | head -1)

app_exists() {
    juju show-application "$1" >/dev/null 2>&1
}

wait_for_app() {
    # Give Juju a moment to start the upgrade, so we do not see the old
    # "active" status and return at once.
    sleep "${SETTLE_SECONDS:-20}"
    juju wait-for application "$1" --timeout=20m \
        --query="name=='$1' && (status=='active' || status=='idle')"
}

refresh_app() {
    local app=$1 config=$2
    echo "::group::Refresh $app"
    juju refresh "$app" --path="$CHARM_FILE" \
        --resource flask-app-image="$IMAGE_URL"
    if [ -n "$config" ]; then
        # Word splitting is wanted: one argument for each key=value.
        # shellcheck disable=SC2086
        juju config "$app" $config
    fi
    wait_for_app "$app"
    echo "::endgroup::"
}

if [ -n "${PUBLISH_APP_NAME:-}" ] && app_exists "$PUBLISH_APP_NAME"; then
    # The publish app runs the database migrations, so it goes first.
    refresh_app "$PUBLISH_APP_NAME" "${PUBLISH_APP_CONFIG:-}"
    refresh_app "$APP_NAME" "${READ_APP_CONFIG:-}"
    echo "publish-app-deployed=true" >>"${GITHUB_OUTPUT:-/dev/null}"
    exit 0
fi

if [ -n "${PUBLISH_APP_NAME:-}" ]; then
    echo "::notice::No '$PUBLISH_APP_NAME' app in this model. Deploying '$APP_NAME' only, with its current config."
fi

if app_exists "$APP_NAME"; then
    refresh_app "$APP_NAME" ""
else
    juju deploy "$CHARM_FILE" "$APP_NAME" \
        --resource flask-app-image="$IMAGE_URL"
    wait_for_app "$APP_NAME"
fi
