#!/bin/bash
# Check the deployed API from outside.
#
#   BASE_URL       for example https://api.staging.security.ubuntu.com
#   CHECK_PUBLISH  "true" to also check the publish route.
set -euo pipefail

BASE_URL=${BASE_URL%/}
ATTEMPTS=${ATTEMPTS:-6}
RETRY_SECONDS=${RETRY_SECONDS:-10}

# check NAME EXPECTED_CODES CURL_ARGS...
check() {
    local name=$1 expected=$2 code attempt
    shift 2
    for attempt in $(seq 1 "$ATTEMPTS"); do
        code=$(curl --silent --output /dev/null --max-time 30 \
            --write-out '%{http_code}' "$@" || true)
        case " $expected " in
            *" $code "*)
                echo "$name: $code"
                return 0
                ;;
        esac
        echo "$name: got $code, want one of: $expected (attempt $attempt/$ATTEMPTS)"
        [ "$attempt" = "$ATTEMPTS" ] || sleep "$RETRY_SECONDS"
    done
    echo "::error::$name failed: got $code, want one of: $expected"
    return 1
}

check "read" "200" "$BASE_URL/security/cves.json?limit=1"

if [ "${CHECK_PUBLISH:-false}" = "true" ]; then
    # An unsigned request must be refused fast. 401 or 403 shows that the
    # route reaches the publish app and that the app can reach Launchpad.
    check "publish" "401 403" --request PUT \
        "$BASE_URL/security/updates/cves.json"
fi
