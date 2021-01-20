from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from canonicalwebteam.flask_base.app import FlaskBase
from flask import jsonify, make_response

from webapp.api_spec import WebappFlaskApiSpec
from webapp.views import (
    get_cve,
    get_notice,
    get_cves,
    get_notices,
    create_notice,
    update_notice,
    delete_notice,
)

app = FlaskBase(
    __name__,
    "ubuntu-com-security-api",
)

app.config.update(
    {
        "APISPEC_SPEC": APISpec(
            title="Ubuntu Security API",
            version="v1",
            openapi_version="2.0.0",
            plugins=[MarshmallowPlugin()],
        ),
        "APISPEC_SWAGGER_URL": "/security/api/spec.json",
        "APISPEC_SWAGGER_UI_URL": "/security/api/docs",
    }
)

app.add_url_rule(
    "/security/cves/<cve_id>.json",
    view_func=get_cve,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/cves.json",
    view_func=get_cves,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/notices/<notice_id>.json",
    view_func=get_notice,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/notices.json",
    view_func=get_notices,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/notices",
    view_func=create_notice,
    methods=["POST"],
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/notices/<notice_id>",
    view_func=update_notice,
    methods=["PUT"],
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/notices/<notice_id>",
    view_func=delete_notice,
    methods=["DELETE"],
    provide_automatic_options=False,
)

docs = WebappFlaskApiSpec(app)
docs.register(get_cve)
docs.register(get_cves)
docs.register(get_notice)
docs.register(get_notices)
docs.register(create_notice)
docs.register(update_notice)
docs.register(delete_notice)


@app.errorhandler(422)
def handle_error(error):
    messages = error.data.get("messages")

    return make_response(
        jsonify({"message": "Invalid payload", "errors": str(messages)}),
        422,
    )
