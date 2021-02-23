from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from canonicalwebteam.flask_base.app import FlaskBase
from flask import jsonify, make_response

from webapp.api_spec import WebappFlaskApiSpec
from webapp.database import db_session
from webapp.views import (
    get_cve,
    get_notice,
    get_cves,
    get_notices,
    create_notice,
    update_notice,
    delete_notice,
    delete_cve,
    bulk_upsert_cve,
    create_release,
    delete_release,
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
    "/security/cves",
    view_func=bulk_upsert_cve,
    methods=["PUT"],
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/cves/<cve_id>",
    view_func=delete_cve,
    methods=["DELETE"],
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

app.add_url_rule(
    "/security/releases",
    view_func=create_release,
    methods=["POST"],
    provide_automatic_options=False,
)
app.add_url_rule(
    "/security/releases/<codename>",
    view_func=delete_release,
    methods=["DELETE"],
    provide_automatic_options=False,
)

views_to_register_in_docs = [
    get_cve,
    get_cves,
    bulk_upsert_cve,
    delete_cve,
    get_notice,
    get_notices,
    create_notice,
    update_notice,
    delete_notice,
    create_release,
    delete_release,
]

docs = WebappFlaskApiSpec(app)
for view in views_to_register_in_docs:
    docs.register(view)


@app.errorhandler(422)
def handle_error(error):
    messages = error.data.get("messages")

    return make_response(
        jsonify({"message": "Invalid payload", "errors": str(messages)}),
        422,
    )


@app.teardown_appcontext
def remove_db_session(response):
    db_session.remove()

    return response
