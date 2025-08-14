import os

from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from canonicalwebteam.flask_base.app import FlaskBase
from flask import jsonify, make_response

from webapp.api_spec import WebappFlaskApiSpec
from webapp.commands import register_commands
from webapp.database import init_db
from webapp.views import (
    bulk_upsert_cve,
    create_notice,
    create_release,
    delete_cve,
    delete_notice,
    delete_release,
    get_cve,
    get_cves,
    get_flat_notices,
    get_released_cves,
    get_sitemap_cves,
    get_sitemap_notices,
    get_notice,
    get_notice_v2,
    get_notices,
    get_notices_v2,
    get_page_notices,
    get_release,
    get_releases,
    update_notice,
    update_release,
)

# Flask compress options
COMPRESS_MIMETYPES = [
    "text/html",
    "text/css",
    "text/plain",
    "text/xml",
    "text/x-component",
    "text/javascript",
    "application/x-javascript",
    "application/javascript",
    "application/manifest+json",
    "application/vnd.api+json",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/vnd.ms-fontobject",
    "application/x-font-ttf",
    "application/x-font-opentype",
    "application/x-font-truetype",
    "image/svg+xml",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "font/ttf",
    "font/eot",
    "font/otf",
    "font/opentype",
]

app = FlaskBase(
    __name__, "ubuntu-com-security-api", compress_mimetypes=COMPRESS_MIMETYPES
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
        "SQLALCHEMY_DATABASE_URI": os.environ.get(
            "POSTGRESQL_DB_CONNECT_STRING",
            os.environ.get("DATABASE_URL", "sqlite:///security.db"),
        ),
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    },
)

init_db(app)

register_commands(app)

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
    "/security/released/cves.json",
    view_func=get_released_cves,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/sitemap/cves.json",
    view_func=get_sitemap_cves,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/sitemap/notices.json",
    view_func=get_sitemap_notices,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/notices/<notice_id>.json",
    view_func=get_notice_v2,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/notices.json",
    view_func=get_notices_v2,
    provide_automatic_options=False,
)


app.add_url_rule(
    "/security/compat/notices/<notice_id>.json",
    view_func=get_notice,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/compat/notices.json",
    view_func=get_notices,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/page/notices.json",
    view_func=get_page_notices,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/flat/notices.json",
    view_func=get_flat_notices,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/releases/<release_codename>.json",
    view_func=get_release,
    methods=["GET"],
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/releases.json",
    view_func=get_releases,
    methods=["GET"],
    provide_automatic_options=False,
)

# Upsert endpoints are declared on /security/updates for performance reasons

app.add_url_rule(
    "/security/updates/cves.json",
    view_func=bulk_upsert_cve,
    methods=["PUT"],
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/updates/cves/<cve_id>.json",
    view_func=delete_cve,
    methods=["DELETE"],
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/updates/notices.json",
    view_func=create_notice,
    methods=["POST"],
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/updates/notices/<notice_id>.json",
    view_func=update_notice,
    methods=["PUT"],
    provide_automatic_options=False,
)

app.add_url_rule(
    "/security/updates/notices/<notice_id>.json",
    view_func=delete_notice,
    methods=["DELETE"],
    provide_automatic_options=False,
)


app.add_url_rule(
    "/security/updates/releases.json",
    view_func=create_release,
    methods=["POST"],
    provide_automatic_options=False,
)
app.add_url_rule(
    "/security/updates/releases/<release_codename>.json",
    view_func=update_release,
    methods=["PUT"],
    provide_automatic_options=False,
)
app.add_url_rule(
    "/security/updates/releases/<release_codename>.json",
    view_func=delete_release,
    methods=["DELETE"],
    provide_automatic_options=False,
)

views_to_register_in_docs = [
    get_cve,
    get_cves,
    bulk_upsert_cve,
    delete_cve,
    get_page_notices,
    get_notice,
    get_notices,
    get_notice_v2,
    get_notices_v2,
    create_notice,
    update_notice,
    delete_notice,
    get_release,
    get_releases,
    create_release,
    update_release,
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
