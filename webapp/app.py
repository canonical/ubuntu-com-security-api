from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from canonicalwebteam.flask_base.app import FlaskBase

from webapp.views import get_cve, get_notice, get_cves, get_notices
from webapp.api_spec import WebappFlaskApiSpec

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
        "APISPEC_SWAGGER_URL": "/security/spec.json",
        "APISPEC_SWAGGER_UI_URL": "/security/docs",
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

docs = WebappFlaskApiSpec(app)
docs.register(get_cve)
docs.register(get_cves)
docs.register(get_notice)
docs.register(get_notices)
