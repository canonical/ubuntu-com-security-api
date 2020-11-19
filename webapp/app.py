from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from canonicalwebteam.flask_base.app import FlaskBase
from flask_apispec import FlaskApiSpec

from webapp.views import get_cve, get_notice

app = FlaskBase(
    __name__,
    "security.ubuntu.com",
)

app.config.update(
    {
        "APISPEC_SPEC": APISpec(
            title="Ubuntu Security API",
            version="v1",
            openapi_version="2.0.0",
            plugins=[MarshmallowPlugin()],
        ),
        "APISPEC_SWAGGER_URL": "/spec.json",
        "APISPEC_SWAGGER_UI_URL": "/docs",
    }
)

app.add_url_rule(
    "/cves/<cve_id>.json",
    view_func=get_cve,
    provide_automatic_options=False,
)

app.add_url_rule(
    "/notices/<notice_id>.json",
    view_func=get_notice,
    provide_automatic_options=False,
)


docs = FlaskApiSpec(app)
docs.register(get_cve)
docs.register(get_notice)
