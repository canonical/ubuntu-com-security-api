from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from canonicalwebteam.flask_base.app import FlaskBase
from flask import jsonify
from flask_apispec.extension import FlaskApiSpec

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
        "APISPEC_SWAGGER_URL": "/spec/",
        "APISPEC_SWAGGER_UI_URL": "/docs/",
    }
)

docs = FlaskApiSpec(app)


@app.route("/hello-world")
def get_hello_world():
    return jsonify({"message": "Hello World!"})


docs.register(get_hello_world)
