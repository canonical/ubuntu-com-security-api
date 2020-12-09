import flask
from flask_apispec import FlaskApiSpec


class WebappFlaskApiSpec(FlaskApiSpec):
    def add_swagger_routes(self):
        blueprint = flask.Blueprint(
            "flask-apispec",
            __name__,
            static_folder="../static",
            template_folder="../templates",
            static_url_path="/security/api/static",
        )

        json_url = self.app.config.get("APISPEC_SWAGGER_URL")
        blueprint.add_url_rule(json_url, "swagger-json", self.swagger_json)

        ui_url = self.app.config.get("APISPEC_SWAGGER_UI_URL")
        blueprint.add_url_rule(ui_url, "swagger-ui", self.swagger_ui)

        self.app.register_blueprint(blueprint)
