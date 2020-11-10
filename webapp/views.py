from flask import make_response, jsonify
from flask_apispec import marshal_with

from webapp.database import db_session
from webapp.models import CVE
from webapp.schemas import CVEModelSchema


@marshal_with(CVEModelSchema, code=200)
def get_cve(cve_id):
    cve = db_session.query(CVE).filter(CVE.id == cve_id).one_or_none()

    if not cve:
        return make_response(
            jsonify({"message": f"CVE with id '{cve_id}' does not exist"}),
            404,
        )

    return cve
