from flask import make_response, jsonify
from flask_apispec import marshal_with

from webapp.database import db_session
from webapp.models import CVE, Notice
from webapp.schemas import CVEAPISchema, NoticeAPISchema


@marshal_with(CVEAPISchema, code=200)
def get_cve(cve_id):
    cve = db_session.query(CVE).filter(CVE.id == cve_id).one_or_none()

    if not cve:
        return make_response(
            jsonify({"message": f"CVE with id '{cve_id}' does not exist"}),
            404,
        )

    return cve


@marshal_with(NoticeAPISchema, code=200)
def get_notice(notice_id):
    notice = (
        db_session.query(Notice).filter(Notice.id == notice_id).one_or_none()
    )

    if not notice:
        return make_response(
            jsonify(
                {"message": f"Notice with id '{notice_id}' does not exist"}
            ),
            404,
        )

    return notice
