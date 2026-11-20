"""Each query on /security/cves/<id>.json is a round trip to a database in
another region, so the view must not use more of them than it needs.
"""

from contextlib import contextmanager

from sqlalchemy import event
from sqlalchemy.engine import Engine

from tests import BaseTestCase
from tests.fixtures.models import make_cve
from webapp.database import db
from webapp.models import Notice


@contextmanager
def recorded_statements():
    statements = []

    def record(conn, cursor, statement, params, context, executemany):
        statements.append(statement)

    event.listen(Engine, "before_cursor_execute", record)
    try:
        yield statements
    finally:
        event.remove(Engine, "before_cursor_execute", record)


class CveRoundTrips(BaseTestCase):
    def _get(self, cve_id, query=""):
        db.session.expunge_all()
        with recorded_statements() as statements:
            response = self.client.get(f"/security/cves/{cve_id}.json{query}")
        return response, statements

    def test_cve_with_notices_takes_two_queries(self):
        notice = db.session.query(Notice).first()
        other = make_cve(id="CVE-1999-3000", status="active")
        db.session.add(other)
        notice.cves.append(other)
        db.session.commit()
        cve_id = self.models["cve"].id
        notice_id = notice.id
        expected_ids = sorted(cve.id for cve in notice.cves)

        response, statements = self._get(cve_id)

        assert response.status_code == 200
        assert len(statements) == 2, statements
        (served,) = [
            n for n in response.json["notices"] if n["id"] == notice_id
        ]
        assert sorted(served["cves_ids"]) == expected_ids
        assert "release_packages" in served
        assert response.json["notices_ids"] == [notice_id]
        assert response.json["packages"]

    def test_hidden_notices_are_left_out_unless_asked_for(self):
        notice = db.session.query(Notice).first()
        notice.is_hidden = True
        db.session.commit()
        cve_id = self.models["cve"].id
        notice_id = notice.id

        hidden, statements = self._get(cve_id)
        shown, _ = self._get(cve_id, "?show_hidden=true")

        assert len(statements) == 2, statements
        assert hidden.json["notices"] == []
        assert [n["id"] for n in shown.json["notices"]] == [notice_id]

    def test_cve_without_notices_takes_two_queries(self):
        db.session.add(make_cve(id="CVE-1999-3001", status="active"))
        db.session.commit()

        response, statements = self._get("CVE-1999-3001")

        assert response.status_code == 200
        assert response.json["notices"] == []
        assert len(statements) == 2, statements

    def test_missing_cve_takes_one_query(self):
        response, statements = self._get("CVE-1999-3999")

        assert response.status_code == 404
        assert len(statements) == 1, statements
