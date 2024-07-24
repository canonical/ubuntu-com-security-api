from click.testing import CliRunner
import unittest

from tests import BaseTestCase, db
from webapp.commands import insert_numerical_cve_ids
from webapp.models import CVE


class TestCommands(BaseTestCase):
    runner = CliRunner()

    def test_upsert_numerical_cve_ids(self):
        """
        Numerical CVE ids should be inserted correctly
        """
        result = self.runner.invoke(insert_numerical_cve_ids)
        assert result.exit_code == 0

        # Check that the numerical cve id was inserted
        new_cve = (
            db.session.query(CVE).filter(CVE.id == "CVE-1111-0001").first()
        )
        assert new_cve.numerical_id == int("11110001")


if __name__ == "__main__":
    unittest.main()
