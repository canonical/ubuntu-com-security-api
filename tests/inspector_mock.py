from unittest.mock import MagicMock

from sqlalchemy.engine.reflection import Inspector

from webapp.database import db_engine

mocked_inspector = Inspector.from_engine(db_engine)

mocked_inspector.get_table_names = MagicMock(
    return_value=["package", "release", "notice", "cve", "status"]
)

mocked_inspector.get_enums = [
    {
        "name": "statuses",
        "labels": [
            "released",
            "DNE",
            "needed",
            "not-affected",
            "deferred",
            "needs-triage",
            "ignored",
            "pending",
        ],
    }
]
