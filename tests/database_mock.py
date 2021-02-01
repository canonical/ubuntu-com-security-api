from unittest.mock import MagicMock

mocked_inspector = MagicMock()
mocked_inspector.get_table_names = MagicMock(
    return_value=["package", "release", "notice", "cve", "status"]
)

mocked_release_codenames = ["bionic", "focal"]
mocked_status_statuses = [
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
