from unittest.mock import MagicMock

mocked_inspector = MagicMock()
mocked_inspector.get_table_names = MagicMock(
    return_value=["package", "release", "notice", "cve", "status"]
)

mocked_release_codenames = ["bionic", "focal", "xenial"]
mocked_status_statuses = [
    "released",
    "DNE",
    "needed",
    "not-affected",
    "deferred",
    "needs-triage",
    "ignored",
    "pending",
]
