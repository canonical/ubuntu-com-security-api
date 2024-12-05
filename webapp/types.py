"""
Defines common types used in schemas and models.
"""

from sqlalchemy import Enum

STATUS_STATUSES = Enum(
    "released",
    "DNE",
    "needed",
    "not-affected",
    "deferred",
    "needs-triage",
    "ignored",
    "pending",
    name="statuses",
)

COMPONENT_OPTIONS = Enum("main", "universe", name="components")

POCKET_OPTIONS = Enum(
    "security",
    "updates",
    "esm-infra",
    "esm-infra-legacy",
    "esm-apps",
    "soss",
    "fips",
    "fips-updates",
    "ros-esm",
    "realtime",
    name="pockets",
)

PACKAGE_TYPE_OPTIONS = [
    "python",
    "conda",
    "golang",
    "unpackaged",
    "deb",
]

PRIORITY_OPTIONS = Enum(
    "unknown",
    "negligible",
    "low",
    "medium",
    "high",
    "critical",
    name="priorities",
)

CVE_STATUSES = Enum(
    "not-in-ubuntu",
    "in-progress",
    "rejected",
    name="cve_statuses",
)
