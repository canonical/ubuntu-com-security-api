import dateutil.parser
from marshmallow import Schema
from marshmallow.fields import (
    Boolean,
    DateTime,
    Dict,
    Float,
    List,
    Nested,
    String,
    Int,
)
from marshmallow.validate import Regexp

from webapp.database import (
    release_codenames,
    status_statuses,
    db_session,
    inspector,
)

# Types
# ===
from webapp.models import Package, Notice


class ParsedDateTime(DateTime):
    default_error_messages = {"parse_error": "dateutil cannot parse {input}."}

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            date = dateutil.parser.parse(value)
        except (OverflowError, ValueError):
            raise self.make_error("parse_error", input=value)

        return super()._deserialize(date.isoformat(), attr, data, **kwargs)


class ReleaseCodename(String):
    default_error_messages = {
        "unrecognised_codename": "Cannot find a release with codename {input}"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if value not in release_codenames:
            raise self.make_error("unrecognised_codename", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class Component(String):
    default_error_messages = {
        "unrecognised_component": "Component must be 'main' or 'universe'"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if value not in ["main", "universe"]:
            raise self.make_error("unrecognised_component", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class StatusStatuses(String):
    default_error_messages = {
        "unrecognised_status": "Cannot find a status with status {input}"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if value not in status_statuses:
            raise self.make_error("unrecognised_status", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class UniqueNoticeId(String):
    default_error_messages = {
        "notice_id_exists": "Notice with id '{input}' already exists"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        exists = False

        if "notice" in inspector.get_table_names():
            exists = (
                db_session.query(Notice.id).filter_by(id=value).scalar()
                is not None
            )

        if exists:
            raise self.make_error("notice_id_exists", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class PackageName(String):
    default_error_messages = {
        "unrecognised_package_name": "No CVEs with package '{input}' found"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        exists = False

        if "package" in inspector.get_table_names():
            exists = (
                db_session.query(Package.name)
                .filter_by(name=value)
                .one_or_none()
                is not None
            )

        if not exists:
            raise self.make_error("unrecognised_package_name", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class Pocket(String):
    default_error_messages = {
        "unrecognised_component": (
            "Pocket must be one of "
            "'security', 'updates', 'esm-infra', 'esm-apps'"
        )
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if value not in ["security", "updates", "esm-infra", "esm-apps"]:
            raise self.make_error("unrecognised_pocket", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


# Schemas
# ===


# Notices
# --
class NoticePackage(Schema):
    name = String(required=True)
    version = String(required=True)
    description = String()
    is_source = Boolean(required=True)
    source_link = String(allow_none=True)
    version_link = String(allow_none=True)
    pocket = Pocket(required=False)


class NoticeSchema(Schema):
    id = String(required=True, validate=Regexp(r"(USN|LSN)-\d{1,5}-\d{1,2}"))
    title = String(required=True)
    summary = String(required=True)
    instructions = String(required=True)
    references = List(String())
    published = ParsedDateTime(required=True)
    description = String(allow_none=True)
    release_packages = Dict(
        keys=ReleaseCodename(),
        values=List(Nested(NoticePackage), required=True),
    )


class NoticeImportSchema(NoticeSchema):
    cves = List(String(validate=Regexp(r"(cve-|CVE-)\d{4}-\d{4,7}")))


class CreateNoticeImportSchema(NoticeImportSchema):
    id = UniqueNoticeId(
        required=True, validate=Regexp(r"(USN|LSN)-\d{1,5}-\d{1,2}")
    )


class NoticeAPISchema(NoticeSchema):
    type = String()
    cves_ids = List(
        String(validate=Regexp(r"(cve-|CVE-)\d{4}-\d{4,7}")), data_key="cves"
    )


class NoticesAPISchema(Schema):
    notices = List(Nested(NoticeAPISchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()


NoticesParameters = {
    "details": String(
        description=(
            "Any string - Selects notices that have either "
            "id, details or cves.id matching it"
        ),
        allow_none=True,
    ),
    "release": ReleaseCodename(
        enum=release_codenames,
        description="List of release codenames",
        allow_none=True,
    ),
    "limit": Int(
        description="Number of CVEs per response. Defaults to 20.",
        allow_none=True,
    ),
    "offset": Int(
        description="Number of CVEs to omit from response. Defaults to 0.",
        allow_none=True,
    ),
    "order": String(
        enum=["oldest"],
        description=(
            "Select order: choose `oldest` for ASC order; "
            "leave empty for DESC order"
        ),
        allow_none=True,
    ),
}


# Release
# --
class ReleaseSchema(Schema):
    name = String(required=True)
    version = String(required=True)
    codename = String(required=True)
    lts = Boolean(required=True)
    development = Boolean(required=True)
    release_date = ParsedDateTime(required=True)
    esm_expires = ParsedDateTime(required=True)
    support_expires = ParsedDateTime(required=True)


class ReleaseAPISchema(ReleaseSchema):
    support_tag = String()


# CVEs
# --
class Status(Schema):
    release_codename = ReleaseCodename(required=True)
    status = StatusStatuses(required=True)
    description = String(allow_none=True)
    component = Component(required=False)
    pocket = Pocket(required=False)


class CvePackage(Schema):
    name = String(required=True)
    source = String(required=True)
    ubuntu = String(required=True)
    debian = String(required=True)
    statuses = List(Nested(Status))


class Note(Schema):
    author = String(required=True)
    note = String(required=True)


class CVESchema(Schema):
    id = String(required=True)
    published = ParsedDateTime(allow_none=True)
    description = String(allow_none=True)
    ubuntu_description = String(allow_none=True)
    notes = List(Nested(Note))
    priority = String(allow_none=True)
    status = String(allow_none=True)
    cvss3 = Float(allow_none=True)
    references = List(String())
    bugs = List(String())
    patches = Dict(
        keys=String(),
        values=List(String(), required=False),
        allow_none=True,
    )
    tags = Dict(
        keys=String(),
        values=List(String(), required=False),
        allow_none=True,
    )


class CVEImportSchema(CVESchema):
    packages = List(Nested(CvePackage))


class CVEAPISchema(CVESchema):
    package_statuses = List(Nested(CvePackage), data_key="packages")
    notices_ids = List(
        String(validate=Regexp(r"(USN|LSN)-\d{1,5}-\d{1,2}")),
        data_key="notices",
    )


class CVEsAPISchema(Schema):
    cves = List(Nested(CVEAPISchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()


CVEsParameters = {
    "q": String(
        description=(
            "Any string -  Selects CVEs that have either "
            "id, description or ubuntu_description matching it"
        ),
        allow_none=True,
    ),
    "priority": String(
        description="CVE priority",
        enum=["unknown", "negligible", "low", "medium", "high", "critical"],
        allow_none=True,
    ),
    "package": PackageName(description="Package name", allow_none=True),
    "limit": Int(
        description="Number of CVEs per response. Defaults to 20.",
        allow_none=True,
    ),
    "offset": Int(
        description="Number of CVEs to omit from response. Defaults to 0.",
        allow_none=True,
    ),
    "component": Component(
        allow_none=True,
        enum=["main", "universe"],
        description="Package component",
    ),
    "version": List(
        ReleaseCodename(enum=release_codenames),
        description="List of release codenames ",
        allow_none=True,
    ),
    "status": List(
        StatusStatuses(enum=status_statuses),
        description="List of statuses",
        allow_none=True,
    ),
    "order": String(
        enum=["oldest"],
        description=(
            "Select order: choose `oldest` for ASC order; "
            "leave empty for DESC order"
        ),
        allow_none=True,
    ),
}


class MessageSchema(Schema):
    message = String()


class MessageWithErrorsSchema(Schema):
    message = String()
    errors = String()
