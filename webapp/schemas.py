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
from webapp.models import Package, Notice, Release


# Types
# ===


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
        if value != "" and value not in release_codenames:
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
        if value != "" and value not in status_statuses:
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
                db_session.query(Notice)
                .filter(Notice.id == value)
                .one_or_none()
                is not None
            )

        if exists:
            raise self.make_error("notice_id_exists", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class UniqueReleaseCodename(String):
    default_error_messages = {
        "release_codename_exists": (
            "Release with codename '{input}' already exists"
        )
    }

    def _deserialize(self, value, attr, data, **kwargs):
        exists = False

        if "release" in inspector.get_table_names():
            exists = (
                db_session.query(Release)
                .filter(Release.codename == value)
                .one_or_none()
                is not None
            )

        if exists:
            raise self.make_error("release_codename_exists", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class UniqueReleaseVersion(String):
    default_error_messages = {
        "release_version_exists": (
            "Release with version '{input}' already exists"
        )
    }

    def _deserialize(self, value, attr, data, **kwargs):
        exists = False

        if "release" in inspector.get_table_names():
            exists = (
                db_session.query(Release)
                .filter(Release.version == value)
                .one_or_none()
                is not None
            )

        if exists:
            raise self.make_error("release_version_exists", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class UniqueReleaseName(String):
    default_error_messages = {
        "release_name_exists": ("Release with name '{input}' already exists")
    }

    def _deserialize(self, value, attr, data, **kwargs):
        exists = False

        if "release" in inspector.get_table_names():
            exists = (
                db_session.query(Release)
                .filter(Release.name == value)
                .one_or_none()
                is not None
            )

        if exists:
            raise self.make_error("release_name_exists", input=value)

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
        "unrecognised_pocket": (
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
    is_visible = Boolean()
    source_link = String(allow_none=True)
    version_link = String(allow_none=True)
    pocket = Pocket(
        enum=["security", "updates", "esm-infra", "esm-apps"], required=False
    )


class NoticeSchema(Schema):
    id = String(required=True, validate=Regexp(r"(USN|LSN)-\d{1,5}-\d{1,2}"))
    title = String(required=True)
    summary = String(required=True)
    instructions = String(required=True)
    references = List(String())
    published = ParsedDateTime(required=True)
    details = String(allow_none=True, data_key="description")
    is_hidden = Boolean(required=False)
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
    notice_type = String(data_key="type")
    cves_ids = List(String(validate=Regexp(r"(cve-|CVE-)\d{4}-\d{4,7}")))


NoticeParameters = {
    "show_hidden": Boolean(
        description=(
            "True or False if you want to select hidden notices. "
            "Default is False."
        ),
        allow_none=True,
    ),
}

NoticesParameters = {
    "details": String(
        description=(
            "Any string - Selects notices that have either "
            "id, details or cves.id matching it"
        ),
        allow_none=True,
    ),
    "cve_id": String(allow_none=True),
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
    "show_hidden": Boolean(
        description=(
            "True or False if you want to select hidden notices. "
            "Default is False."
        ),
        allow_none=True,
    ),
}


# Release
# --
class ReleaseSchema(Schema):
    name = UniqueReleaseName(required=True)
    version = UniqueReleaseVersion(required=True)
    codename = UniqueReleaseCodename(enum=release_codenames, required=True)
    lts = Boolean(required=True)
    development = Boolean(required=True)
    release_date = ParsedDateTime(required=True)
    esm_expires = ParsedDateTime(required=True)
    support_expires = ParsedDateTime(required=True)


class UpdateReleaseSchema(Schema):
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


class ReleasesAPISchema(Schema):
    releases = List(Nested(ReleaseAPISchema))


# CVEs
# --
class Status(Schema):
    release_codename = ReleaseCodename(enum=release_codenames, required=True)
    status = StatusStatuses(enum=status_statuses, required=True)
    description = String(allow_none=True)
    component = Component(enum=["main", "universe"], required=False)
    pocket = Pocket(
        enum=["security", "updates", "esm-infra", "esm-apps"], required=False
    )


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
    mitigation = String(allow_none=True)
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
    )


class NoticeAPIDetailedSchema(NoticeAPISchema):
    cves = List(Nested(CVEAPISchema))


class CVEAPIDetailedSchema(CVEAPISchema):
    notices = List(Nested(NoticeAPISchema))


class NoticesAPISchema(Schema):
    notices = List(Nested(NoticeAPIDetailedSchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()


class CVEsAPISchema(Schema):
    cves = List(Nested(CVEAPIDetailedSchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()


CVEParameter = {
    "show_hidden": Boolean(
        description=(
            "True or False if you want to select hidden notices. "
            "Default is False."
        ),
        allow_none=True,
    ),
}

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
    "show_hidden": Boolean(
        description=(
            "True or False if you want to select hidden notices. "
            "Default is False."
        ),
        allow_none=True,
    ),
}


class MessageSchema(Schema):
    message = String()


class MessageWithErrorsSchema(Schema):
    message = String()
    errors = String()
