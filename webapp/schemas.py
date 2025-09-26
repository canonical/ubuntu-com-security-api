import dateutil.parser
import orjson

from marshmallow import Schema, ValidationError
from marshmallow.fields import (
    Boolean,
    DateTime,
    Dict,
    Float,
    List,
    Nested,
    String,
    Int,
    Pluck,
)
from marshmallow.validate import Regexp, Range

from webapp.models import Package, Notice, Release
from webapp.types import (
    STATUS_STATUSES,
    COMPONENT_OPTIONS,
    POCKET_OPTIONS,
    PACKAGE_TYPE_OPTIONS,
    PRIORITY_OPTIONS,
)


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
        release_codenames = [
            release.codename for release in Release.query.all()
        ]
        if value != "" and value not in release_codenames:
            raise self.make_error("unrecognised_codename", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class Component(String):
    default_error_messages = {
        "unrecognised_component": "Unrecognised component"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if value not in COMPONENT_OPTIONS.enums:
            raise self.make_error("unrecognised_component", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class StatusStatuses(String):
    default_error_messages = {
        "unrecognised_status": "Cannot find a status with status {input}"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if value != "" and value not in STATUS_STATUSES.enums:
            raise self.make_error("unrecognised_status", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class Priority(String):
    default_error_messages = {
        "unrecognised_priority": "Unrecognized priority {input}"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if value not in PRIORITY_OPTIONS.enums:
            raise self.make_error("unrecognised_priority", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class UniqueNoticeId(String):
    default_error_messages = {
        "notice_id_exists": "Notice with id '{input}' already exists"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if Notice.query.get(value):
            raise self.make_error("notice_id_exists", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class UniqueReleaseCodename(String):
    default_error_messages = {
        "release_codename_exists": (
            "Release with codename '{input}' already exists"
        )
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if Release.query.get(value):
            raise self.make_error("release_codename_exists", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class UniqueReleaseVersion(String):
    default_error_messages = {
        "release_version_exists": (
            "Release with version '{input}' already exists"
        )
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if Release.query.get(value):
            raise self.make_error("release_version_exists", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class UniqueReleaseName(String):
    default_error_messages = {
        "release_name_exists": ("Release with name '{input}' already exists")
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if Release.query.get(value):
            raise self.make_error("release_name_exists", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class PackageName(String):
    default_error_messages = {
        "unrecognised_package_name": "No CVEs with package '{input}' found"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if not Package.query.get(value):
            raise self.make_error("unrecognised_package_name", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class Pocket(String):
    default_error_messages = {"unrecognised_pocket": "Unrecognised pocket"}

    def _deserialize(self, value, attr, data, **kwargs):
        if value not in POCKET_OPTIONS.enums:
            raise self.make_error("unrecognised_pocket", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class PackageType(String):
    default_error_messages = {
        "unrecognised_package_type": "Unrecognised pacakge type"
    }

    def _deserialize(self, value, attr, data, **kwargs):
        if value not in PACKAGE_TYPE_OPTIONS:
            raise self.make_error("unrecognised_package_type", input=value)

        return super()._deserialize(value, attr, data, **kwargs)


class StringDelimitedList(String):
    """
    Support lists of strings that are delimited by commas e.g
    "foo,bar" -> ["foo", "bar",]
    """

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return value.split(",")
        except AttributeError:
            raise ValidationError(
                f"{attr} is not a string delimited list.\n value: {value}."
            )


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
    pocket = Pocket()
    package_type = PackageType()
    channel = String(allow_none=True)

    class Meta:
        render_module = orjson


class NoticeSchema(Schema):
    id = String(
        required=True,
        validate=Regexp(r"(USN|LSN|SSN)-\d{1,5}-\d{1,2}"),
    )
    title = String(required=True)
    summary = String(required=True)
    instructions = String(required=True)
    references = List(String())
    published = ParsedDateTime(required=True)
    details = String(allow_none=True, data_key="description")
    is_hidden = Boolean(required=False)
    release_packages = Dict(
        keys=String(),
        values=List(Nested(NoticePackage), required=True),
    )

    class Meta:
        render_module = orjson


class NoticeImportSchema(NoticeSchema):
    cves = List(String(validate=Regexp(r"(cve-|CVE-)\d{4}-\d{4,7}")))

    class Meta:
        render_module = orjson


class CreateNoticeImportSchema(NoticeImportSchema):
    id = UniqueNoticeId(
        required=True, validate=Regexp(r"(USN|LSN|SSN)-\d{1,5}-\d{1,2}")
    )

    class Meta:
        render_module = orjson


class NoticeAPISchema(NoticeSchema):
    notice_type = String(data_key="type")
    cves_ids = List(String(validate=Regexp(r"(cve-|CVE-)\d{4}-\d{4,7}")))


NoticeParameters = {
    "show_hidden": Boolean(
        description=(
            "True or False if you want to select hidden notices. "
            "Default is `false`."
        ),
        allow_none=True,
    ),
}

NoticesParameters = {
    "details": String(
        description=(
            "Any string - Selects notices that have either "
            "id, details or cves.id matching it."
        ),
        allow_none=True,
    ),
    "cve_id": String(
        description="CVE ID to filter notices by.", allow_none=True
    ),
    "cves": StringDelimitedList(
        description="Comma-separated list of CVE IDs to filter notices by.",
        allow_none=True,
    ),
    "release": String(
        description="Ubuntu release codename to filter notices by."
        'example: `"noble"`.',
        allow_none=True,
    ),
    "limit": Int(
        validate=Range(min=1, max=20),
        description="Number of Notices per response."
        "Defaults to `10`. Max `20`.",
        allow_none=True,
        load_default=10,
    ),
    "offset": Int(
        description="Number of Notices to omit from response."
        "Defaults to `0`.",
        allow_none=True,
        load_default=0,
    ),
    "order": String(
        validate=lambda x: x in ["oldest", "newest"],
        description=(
            "Select order: choose `oldest` for ASC order; "
            "`newest` for DESC order. Default is `newest`."
        ),
        load_default="newest",
        allow_none=True,
    ),
    "show_hidden": Boolean(
        description=(
            "True or False if you want to select hidden notices. "
            "Default is `false`."
        ),
        load_default=False,
        allow_none=True,
    ),
}

PageNoticesParameters = {
    "details": String(
        description=(
            "Any string - Selects notices that have either "
            "id, details or cves.id matching it."
        ),
        allow_none=True,
    ),
    "cve_id": String(
        description="CVE ID to filter notices by.", allow_none=True
    ),
    "cves": StringDelimitedList(
        description="Comma-separated list of CVE IDs to filter notices by.",
        allow_none=True,
    ),
    "release": List(
        String(),
        description="List of release codenames ",
        allow_none=True,
    ),
    "limit": Int(
        validate=Range(min=1, max=20),
        description="Number of Notices per response."
        "Defaults to `10`. Max `20`.",
        allow_none=True,
        load_default=10,
    ),
    "offset": Int(
        description="Number of Notices to omit from response."
        "Defaults to `0`.",
        allow_none=True,
        load_default=0,
    ),
    "order": String(
        validate=lambda x: x in ["oldest", "newest"],
        description=(
            "Select order: choose `oldest` for ASC order; "
            "`newest` for DESC order. Default is `newest`."
        ),
        load_default="newest",
        allow_none=True,
    ),
    "show_hidden": Boolean(
        description=(
            "True or False if you want to select hidden notices. "
            "Default is `false`."
        ),
        load_default=False,
        allow_none=True,
    ),
}

FlatNoticesParameters = {
    "details": String(
        description=(
            "Any string - Selects notices that have either "
            "id, details or cves.id matching it."
        ),
        allow_none=True,
    ),
    "release": List(
        String(),
        description="List of release codenames ",
        allow_none=True,
    ),
    "limit": Int(
        validate=Range(min=1, max=20),
        description="Number of Notices per response."
        "Defaults to `10`. Max `20`.",
        allow_none=True,
        load_default=10,
    ),
    "offset": Int(
        description="Number of Notices to omit from response."
        "Defaults to `0`.",
        allow_none=True,
        load_default=0,
    ),
    "order": String(
        validate=lambda x: x in ["oldest", "newest"],
        description=(
            "Select order: choose `oldest` for ASC order; "
            "`newest` for DESC order. Default is `newest`."
        ),
        load_default="newest",
        allow_none=True,
    ),
}

NoticeSitemapParameters = {
    "limit": Int(
        validate=Range(min=1, max=100),
        description="Number of Notices per response. Defaults to 10. Max 100.",
        allow_none=True,
    ),
    "offset": Int(
        description="Number of Notices to omit from response. Defaults to 0.",
        allow_none=True,
    ),
}


# Release
# --
class ReleaseSchema(Schema):
    name = UniqueReleaseName(required=True)
    version = UniqueReleaseVersion(required=True)
    codename = UniqueReleaseCodename(required=True)
    lts = Boolean(required=True)
    development = Boolean(required=True)
    release_date = ParsedDateTime(required=True)
    esm_expires = ParsedDateTime(required=True)
    support_expires = ParsedDateTime(required=True)

    class Meta:
        render_module = orjson


class UpdateReleaseSchema(Schema):
    name = String(required=True)
    version = String(required=True)
    codename = String(required=True)
    lts = Boolean(required=True)
    development = Boolean(required=True)
    release_date = ParsedDateTime(required=True)
    esm_expires = ParsedDateTime(required=True)
    support_expires = ParsedDateTime(required=True)

    class Meta:
        render_module = orjson


class ReleaseAPISchema(ReleaseSchema):
    support_tag = String()

    class Meta:
        render_module = orjson


class ReleasesAPISchema(Schema):
    releases = List(Nested(ReleaseAPISchema))

    class Meta:
        render_module = orjson


# CVEs
# --
class Status(Schema):
    release_codename = String(required=True)
    status = StatusStatuses(required=True)
    description = String(allow_none=True)
    component = Component(allow_none=True)
    pocket = Pocket(allow_none=True)

    class Meta:
        render_module = orjson


class CvePackage(Schema):
    name = String(required=True)
    source = String(required=True)
    ubuntu = String(required=True)
    debian = String(required=True)
    statuses = List(Nested(Status))

    class Meta:
        render_module = orjson


class CvssV3(Schema):
    version = String(allow_none=True)
    vectorString = String(allow_none=True)
    attackVector = String(allow_none=True)
    attackComplexity = String(allow_none=True)
    privilegesRequired = String(allow_none=True)
    userInteraction = String(allow_none=True)
    scope = String(allow_none=True)
    confidentialityImpact = String(allow_none=True)
    integrityImpact = String(allow_none=True)
    availabilityImpact = String(allow_none=True)
    baseScore = Float(allow_none=True)
    baseSeverity = String(allow_none=True)

    class Meta:
        render_module = orjson


class CveBaseMetric(Schema):
    cvssV3 = Nested(CvssV3)
    exploitabilityScore = Float(allow_none=True)
    impactScore = Float(allow_none=True)

    class Meta:
        render_module = orjson


class CvssV4(Schema):
    version = String(allow_none=True)
    vectorString = String(allow_none=True)
    attackVector = String(allow_none=True)
    attackComplexity = String(allow_none=True)
    attackRequirements = String(allow_none=True)
    privilegesRequired = String(allow_none=True)
    userInteraction = String(allow_none=True)
    vulnerableSystemConfidentialityImpact = String(allow_none=True)
    vulnerableSystemIntegrityImpact = String(allow_none=True)
    vulnerableSystemAvailabilityImpact = String(allow_none=True)
    subsequentSystemConfidentialityImpact = String(allow_none=True)
    subsequentSystemIntegrityImpact = String(allow_none=True)
    subsequentSystemAvailabilityImpact = String(allow_none=True)
    baseScore = Float(allow_none=True)
    baseSeverity = String(allow_none=True)

    class Meta:
        render_module = orjson

class CveBaseMetricV4(Schema):
    cvssV4 = Nested(CvssV4)

    class Meta:
        render_module = orjson

class CveImpact(Schema):
    baseMetricV3 = Nested(CveBaseMetric)
    baseMetricV4 = Nested(CveBaseMetricV4)

    class Meta:
        render_module = orjson


class Note(Schema):
    author = String(required=True)
    note = String(required=True)

    class Meta:
        render_module = orjson


class CVESchema(Schema):
    id = String(required=True)
    published = ParsedDateTime(allow_none=True)
    updated_at = ParsedDateTime(allow_none=True)
    description = String(allow_none=True)
    ubuntu_description = String(allow_none=True)
    notes = List(Nested(Note))
    codename = String(allow_none=True)
    priority = String(allow_none=True)
    cvss3 = Float(allow_none=True)
    impact = Nested(CveImpact)
    status = String(allow_none=True)
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

    class Meta:
        render_module = orjson


class CVEImportSchema(CVESchema):
    packages = List(Nested(CvePackage))

    class Meta:
        render_module = orjson


class CVEAPISchema(CVESchema):
    package_statuses = List(Nested(CvePackage), data_key="packages")
    notices_ids = List(
        String(validate=Regexp(r"(USN|LSN|SSN)-\d{1,5}-\d{1,2}")),
    )

    class Meta:
        render_module = orjson


class RelatedNoticesSchema(Schema):
    id = String()
    packages = String()

    class Meta:
        render_module = orjson


class NoticeReleasesSchema(Schema):
    codename = String()
    version = String()
    support_tag = String()

    class Meta:
        render_module = orjson


class NoticeAPIDetailedSchema(NoticeAPISchema):
    cves = List(Nested(CVEAPISchema))
    related_notices = List(Nested(RelatedNoticesSchema))
    releases = List(Nested(NoticeReleasesSchema))

    class Meta:
        render_module = orjson


class CVESummaryV2(Schema):
    id = String()
    notices_ids = List(String())

    class Meta:
        render_module = orjson


class ReleasedCVEAPISchema(Schema):
    id = String(required=True)
    description = String(allow_none=True)
    codename = String(allow_none=True)
    priority = String(allow_none=True)
    published = ParsedDateTime(allow_none=True)
    updated_at = ParsedDateTime(allow_none=True)
    references = List(String())
    bugs = List(String())
    patches = Dict(
        keys=String(),
        values=List(String(), required=False),
        allow_none=True,
    )

    class Meta:
        render_module = orjson


class ReleasedCVEsAPISchema(CVESchema):
    cves = List(Nested(ReleasedCVEAPISchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()

    class Meta:
        render_module = orjson


class NoticeAPIDetailedSchemaV2(NoticeSchema):
    notice_type = String(data_key="type")
    cves = List(Nested(CVESummaryV2))
    cves_ids = List(String(validate=Regexp(r"(cve-|CVE-)\d{4}-\d{4,7}")))
    releases = List(Nested(NoticeReleasesSchema))
    related_notices = Pluck(RelatedNoticesSchema, "id", many=True)

    class Meta:
        render_module = orjson


class PageNoticeAPISchema(Schema):
    id = String(
        required=True,
        validate=Regexp(r"(USN|LSN|SSN)-\d{1,5}-\d{1,2}"),
    )
    cves_ids = List(String(validate=Regexp(r"(cve-|CVE-)\d{4}-\d{4,7}")))
    published = ParsedDateTime(required=True)
    summary = String(required=True)
    notice_type = String(data_key="type")
    releases = List(Nested(NoticeReleasesSchema))
    title = String(required=True)
    details = String(allow_none=True, data_key="description")

    class Meta:
        render_module = orjson


class PageNoticesAPISchema(Schema):
    notices = List(Nested(PageNoticeAPISchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()

    class Meta:
        render_module = orjson


class SitemapsCVESchema(Schema):
    id = String(required=True)
    published = ParsedDateTime(allow_none=True)

    class Meta:
        render_module = orjson


class SitemapCVEsAPISchema(Schema):
    cves = List(Nested(SitemapsCVESchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()

    class Meta:
        render_module = orjson


class SitemapsNoticeSchema(Schema):
    id = String(required=True)
    published = ParsedDateTime(allow_none=True)

    class Meta:
        render_module = orjson


class SitemapNoticesAPISchema(Schema):
    notices = List(Nested(SitemapsNoticeSchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()

    class Meta:
        render_module = orjson


class FlatNoticeSchema(Schema):
    id = String(
        required=True,
        validate=Regexp(r"(USN|LSN|SSN)-\d{1,5}-\d{1,2}"),
    )
    title = String(required=True)
    published = ParsedDateTime(required=True)
    details = String(allow_none=True, data_key="description")
    cves_ids = List(String(validate=Regexp(r"(cve-|CVE-)\d{4}-\d{4,7}")))

    class Meta:
        render_module = orjson


class FlatNoticesAPISchema(Schema):
    notices = List(Nested(FlatNoticeSchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()

    class Meta:
        render_module = orjson


class CVEAPIDetailedSchema(CVEAPISchema):
    notices = List(Nested(NoticeAPISchema))

    class Meta:
        render_module = orjson


class NoticesAPISchema(Schema):
    notices = List(Nested(NoticeAPIDetailedSchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()

    class Meta:
        render_module = orjson


class NoticesAPISchemaV2(Schema):
    notices = List(Nested(NoticeAPIDetailedSchemaV2))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()

    class Meta:
        render_module = orjson


class CVEsAPISchema(Schema):
    cves = List(Nested(CVEAPIDetailedSchema))
    offset = Int(allow_none=True)
    limit = Int(allow_none=True)
    total_results = Int()

    class Meta:
        render_module = orjson


CVEParameter = {
    "show_hidden": Boolean(
        description=(
            "True or False if you want to select hidden notices. "
            "Default is False."
        ),
        allow_none=True,
    ),
}

CVESitemapParameters = {
    "limit": Int(
        validate=Range(min=1, max=100),
        description="Number of CVEs per response. Defaults to 10. Max 100.",
        allow_none=True,
    ),
    "offset": Int(
        description="Number of CVEs to omit from response. Defaults to 0.",
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
    "priority": List(
        Priority(),
        description="CVE priority",
        allow_none=True,
    ),
    "package": String(description="Package name", allow_none=True),
    "limit": Int(
        validate=Range(min=1, max=20),
        description="Number of CVEs per response. Defaults to 10. Max 20.",
        allow_none=True,
    ),
    "offset": Int(
        description="Number of CVEs to omit from response. Defaults to 0.",
        allow_none=True,
    ),
    "component": List(
        Component(),
        allow_none=True,
        description="Package component",
    ),
    "version": List(
        String(),
        description="List of release codenames ",
        allow_none=True,
    ),
    "cve_status": String(
        description="CVE status",
        enum=["not-in-ubuntu", "active", "rejected"],
        allow_none=True,
    ),
    "status": List(
        StatusStatuses(),
        description="List of package statuses",
        allow_none=True,
    ),
    "order": String(
        load_default="descending",
        enum=["oldest, descending, ascending"],
        description=(
            "Select `ascending` or `oldest` (depreciated) for ASC order;"
            "leave empty for descending order"
        ),
    ),
    "group_by": String(
        enum=["priority"],
        description=(
            "Select `priority` to group CVEs by highest to lowest priority"
        ),
        allow_none=True,
    ),
    "sort_by": String(
        load_default="published",
        enum=["updated", "published"],
        description=(
            "Select `updated` to sort by most recently updated CVEs;"
            "leave empty to sort by publish date"
        ),
    ),
    "show_hidden": Boolean(
        description=(
            "True or False if you want to select hidden notices. "
            "Default is False."
        ),
        allow_none=True,
    ),
}

ReleasedCVEsParameters = {
    "package": String(description="Package name", allow_none=True),
    "limit": Int(
        validate=Range(min=1, max=20),
        description="Number of CVEs per response. Defaults to 10. Max 20.",
        allow_none=True,
    ),
    "offset": Int(
        description="Number of CVEs to omit from response. Defaults to 0.",
        allow_none=True,
    ),
    "version": List(
        String(),
        description="List of release codenames ",
        allow_none=True,
    ),
    "order": String(
        load_default="descending",
        enum=["oldest, descending, ascending"],
        description=(
            "Select `ascending` or `oldest` (depreciated) for ASC order;"
            "leave empty for descending order"
        ),
    ),
}


class MessageSchema(Schema):
    message = String()

    class Meta:
        render_module = orjson


class MessageWithErrorsSchema(Schema):
    message = String()
    errors = String()

    class Meta:
        render_module = orjson
