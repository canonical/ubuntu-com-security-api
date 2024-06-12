from collections import defaultdict
from datetime import datetime
from distutils.util import strtobool

from flask import make_response, jsonify, request
from flask_apispec import marshal_with, use_kwargs
from sqlalchemy import desc, or_, and_, case, asc
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import load_only, selectinload, Query
import dateutil

from webapp.app import db
from webapp.auth import authorization_required
from webapp.models import (
    CVE,
    Notice,
    Release,
    Status,
    Package,
    STATUS_STATUSES,
)
from webapp.schemas import (
    CVEsAPISchema,
    CVEsParameters,
    NoticesParameters,
    NoticesAPISchema,
    NoticeImportSchema,
    MessageSchema,
    MessageWithErrorsSchema,
    CreateNoticeImportSchema,
    CVEImportSchema,
    ReleaseSchema,
    NoticeParameters,
    CVEParameter,
    CVEAPIDetailedSchema,
    NoticeAPIDetailedSchema,
    ReleaseAPISchema,
    ReleasesAPISchema,
    UpdateReleaseSchema,
)


@marshal_with(CVEAPIDetailedSchema, code=200)
@marshal_with(MessageSchema, code=404)
@use_kwargs(CVEParameter, location="query")
def get_cve(cve_id, **kwargs):
    cve_query: Query = db.session.query(CVE)

    cve_notices_query = CVE.notices
    if not kwargs.get("show_hidden", False):
        cve_notices_query = cve_notices_query.and_(Notice.is_hidden == "False")

    cve: CVE = (
        cve_query.filter(CVE.id == cve_id.upper())
        .options(
            selectinload(cve_notices_query).options(
                selectinload(Notice.cves).options(load_only(CVE.id))
            )
        )
        .options(selectinload(CVE.statuses))
        .one_or_none()
    )

    if not cve:
        return make_response(
            jsonify({"message": f"CVE with id '{cve_id}' does not exist"}),
            404,
        )

    return cve


@marshal_with(CVEsAPISchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(CVEsParameters, location="query")
def get_cves(**kwargs):
    query = kwargs.get("q", "").strip()
    priorities = kwargs.get("priority")
    group_by = kwargs.get("group_by")
    package = kwargs.get("package")
    limit = kwargs.get("limit", 20)
    offset = kwargs.get("offset", 0)
    component = kwargs.get("component")
    versions = kwargs.get("version")
    cve_status = kwargs.get("cve_status")
    statuses = kwargs.get("status")
    order = kwargs.get("order")
    sort_by = kwargs.get("sort_by")
    show_hidden = kwargs.get("show_hidden", False)

    # query cves by filters. Default filter by active CVEs
    if cve_status:
        cves_query: Query = db.session.query(CVE).filter(
            CVE.status == cve_status
        )
    else:
        cves_query: Query = db.session.query(CVE).filter(
            CVE.status == "active"
        )

    # order by priority
    if group_by == "priority":
        cves_query = _sort_by_priority(cves_query)

    # filter by priority
    if priorities:
        cves_query = cves_query.filter(CVE.priority.in_(priorities))

    # filter by all text based fields
    if query:
        cves_query = cves_query.filter(
            or_(
                CVE.id.ilike(f"%{query}%"),
                CVE.description.ilike(f"%{query}%"),
                CVE.ubuntu_description.ilike(f"%{query}%"),
                CVE.codename.ilike(f"%{query}%"),
                CVE.mitigation.ilike(f"%{query}%"),
            )
        )

    # build CVE statuses filter parameters
    parameters = []

    cve_statuses_query = CVE.statuses

    should_filter_by_version_and_status = _should_filter_by_version_and_status(
        versions, statuses
    )

    if should_filter_by_version_and_status:
        parameters = _params_with_conditions(
            versions, statuses, parameters, package, component
        )

        # filter the CVEs that fulfill criteria
        cves_query = cves_query.filter(
            CVE.statuses.any(or_(*[p for p in parameters]))
        )

    else:
        # If an empty string is provided for the status,
        # retain legacy functionality by ignoring it
        if statuses:
            for status in statuses:
                if status == "":
                    continue
                else:
                    parameters.append(Status.status == status)

        if versions:
            for version in versions:
                parameters.append(Status.release_codename == version)

        # filter by package name
        if package:
            parameters.append(Status.package_name == package)

        # filter by component
        if component:
            parameters.append(Status.component == component)

        if parameters:
            if package:
                cves_query = cves_query.filter(
                    CVE.statuses.any(and_(*[p for p in parameters]))
                )
            else:
                cves_query = cves_query.filter(
                    CVE.statuses.any(or_(*[p for p in parameters]))
                )

    # filter the CVE statuses that fulfil creatia
    cve_statuses_query = cve_statuses_query.and_(*[p for p in parameters])

    cve_notices_query = CVE.notices
    if not show_hidden:
        cve_notices_query = cve_notices_query.and_(Notice.is_hidden == "False")

    if order in ("oldest", "ascending"):
        sort = asc
    elif order == "descending":
        sort = desc

    if sort_by == "published":
        sort_field = CVE.published
    elif sort_by == "updated":
        sort_field = CVE.updated_at

    query: Query = (
        cves_query.options(
            selectinload(cve_notices_query).options(
                selectinload(Notice.cves).options(load_only(CVE.id))
            )
        )
        .order_by(
            case(
                [(sort_field.is_(None), 1)],
                else_=0,
            ),
            sort(sort_field),
            sort(CVE.id),
        )
        .limit(limit)
        .offset(offset)
    )

    return {
        "cves": query.all(),
        "offset": offset,
        "limit": limit,
        "total_results": cves_query.count(),
    }


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=400)
@marshal_with(MessageSchema, code=413)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(CVEImportSchema(many=True), location="json")
def bulk_upsert_cve(*args, **kwargs):
    cves_data = request.json

    if len(cves_data) > 50:
        return make_response(
            jsonify(
                {
                    "message": (
                        "Please only submit up to 50 CVEs at a time. "
                        f"({len(cves_data)} submitted)"
                    )
                }
            ),
            413,
        )

    packages = {}
    for package in Package.query.all():
        packages[package.name] = package

    for data in cves_data:
        update_cve = False
        cve = CVE.query.get(data["id"].upper())

        if cve is None:
            update_cve = True
            cve = CVE(id=data["id"])

        if cve.status != data.get("status"):
            update_cve = True
            cve.status = data.get("status")

        published_date = (
            cve.published.strftime("%Y-%B-%d") if cve.published else None
        )
        data_published_date = (
            dateutil.parser.parse(data.get("published")).strftime("%Y-%B-%d")
            if data.get("published")
            else None
        )
        if published_date != data_published_date:
            update_cve = True
            cve.published = data.get("published")

        if cve.priority != data.get("priority"):
            update_cve = True
            cve.priority = data.get("priority")

        if cve.cvss3 != data.get("cvss3"):
            update_cve = True
            cve.cvss3 = data.get("cvss3")

        if cve.description != data.get("description"):
            update_cve = True
            cve.description = data.get("description")

        if cve.ubuntu_description != data.get("ubuntu_description"):
            update_cve = True
            cve.ubuntu_description = data.get("ubuntu_description")

        if cve.notes != data.get("notes"):
            update_cve = True
            cve.notes = data.get("notes")

        if cve.references != data.get("references"):
            update_cve = True
            cve.references = data.get("references")

        if cve.bugs != data.get("bugs"):
            update_cve = True
            cve.bugs = data.get("bugs")

        if cve.patches != data.get("patches"):
            update_cve = True
            cve.patches = data.get("patches")

        if cve.tags != data.get("tags"):
            update_cve = True
            cve.tags = data.get("tags")

        if cve.mitigation != data.get("mitigation"):
            update_cve = True
            cve.mitigation = data.get("mitigation")

        if cve.impact != data.get("impact"):
            update_cve = True
            cve.impact = data.get("impact")

        if cve.codename != data.get("codename"):
            update_cve = True
            cve.codename = data.get("codename")

        if update_cve:
            db.session.add(cve)

        _update_statuses(cve, data, packages)

    created = defaultdict(lambda: 0)
    updated = defaultdict(lambda: 0)
    deleted = defaultdict(lambda: 0)

    for item in db.session.new:
        created[type(item).__name__] += 1

    for item in db.session.dirty:
        updated[type(item).__name__] += 1

    for item in db.session.deleted:
        deleted[type(item).__name__] += 1

    try:
        db.session.commit()
    except DataError as error:
        return make_response(
            jsonify(
                {
                    "message": "Failed bulk upserting session",
                    "error": error.orig.args[0],
                }
            ),
            400,
        )

    return make_response(
        jsonify({"created": created, "updated": updated, "deleted": deleted}),
        200,
    )


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageSchema, code=404)
def delete_cve(cve_id):
    cve = CVE.query.get(cve_id.upper())

    if not cve:
        return make_response(
            jsonify({"message": f"CVE {cve_id} doesn't exist"}),
            404,
        )

    db.session.delete(cve)
    db.session.commit()

    return make_response(
        jsonify({"message": f"CVE with id '{cve_id}' was deleted"}), 200
    )


@marshal_with(NoticeAPIDetailedSchema, code=200)
@marshal_with(MessageSchema, code=404)
@use_kwargs(NoticeParameters, location="query")
def get_notice(notice_id, **kwargs):
    notice_query: Query = db.session.query(Notice)

    if not kwargs.get("show_hidden", False):
        notice_query = notice_query.filter_by(is_hidden=False)

    notice: Notice = (
        notice_query.filter(Notice.id == notice_id.upper())
        .options(
            selectinload(Notice.cves).options(
                selectinload(CVE.statuses),
                selectinload(CVE.notices).options(
                    load_only(
                        Notice.id, Notice.is_hidden, Notice.release_packages
                    )
                ),
            )
        )
        .options(selectinload(Notice.releases))
        .one_or_none()
    )

    if not notice:
        return make_response(
            jsonify(
                {"message": f"Notice with id '{notice_id}' does not exist"}
            ),
            404,
        )

    return notice


@marshal_with(NoticesAPISchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(NoticesParameters, location="query")
def get_notices(**kwargs):
    details = kwargs.get("details")
    cve_id = kwargs.get("cve_id")
    release = kwargs.get("release")
    limit = kwargs.get("limit", 20)
    offset = kwargs.get("offset", 0)
    order_by = kwargs.get("order")

    notices_query: Query = db.session.query(Notice)

    if not kwargs.get("show_hidden", False):
        notices_query = notices_query.filter(Notice.is_hidden == "False")

    if cve_id:
        notices_query = notices_query.filter(Notice.cves.any(CVE.id == cve_id))

    if release:
        notices_query = notices_query.join(Release, Notice.releases).filter(
            Release.codename == release
        )

    if details:
        notices_query = notices_query.filter(
            or_(
                Notice.id.ilike(f"%{details}%"),
                Notice.details.ilike(f"%{details}%"),
                Notice.title.ilike(f"%{details}%"),
                Notice.cves.any(CVE.id.ilike(f"%{details}%")),
            )
        )

    sort = asc if order_by == "oldest" else desc

    notices = (
        notices_query.options(
            selectinload(Notice.cves).options(
                selectinload(CVE.statuses),
                selectinload(CVE.notices).options(
                    load_only(
                        Notice.id, Notice.is_hidden, Notice.release_packages
                    )
                ),
            )
        )
        .options(selectinload(Notice.releases))
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "notices": notices,
        "offset": offset,
        "limit": limit,
        "total_results": notices_query.count(),
    }


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(CreateNoticeImportSchema, location="json")
def create_notice(**kwargs):
    notice_data = request.json

    db.session.add(
        _update_notice_object(Notice(id=notice_data["id"]), notice_data)
    )

    db.session.commit()

    return make_response(jsonify({"message": "Notice created"}), 200)


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=404)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(NoticeImportSchema, location="json")
def update_notice(notice_id, **kwargs):
    notice = Notice.query.get(notice_id)

    if not notice:
        return make_response(
            jsonify({"message": f"Notice '{notice_id}' doesn't exist"}),
            404,
        )

    notice = _update_notice_object(notice, request.json)

    db.session.add(notice)
    db.session.commit()

    return make_response(jsonify({"message": "Notice updated"}), 200)


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageSchema, code=404)
def delete_notice(notice_id):
    notice = Notice.query.get(notice_id)

    if not notice:
        return make_response(
            jsonify({"message": f"Notice {notice_id} doesn't exist"}),
            404,
        )

    db.session.delete(notice)
    db.session.commit()

    return make_response(
        jsonify({"message": f"Notice {notice_id} deleted"}), 200
    )


@marshal_with(ReleaseAPISchema, code=200)
@marshal_with(MessageSchema, code=404)
def get_release(release_codename):
    release = Release.query.get(release_codename)

    if not release:
        return make_response(
            jsonify({"message": f"Release {release_codename} doesn't exist"}),
            404,
        )

    return release


@marshal_with(ReleasesAPISchema, code=200)
@marshal_with(MessageSchema, code=404)
def get_releases():
    releases = Release.query.order_by(desc(Release.release_date))

    return {"releases": releases}


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(ReleaseSchema, location="json")
def create_release(**kwargs):
    release_data = request.json

    db.session.add(
        Release(
            codename=release_data["codename"],
            version=release_data["version"],
            name=release_data["name"],
            development=release_data["development"],
            lts=release_data["lts"],
            release_date=release_data["release_date"],
            esm_expires=release_data["esm_expires"],
            support_expires=release_data["support_expires"],
        )
    )
    db.session.commit()

    return make_response(jsonify({"message": "Release created"}), 200)


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageSchema, code=404)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(UpdateReleaseSchema, location="json")
def update_release(release_codename, **kwargs):
    release = Release.query.get(release_codename)

    if not release:
        return make_response(
            jsonify({"message": f"Release {release_codename} doesn't exist"}),
            404,
        )

    release_data = request.json
    release.version = release_data["version"]
    release.name = release_data["name"]
    release.development = release_data["development"]
    release.lts = release_data["lts"]
    release.release_date = release_data["release_date"]
    release.esm_expires = release_data["esm_expires"]
    release.support_expires = release_data["support_expires"]

    db.session.add(release)

    try:
        db.session.commit()
    except IntegrityError as error:
        return make_response(
            jsonify(
                {
                    "message": "Failed updating release",
                    "error": error.orig.args[0],
                }
            ),
            422,
        )

    return make_response(jsonify({"message": "Release updated"}), 200)


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageSchema, code=400)
@marshal_with(MessageSchema, code=404)
def delete_release(release_codename):
    release = Release.query.get(release_codename)

    if not release:
        return make_response(
            jsonify({"message": f"Release {release_codename} doesn't exist"}),
            404,
        )

    if len(release.statuses) > 0:
        return (
            jsonify(
                {
                    "message": (
                        f"Cannot delete '{release_codename}' release. "
                        f"Release already in use"
                    )
                }
            ),
            400,
        )

    db.session.delete(release)
    db.session.commit()

    return make_response(
        jsonify({"message": f"Release {release_codename} deleted"}), 200
    )


def _sort_by_priority(cves_query):
    priority_list = [
        "critical",
        "high",
        "medium",
        "low",
        "negligible",
        "unknown",
    ]

    priority_sorting = case(
        {_id: index for index, _id in enumerate(priority_list)},
        value=CVE.priority,
    )
    cves_query = cves_query.order_by(priority_sorting)

    return cves_query


def _params_with_conditions(
    versions, statuses, parameters, package, component
):
    conditions = []

    clean_versions = _get_clean_versions(versions)
    clean_statuses = _get_clean_statuses(statuses)

    # Add parent condition
    if versions or statuses:
        for key, sub_versions in enumerate(clean_versions):
            for key, sub_statuses in enumerate(clean_statuses):
                conditions.append(
                    and_(
                        Status.release_codename.in_(sub_versions),
                        Status.status.in_(sub_statuses),
                    )
                )

        parameters.append(or_(*[condition for condition in conditions]))

    if package or component:
        sub_conditions = []
        for key, sub_versions in enumerate(clean_versions):
            for key, sub_statuses in enumerate(clean_statuses):
                sub_conditions.append(
                    and_(
                        Status.release_codename.in_(sub_versions),
                        Status.status.in_(sub_statuses),
                    )
                )

        if package:
            sub_conditions.append(Status.package_name == package)

        if component:
            sub_conditions.append(Status.component == component)

        condition = CVE.statuses.any(
            and_(*[sub_condition for sub_condition in sub_conditions])
        )

        conditions.append(condition)

        parameters.append(and_(*[condition for condition in conditions]))

    return parameters


def _get_clean_statuses(statuses) -> list:
    """
    Response: Returns a array of `status` arrays

    User can provide multiple `version` and `status` parameters.
    We group one `version` and one `status` together by matching their position
    in the arrays.

    The query checks for `CVEs.statuses` that matches each group of
    `version-status`.

    E.g.::

        and_(
            Status.release_codename.in_(versions),
            Status.status.in_(statuses),
        )

    We return an array of 'status' arrays for the case where users
    provide "" (Any) as a value for the 'status'.
    'Any' means user wants all statuses
    """

    clean_statuses = []

    for status in statuses:
        if status != "" and status in STATUS_STATUSES.enums:
            clean_statuses.append([status])
        else:
            clean_statuses.append(STATUS_STATUSES.enums)

    return clean_statuses


def _get_clean_versions(versions) -> list:
    """
    Response: Returns a array of `version` arrays

    User can provide multiple `version` and `status` parameters.
    We group one `version` and one `status` together by matching their position
    in the arrays.

    The query checks for `CVEs.statuses` that matches each group of
    `version-status`.

    E.g.::

        and_(
            Status.release_codename.in_(versions),
            Status.status.in_(statuses),
        )

    We return an array of 'version' arrays for the case where users
    provide "" (Any) as a value for the 'version'.
    'Any' means user wants all versions that are still supported
    """

    clean_versions = []

    for version in versions:
        if version not in ["", "current"]:
            clean_versions.append([version])
        else:
            releases_query = Release.query.filter(
                or_(
                    Release.support_expires > datetime.now(),
                    Release.esm_expires > datetime.now(),
                )
            ).filter(Release.codename != "upstream")

            releases = releases_query.order_by(Release.release_date).all()

            clean_versions.append([release.codename for release in releases])

    return clean_versions


def _should_filter_by_version_and_status(versions, statuses) -> bool:
    """
    Returns True if filtering by versions or
    statuses
    """

    return versions and statuses


def _update_notice_object(notice, data):
    """
    Set fields on a Notice model object
    """
    notice.title = data["title"]
    notice.summary = data["summary"]
    notice.details = data["description"]
    notice.release_packages = data["release_packages"]
    notice.published = data["published"]
    notice.references = data["references"]
    notice.instructions = data["instructions"]
    notice.is_hidden = strtobool(data.get("is_hidden", "false"))

    notice.releases = [
        Release.query.get(codename)
        for codename in data["release_packages"].keys()
    ]

    notice.cves.clear()
    for cve_id in set(data["cves"]):
        notice.cves.append(CVE.query.get(cve_id) or CVE(id=cve_id))

    return notice


def _update_statuses(cve, data, packages):
    statuses = cve.packages

    statuses_to_check = Status.query.filter(Status.cve_id == cve.id).all()

    statuses_to_delete = {
        f"{v.package_name}||{v.release_codename}": v for v in statuses_to_check
    }

    for package_data in data.get("packages", []):
        name = package_data["name"]

        if packages.get(name) is None:
            package = Package(name=name)
            package.source = package_data["source"]
            package.ubuntu = package_data["ubuntu"]
            package.debian = package_data["debian"]
            packages[name] = package

            db.session.add(package)

        for status_data in package_data["statuses"]:
            update_status = False
            codename = status_data["release_codename"]

            status = statuses[name].get(codename)
            if status is None:
                update_status = True
                status = Status(
                    cve_id=cve.id, package_name=name, release_codename=codename
                )
            elif f"{name}||{codename}" in statuses_to_delete:
                del statuses_to_delete[f"{name}||{codename}"]

            if status.status != status_data["status"]:
                update_status = True
                status.status = status_data["status"]

            if status.description != status_data["description"]:
                update_status = True
                status.description = status_data["description"]

            if status.component != status_data.get("component"):
                update_status = True
                status.component = status_data.get("component")

            if status.pocket != status_data.get("pocket"):
                update_status = True
                status.pocket = status_data.get("pocket")

            if update_status:
                statuses[name][codename] = status
                db.session.add(status)

    for key in statuses_to_delete:
        db.session.delete(statuses_to_delete[key])
