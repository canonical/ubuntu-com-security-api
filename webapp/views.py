from collections import defaultdict
from datetime import datetime

from flask import make_response, jsonify, request
from flask_apispec import marshal_with, use_kwargs
from sqlalchemy import desc, or_, func, and_, case, asc
from sqlalchemy.exc import DataError
from sqlalchemy.orm import contains_eager

from webapp.auth import authorization_required
from webapp.database import db_session, status_statuses
from webapp.models import CVE, Notice, Release, Status, Package
from webapp.schemas import (
    CVEAPISchema,
    NoticeAPISchema,
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
)


@marshal_with(CVEAPISchema, code=200)
@marshal_with(MessageSchema, code=404)
def get_cve(cve_id):
    cve = db_session.query(CVE).filter(CVE.id == cve_id).one_or_none()

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
    priority = kwargs.get("priority")
    package = kwargs.get("package")
    limit = kwargs.get("limit", 20)
    offset = kwargs.get("offset", 0)
    component = kwargs.get("component")
    versions = kwargs.get("version")
    statuses = kwargs.get("status")
    order_by = kwargs.get("order")

    clean_versions = _get_clean_versions(statuses, versions)
    clean_statuses = _get_clean_statuses(statuses, versions)

    # query cves by filters
    cves_query = db_session.query(
        CVE, func.count("*").over().label("total")
    ).filter(CVE.status == "active")

    # filter by priority
    if priority:
        cves_query = cves_query.filter(CVE.priority == priority)

    # filter by description or CVE id
    if query:
        cves_query = cves_query.filter(
            or_(
                CVE.id.ilike(f"%{query}%"),
                CVE.description.ilike(f"%{query}%"),
                CVE.ubuntu_description.ilike(f"%{query}%"),
            )
        )

    # build CVE statuses filter parameters
    parameters = []

    # filter by package name
    if package:
        parameters.append(Status.package_name == package)

    # filter by component
    if component:
        parameters.append(Status.component == component)

    # filter by status and version
    if not _should_filter_by_version_and_status(statuses, versions):
        # by default we look for CVEs with active statuses
        parameters.append(Status.status.in_(Status.active_statuses))
    else:
        # make initial filter for cves.statuses by status-version criteria
        conditions = []
        for key, version in enumerate(clean_versions):
            conditions.append(
                and_(
                    Status.release_codename.in_(version),
                    Status.status.in_(clean_statuses[key]),
                )
            )

        parameters.append(or_(*[condition for condition in conditions]))

        # filter for cve.statuses by status-version including package/component
        conditions = []
        for key, version in enumerate(clean_versions):
            sub_conditions = [
                Status.release_codename.in_(version),
                Status.status.in_(clean_statuses[key]),
                CVE.id == Status.cve_id,
            ]

            if package:
                sub_conditions.append(Status.package_name == package)

            if component:
                sub_conditions.append(Status.component == component)

            condition = Package.statuses.any(
                and_(*[sub_condition for sub_condition in sub_conditions])
            )

            conditions.append(condition)

        parameters.append(
            Status.package.has(and_(*[condition for condition in conditions]))
        )

    # apply CVE statuses filter parameters
    if len(parameters) > 0:
        cves_query = cves_query.filter(
            CVE.statuses.any(and_(*[p for p in parameters]))
        )

    sort = asc if order_by == "oldest" else desc

    cves_query = (
        cves_query.group_by(CVE.id)
        .order_by(
            case(
                [(CVE.published.is_(None), 1)],
                else_=0,
            ),
            sort(CVE.published),
        )
        .limit(limit)
        .offset(offset)
        .from_self()
        .join(CVE.statuses)
        .options(contains_eager(CVE.statuses))
    )

    # get filtered cves
    raw_cves = cves_query.all()

    cves = []
    # filter cve.packages by parameters
    for raw_cve in raw_cves:
        cve = raw_cve[0]
        packages = cve.packages

        # filter by package name
        if package:
            packages = {
                package_name: package_statuses
                for package_name, package_statuses in packages.items()
                if package_name == package
            }

        # filter by component
        if component:
            packages = {
                package_name: package_statuses
                for package_name, package_statuses in packages.items()
                if any(
                    status.component == component
                    for status in package_statuses.values()
                )
            }

        # filter by status and version
        if _should_filter_by_version_and_status(statuses, versions):
            packages = {
                package_name: package_statuses
                for package_name, package_statuses in packages.items()
                if all(
                    any(
                        package_status.release_codename in version
                        and package_status.status in clean_statuses[key]
                        for package_status in package_statuses.values()
                    )
                    for key, version in enumerate(clean_versions)
                )
            }

        # refresh cve.statuses after cve.packages filter
        for package_name in packages:
            statuses = []
            for release, status in packages[package_name].items():
                statuses.append(status)

        cve.statuses = statuses
        cves.append(cve)

    return {
        "cves": cves,
        "offset": offset,
        "limit": limit,
        "total_results": raw_cves[0][1] if cves else 0,
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
    for package in db_session.query(Package).all():
        packages[package.name] = package

    for data in cves_data:
        update_cve = False
        cve = db_session.query(CVE).filter(CVE.id == data["id"]).one_or_none()

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
            data.get("published").strftime("%Y-%B-%d")
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

        if update_cve:
            db_session.add(cve)

        _update_statuses(cve, data, packages)

    created = defaultdict(lambda: 0)
    updated = defaultdict(lambda: 0)
    deleted = defaultdict(lambda: 0)

    for item in db_session.new:
        created[type(item).__name__] += 1

    for item in db_session.dirty:
        updated[type(item).__name__] += 1

    for item in db_session.deleted:
        deleted[type(item).__name__] += 1

    try:
        db_session.commit()
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
    cve = db_session.query(CVE).filter(CVE.id == cve_id).one_or_none()

    if not cve:
        return make_response(
            jsonify({"message": f"CVE {cve_id} doesn't exist"}),
            404,
        )

    db_session.delete(cve)
    db_session.commit()

    return make_response(
        jsonify({"message": f"CVE with id '{cve_id}' was deleted"}), 200
    )


@marshal_with(NoticeAPISchema, code=200)
@marshal_with(MessageSchema, code=404)
@marshal_with(MessageWithErrorsSchema, code=404)
@use_kwargs(NoticeParameters, location="query")
def get_notice(notice_id, **kwargs):
    notice_query = db_session.query(Notice)

    if kwargs.get("show_hidden", False):
        notice_query = notice_query.without_default_filters()

    notice = notice_query.filter(Notice.id == notice_id).one_or_none()

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
    release = kwargs.get("release")
    limit = kwargs.get("limit", 20)
    offset = kwargs.get("offset", 0)
    order_by = kwargs.get("order")

    notices_query = db_session.query(
        Notice, func.count("*").over().label("total")
    )

    if kwargs.get("is_hidden", False):
        notices_query = notices_query.without_default_filters()

    if release:
        notices_query = notices_query.join(Release, Notice.releases).filter(
            Release.codename == release
        )

    if details:
        notices_query = notices_query.filter(
            or_(
                Notice.id.like(f"%{details}%"),
                Notice.details.like(f"%{details}%"),
                Notice.cves.any(CVE.id.like(f"%{details}%")),
            )
        )

    sort = asc if order_by == "oldest" else desc

    raw_notices = (
        notices_query.order_by(sort(Notice.published))
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "notices": [raw_notice[0] for raw_notice in raw_notices],
        "offset": offset,
        "limit": limit,
        "total_results": raw_notices[0][1] if raw_notices else 0,
    }


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(CreateNoticeImportSchema, location="json")
def create_notice(**kwargs):
    notice_data = request.json

    db_session.add(
        _update_notice_object(Notice(id=notice_data["id"]), notice_data)
    )

    db_session.commit()

    return make_response(jsonify({"message": "Notice created"}), 200)


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=404)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(NoticeImportSchema, location="json")
def update_notice(notice_id, **kwargs):
    notice = (
        db_session.query(Notice).filter(Notice.id == notice_id).one_or_none()
    )

    if not notice:
        return make_response(
            jsonify({"message": f"Notice '{notice_id}' doesn't exist"}),
            404,
        )

    notice = _update_notice_object(notice, request.json)

    db_session.add(notice)
    db_session.commit()

    return make_response(jsonify({"message": "Notice updated"}), 200)


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageSchema, code=404)
def delete_notice(notice_id):
    notice = (
        db_session.query(Notice).filter(Notice.id == notice_id).one_or_none()
    )

    if not notice:
        return make_response(
            jsonify({"message": f"Notice {notice_id} doesn't exist"}),
            404,
        )

    db_session.delete(notice)
    db_session.commit()

    return make_response(
        jsonify({"message": f"Notice {notice_id} deleted"}), 200
    )


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(ReleaseSchema, location="json")
def create_release(**kwargs):
    release_data = request.json

    release = Release(
        codename=release_data["codename"],
        version=release_data["version"],
        name=release_data["name"],
        development=release_data["development"],
        lts=release_data["lts"],
        release_date=release_data["release_date"],
        esm_expires=release_data["esm_expires"],
        support_expires=release_data["support_expires"],
    )

    db_session.add(release)
    db_session.commit()

    return make_response(jsonify({"message": "Release created"}), 200)


@authorization_required
@marshal_with(MessageSchema, code=200)
@marshal_with(MessageSchema, code=400)
@marshal_with(MessageSchema, code=404)
def delete_release(codename):
    release = (
        db_session.query(Release)
        .filter(Release.codename == codename)
        .one_or_none()
    )

    if not release:
        return make_response(
            jsonify({"message": f"Release {codename} doesn't exist"}),
            404,
        )

    if len(release.statuses) > 0:
        return (
            jsonify(
                {
                    "message": (
                        f"Cannot delete '{codename}' release. "
                        f"Release already in use"
                    )
                }
            ),
            400,
        )

    db_session.delete(release)
    db_session.commit()

    return make_response(
        jsonify({"message": f"Release {codename} deleted"}), 200
    )


def _get_releases(versions):
    releases_query = db_session.query(Release).order_by(Release.release_date)

    if versions and not any(a in ["", "current"] for a in versions):
        releases_query = releases_query.filter(Release.codename.in_(versions))
    else:
        releases_query = releases_query.filter(
            or_(
                Release.support_expires > datetime.now(),
                Release.esm_expires > datetime.now(),
            )
        ).filter(Release.codename != "upstream")

    return releases_query.all()


def _should_filter_by_version_and_status(statuses, versions):
    return versions and statuses and len(versions) == len(statuses)


def _get_clean_statuses(statuses, versions):
    clean_statuses = []

    if not _should_filter_by_version_and_status(statuses, versions):
        return clean_statuses

    for status in statuses:
        if status != "" and status in status_statuses:
            clean_statuses.append([status])
        else:
            clean_statuses.append(status_statuses)

    return clean_statuses


def _get_clean_versions(statuses, versions):
    clean_versions = []

    if not _should_filter_by_version_and_status(statuses, versions):
        return clean_versions

    releases = _get_releases(versions)

    for version in versions:
        if version not in ["", "current"]:
            clean_versions.append([version])
        else:
            clean_versions.append([release.codename for release in releases])

    return clean_versions


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

    if "is_hidden" in data:
        notice.is_hidden = data["is_hidden"]

    notice.releases = [
        db_session.query(Release).get(codename)
        for codename in data["release_packages"].keys()
    ]

    notice.cves.clear()
    for cve_id in set(data["cves"]):
        notice.cves.append(db_session.query(CVE).get(cve_id) or CVE(id=cve_id))

    return notice


def _update_statuses(cve, data, packages):
    statuses = cve.packages

    statuses_to_check = (
        db_session.query(Status).filter(Status.cve_id == cve.id).all()
    )
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

            db_session.add(package)

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
                db_session.add(status)

    for key in statuses_to_delete:
        db_session.delete(statuses_to_delete[key])
