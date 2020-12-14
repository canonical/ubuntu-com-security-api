from datetime import datetime

from flask import make_response, jsonify
from flask_apispec import marshal_with, use_kwargs
from sqlalchemy import desc, or_, func, and_, case, asc
from sqlalchemy.orm import contains_eager

from webapp.database import db_session
from webapp.models import CVE, Notice, Release, Status, Package
from webapp.schemas import (
    CVEAPISchema,
    NoticeAPISchema,
    CVEsAPISchema,
    CVEsParameters,
    NoticesParameters,
    NoticesAPISchema,
)


@marshal_with(CVEAPISchema, code=200)
def get_cve(cve_id):
    cve = db_session.query(CVE).filter(CVE.id == cve_id).one_or_none()

    if not cve:
        return make_response(
            jsonify({"message": f"CVE with id '{cve_id}' does not exist"}),
            404,
        )

    return cve


@use_kwargs(CVEsParameters, location="query")
@marshal_with(CVEsAPISchema, code=200)
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


@marshal_with(NoticeAPISchema, code=200)
def get_notice(notice_id):
    notice = (
        db_session.query(Notice).filter(Notice.id == notice_id).one_or_none()
    )

    if not notice:
        return make_response(
            jsonify(
                {"message": f"Notice with id '{notice_id}' does not exist"}
            ),
            404,
        )

    return notice


@use_kwargs(NoticesParameters, location="query")
@marshal_with(NoticesAPISchema, code=200)
def get_notices(**kwargs):
    details = kwargs.get("details")
    release = kwargs.get("release")
    limit = kwargs.get("limit", 20)
    offset = kwargs.get("offset", 0)
    order_by = kwargs.get("order")

    notices_query = db_session.query(
        Notice, func.count("*").over().label("total")
    )

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


def _get_statuses():
    raw_all_statuses = db_session.execute(
        "SELECT unnest(enum_range(NULL::statuses));"
    ).fetchall()

    all_statuses = ["".join(s) for s in raw_all_statuses]

    return all_statuses


def _get_clean_statuses(statuses, versions):
    clean_statuses = []

    if not _should_filter_by_version_and_status(statuses, versions):
        return clean_statuses

    all_statuses = _get_statuses()

    for status in statuses:
        if status != "":
            clean_statuses.append([status])
        else:
            clean_statuses.append(all_statuses)

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
