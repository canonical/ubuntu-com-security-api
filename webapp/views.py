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

    releases = releases_query.all()

    should_filter_by_version_and_status = (
        versions and statuses and len(versions) == len(statuses)
    )

    clean_versions = []
    clean_statuses = []
    if should_filter_by_version_and_status:
        raw_all_statuses = db_session.execute(
            "SELECT unnest(enum_range(NULL::statuses));"
        ).fetchall()
        all_statuses = ["".join(s) for s in raw_all_statuses]

        clean_versions = [
            (
                [version]
                if version not in ["", "current"]
                else [r.codename for r in releases]
            )
            for version in versions
        ]

        clean_statuses = [
            ([status] if status != "" else all_statuses) for status in statuses
        ]

    # query cves by filters
    cves_query = db_session.query(
        CVE, func.count("*").over().label("total")
    ).filter(CVE.status == "active")

    if priority:
        cves_query = cves_query.filter(CVE.priority == priority)

    if query:
        cves_query = cves_query.filter(
            or_(
                CVE.description.ilike(f"%{query}%"),
                CVE.ubuntu_description.ilike(f"%{query}%"),
            )
        )

    parameters = []
    if package:
        parameters.append(Status.package_name == package)

    if component:
        parameters.append(Status.component == component)

    if should_filter_by_version_and_status:
        conditions = []
        for key, version in enumerate(clean_versions):
            conditions.append(
                and_(
                    Status.release_codename.in_(version),
                    Status.status.in_(clean_statuses[key]),
                )
            )

        parameters.append(or_(*[c for c in conditions]))

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
                and_(*[sc for sc in sub_conditions])
            )

            conditions.append(condition)

        parameters.append(Status.package.has(and_(*[c for c in conditions])))
    else:
        parameters.append(Status.status.in_(Status.active_statuses))

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

    # each result item has
    raw_cves = cves_query.all()

    cves = []
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

        if should_filter_by_version_and_status:
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
