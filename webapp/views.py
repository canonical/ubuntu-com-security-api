from collections import defaultdict
from distutils.util import strtobool
from typing import List, Literal, Optional

import dateutil
from flask import (
    Response,
    jsonify,
    make_response,
    request,
    stream_with_context,
)
from flask_apispec import marshal_with, use_kwargs
from sqlalchemy import asc, case, desc, func, or_, text, distinct
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Query, load_only, selectinload, aliased
from webapp.auth import authorization_required
from webapp.database import db
from webapp.models import (
    CVE,
    Notice,
    Package,
    Release,
    Status,
    convert_cve_id_to_numerical_id,
)
from webapp.schemas import (
    CreateNoticeImportSchema,
    CVEAPIDetailedSchema,
    CVEImportSchema,
    CVEParameter,
    CVEsAPISchema,
    CVEsParameters,
    ReleasedCVEsAPISchema,
    ReleasedCVEsParameters,
    MessageSchema,
    MessageWithErrorsSchema,
    NoticeAPIDetailedSchema,
    NoticeAPIDetailedSchemaV2,
    NoticeImportSchema,
    NoticeParameters,
    NoticesAPISchema,
    NoticesAPISchemaV2,
    NoticesParameters,
    PageNoticesParameters,
    PageNoticesAPISchema,
    FlatNoticesAPISchema,
    FlatNoticesParameters,
    ReleaseAPISchema,
    ReleasesAPISchema,
    ReleaseSchema,
    UpdateReleaseSchema,
)
from webapp.utils import stream_notices

SIX_HOURS_IN_SECONDS = 60 * 60 * 6
TEN_MINUTES_IN_SECONDS = 60 * 10
MAX_PAGE = 100


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
    priorities: Optional[List[str]] = kwargs.get("priority")
    group_by: Optional[str] = kwargs.get("group_by")
    package: Optional[str] = kwargs.get("package")
    limit: int = kwargs.get("limit", 10)
    offset: int = kwargs.get("offset", 0)
    component: Optional[str] = kwargs.get("component")
    versions: Optional[List[str]] = kwargs.get("version")
    cve_status: Optional[str] = kwargs.get("cve_status")
    statuses: Optional[List[str]] = kwargs.get("status")
    order: Optional[Literal["oldest", "ascending", "descending"]] = kwargs.get(
        "order"
    )
    sort_by: Optional[Literal["published", "updated"]] = kwargs.get("sort_by")
    show_hidden: bool = kwargs.get("show_hidden", False)

    # Convert offset-based input to page number for db.paginate compatibility
    page = (offset // limit) + 1

    # Default to 'active' CVE status if not provided
    if cve_status:
        cves_query: Query = db.session.query(CVE).filter(
            CVE.status == cve_status
        )
    else:
        cves_query: Query = db.session.query(CVE).filter(
            CVE.status == "active"
        )

    if group_by == "priority":
        cves_query = _sort_by_priority(cves_query)

    if priorities:
        cves_query = cves_query.filter(CVE.priority.in_(priorities))

    if query:
        lowered_query = f"%{query.lower()}%"
        cves_query = cves_query.filter(
            or_(
                func.lower(CVE.id).like(lowered_query),
                func.lower(CVE.description).like(lowered_query),
                func.lower(CVE.ubuntu_description).like(lowered_query),
                func.lower(CVE.codename).like(lowered_query),
                func.lower(CVE.mitigation).like(lowered_query),
            )
        )

    join_required = any([statuses, versions, package, component])

    if join_required:
        # Use an alias to safely join Status table
        StatusAlias = aliased(Status)
        cves_query = cves_query.join(StatusAlias, CVE.id == StatusAlias.cve_id)

        if versions:
            cves_query = cves_query.filter(
                StatusAlias.release_codename.in_(versions)
            )
        if package:
            cves_query = cves_query.filter(
                StatusAlias.package_name.ilike(f"%{package}%")
            )
        if component:
            cves_query = cves_query.filter(StatusAlias.component == component)
        if statuses:
            statuses = [s for s in statuses if s]
            if statuses:
                cves_query = cves_query.filter(
                    StatusAlias.status.in_(statuses)
                )

    if not show_hidden:
        cve_notices_query = CVE.notices.and_(Notice.is_hidden == "False")
    else:
        cve_notices_query = CVE.notices

    # Default to sorting by published date unless sort_by is explicitly passed
    sort_field = {"published": CVE.published, "updated": CVE.updated_at}.get(
        sort_by, CVE.published
    )
    sort = asc if order in ("oldest", "ascending") else desc

    if sort_by and sort_by not in {"published", "updated"}:
        raise ValueError(
            "Invalid sort value. Please use 'published' or 'updated'."
        )

    if join_required:
        cves_subq = cves_query.add_columns(
            func.row_number()
            .over(
                partition_by=CVE.id,
                order_by=[
                    case([(sort_field.is_(None), 1)], else_=0),
                    sort(sort_field),
                    sort(CVE.id),
                ],
            )
            .label("row_num")
        ).subquery()

        cves_query = (
            db.session.query(CVE)
            .join(cves_subq, CVE.id == cves_subq.c.id)
            .filter(cves_subq.c.row_num == 1)
        )
    else:
        cves_query = cves_query.order_by(
            case([(sort_field.is_(None), 1)], else_=0),
            sort(sort_field),
            sort(CVE.id),
        )

    cves_query = cves_query.options(
        selectinload(cve_notices_query).options(
            selectinload(Notice.cves).options(load_only(CVE.id))
        )
    )

    pagination = db.paginate(
        cves_query, page=page, per_page=limit, error_out=False
    )

    result = CVEsAPISchema().dump(
        {
            "cves": pagination.items,
            "offset": offset,
            "limit": limit,
            "total_results": pagination.total,
        }
    )

    response = jsonify(result)
    response.cache_control.max_age = TEN_MINUTES_IN_SECONDS
    return response


@marshal_with(ReleasedCVEsAPISchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(ReleasedCVEsParameters, location="query")
def get_released_cves(**kwargs):
    package: Optional[str] = kwargs.get("package")
    limit: int = kwargs.get("limit", 10)
    offset: int = kwargs.get("offset", 0)
    versions: Optional[List[str]] = kwargs.get("version")

    # Base status query for released statuses
    status_query = db.session.query(Status.cve_id).filter(
        Status.status == "released"
    )

    if versions:
        status_query = status_query.filter(
            Status.release_codename.in_(versions)
        )

    if package:
        lowered_package = f"%{package.lower()}%"
        status_query = status_query.filter(
            func.lower(Status.package_name).like(lowered_package)
        )

    # Subquery of released CVE IDs with optional filters
    released_cve_ids_subquery = status_query.distinct().subquery()

    # Main query: CVEs that are active and have a released status
    cve_query = (
        db.session.query(CVE)
        .join(
            released_cve_ids_subquery,
            CVE.id == released_cve_ids_subquery.c.cve_id,
        )
        .filter(CVE.status == "active")
        .order_by(CVE.published.desc().nullslast())
        .offset(offset)
        .limit(limit)
    )

    cves = cve_query.all()

    # Count distinct active CVEs with released statuses
    total_results = (
        db.session.query(func.count(distinct(CVE.id)))
        .join(
            released_cve_ids_subquery,
            CVE.id == released_cve_ids_subquery.c.cve_id,
        )
        .filter(CVE.status == "active")
        .scalar()
    )

    result = ReleasedCVEsAPISchema().dump(
        {
            "cves": cves,
            "offset": offset,
            "limit": limit,
            "total_results": total_results,
        }
    )

    response = jsonify(result)
    response.cache_control.max_age = TEN_MINUTES_IN_SECONDS
    return response


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

    schema = NoticeAPIDetailedSchema
    result = schema().dump(notice)
    response = jsonify(result)
    response.cache_control.max_age = SIX_HOURS_IN_SECONDS

    return response


@use_kwargs(NoticesParameters, location="query")
@marshal_with(NoticesAPISchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
def get_notices(**kwargs):
    limit: int = kwargs["limit"]
    offset: int = kwargs["offset"]
    order_by: Literal["oldest", "newest"] = kwargs["order"]
    show_hidden: bool = kwargs["show_hidden"]
    cve_ids_only: bool = kwargs["cve_ids_only"]

    release: Optional[str] = kwargs.get("release")
    details: Optional[str] = kwargs.get("details")
    cve_id: Optional[str] = kwargs.get("cve_id")
    cves: Optional[List[str]] = kwargs.get("cves")

    notices_query: Query = db.session.query(Notice)

    sort_order_by = asc if order_by == "oldest" else desc

    if not show_hidden:
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
            )
        )

    if cves:
        # Get CVEs by numerical ID
        numerical_cve_ids = [
            convert_cve_id_to_numerical_id(cve) for cve in cves
        ]
        matched_cves = (
            db.session.query(CVE)
            .filter(CVE.numerical_id.in_(numerical_cve_ids))
            .all()
        )
        # Get notices_ids from cves
        notice_ids = []
        for cve in matched_cves:
            notice_ids += [notice.id for notice in cve.notices]

        notices_query = notices_query.filter(Notice.id.in_(notice_ids))

    total_count = (
        notices_query.order_by(None).with_entities(func.count()).scalar()
    )

    notices_query = (
        notices_query.options(
            selectinload(Notice.cves).options(
                selectinload(CVE.statuses),
                selectinload(CVE.notices).options(
                    load_only(
                        Notice.id,
                        Notice.is_hidden,
                        Notice.release_packages,
                    )
                ),
            )
        )
        .options(selectinload(Notice.releases))
        .order_by(sort_order_by(Notice.published), sort_order_by(Notice.id))
    )

    response = Response(
        stream_with_context(
            stream_notices(
                notices_query, offset, limit, total_count, cve_ids_only
            )
        ),
        content_type="application/json",
    )

    response.cache_control.max_age = SIX_HOURS_IN_SECONDS
    return response


@marshal_with(NoticeAPIDetailedSchemaV2, code=200)
@marshal_with(MessageSchema, code=404)
@use_kwargs(NoticeParameters, location="query")
def get_notice_v2(notice_id, **kwargs):
    notice_query: Query = db.session.query(Notice)

    if not kwargs.get("show_hidden", False):
        notice_query = notice_query.filter_by(is_hidden=False)

    notice: Notice = (
        notice_query.filter(Notice.id == notice_id.upper())
        .options(selectinload(Notice.cves), selectinload(Notice.releases))
        .one_or_none()
    )

    if not notice:
        return {"message": f"Notice with id '{notice_id}' does not exist"}, 404

    schema = NoticeAPIDetailedSchemaV2
    result = schema().dumps(notice)
    response = make_response(result)
    response.content_type = "application/json"
    response.cache_control.max_age = SIX_HOURS_IN_SECONDS
    return response


@use_kwargs(NoticesParameters, location="query")
@marshal_with(NoticesAPISchemaV2, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
def get_notices_v2(**kwargs):
    limit: int = kwargs["limit"]
    offset: int = kwargs["offset"]
    order_by: Literal["oldest", "newest"] = kwargs["order"]
    show_hidden: bool = kwargs["show_hidden"]

    release: Optional[str] = kwargs.get("release")
    details: Optional[str] = kwargs.get("details")
    cve_id: Optional[str] = kwargs.get("cve_id")
    cves: Optional[List[str]] = kwargs.get("cves", [])

    notices_query: Query = db.session.query(Notice)

    sort_order_by = asc if order_by == "oldest" else desc

    if not show_hidden:
        notices_query = notices_query.filter(Notice.is_hidden == "False")

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
            )
        )

    if cve_id:
        cves.append(cve_id)

    if cves:
        notices_query = notices_query.filter(Notice.cves.any(CVE.id.in_(cves)))

    notices_query = notices_query.options(
        selectinload(Notice.cves), selectinload(Notice.releases)
    ).order_by(sort_order_by(Notice.published), sort_order_by(Notice.id))

    schema = NoticesAPISchemaV2
    result = schema().dumps(
        {
            "notices": notices_query.offset(offset).limit(limit).all(),
            "offset": offset,
            "limit": limit,
            "total_results": notices_query.count(),
        }
    )
    response = make_response(result)
    response.content_type = "application/json"
    response.cache_control.public = True
    response.cache_control.max_age = TEN_MINUTES_IN_SECONDS

    return response


@marshal_with(PageNoticesAPISchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(PageNoticesParameters, location="query")
def get_page_notices(**kwargs):
    details = kwargs.get("details")
    cve_id = kwargs.get("cve_id")
    releases = kwargs.get("release")
    limit = kwargs.get("limit", 20)
    offset = kwargs.get("offset", 0)
    order_by = kwargs.get("order")

    notices_query: Query = db.session.query(Notice)

    if not kwargs.get("show_hidden", False):
        notices_query = notices_query.filter(Notice.is_hidden == "False")

    if cve_id:
        notices_query = notices_query.filter(Notice.cves.any(CVE.id == cve_id))

    if releases:
        notices_query = notices_query.join(Release, Notice.releases).filter(
            Release.codename.in_(releases)
        )

    if details:
        notices_query = notices_query.filter(
            or_(
                Notice.id.ilike(f"%{details}%"),
                Notice.details.ilike(f"%{details}%"),
                Notice.title.ilike(f"%{details}%"),
            )
        )

    sort = asc if order_by == "oldest" else desc

    notices = (
        notices_query.options(selectinload(Notice.releases))
        .order_by(sort(Notice.published), sort(Notice.id))
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


@marshal_with(FlatNoticesAPISchema, code=200)
@marshal_with(MessageWithErrorsSchema, code=422)
@use_kwargs(FlatNoticesParameters, location="query")
def get_flat_notices(**kwargs):
    details: Optional[str] = kwargs.get("details")
    releases: Optional[List[str]] = kwargs.get("release")
    limit: int = kwargs.get("limit", 10)
    offset: int = kwargs.get("offset", 0)
    order_by: Optional[str] = kwargs.get("order")

    notices_query: Query = db.session.query(Notice)

    # Filter out hidden notices by default
    notices_query = notices_query.filter(Notice.is_hidden.is_(False))

    if releases:
        notices_query = notices_query.join(Release, Notice.releases).filter(
            Release.codename.in_(releases)
        )

    if details:
        notices_query = notices_query.filter(
            or_(
                Notice.id.ilike(f"%{details}%"),
                Notice.details.ilike(f"%{details}%"),
                Notice.title.ilike(f"%{details}%"),
            )
        )

    # Determine sort order based on user input
    # default to 'oldest' if not specified
    sort = asc if order_by == "oldest" else desc

    notices = (
        notices_query.options(selectinload(Notice.releases))
        .order_by(sort(Notice.published), sort(Notice.id))
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
