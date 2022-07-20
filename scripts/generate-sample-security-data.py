#! /usr/bin/env python3

import os
import sys

sys.path.append(os.getcwd())

from datetime import datetime

# We're importing the db object from app.py rather than database.py
# so that it comes with the application context already added with
# `db = db.init_app(app)`
from webapp.app import app, db
from webapp.models import Notice, Release, Status, CVE, Package


with app.app_context():
    release = Release(
        codename="some release",
        name="00.00",
        version="0.0.0",
        lts=True,
        development=False,
        release_date=datetime.now(),
        esm_expires=datetime.now(),
        support_expires=datetime.now(),
    )
    db.session.add(release)

    package = Package(
        name="some package", source="", launchpad="", ubuntu="", debian=""
    )
    db.session.add(package)

    for usn_num in range(9999):
        cves = []

        for cve_num in range(5):
            cve = CVE(
                id=f"CVE-{usn_num}-{cve_num}",
                published=datetime.now(),
                description="",
                ubuntu_description="",
                notes={},
                priority="unknown",
                cvss3=2.3,
                mitigation="",
                references={},
                patches={},
                tags={},
                bugs={},
                status="active",
            )
            db.session.add(cve)
            cves.append(cve)

            status = Status(
                status="pending", cve=cve, package=package, release=release
            )
            db.session.add(status)

        notice = Notice(
            id=f"USN-{usn_num:04d}",
            is_hidden=False,
            published=datetime.now(),
            summary="",
            details="",
            instructions="",
            releases=[release],
            cves=cves,
        )
        db.session.add(notice)

    db.session.commit()
