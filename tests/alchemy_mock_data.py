from datetime import datetime

from sqlalchemy.testing import mock

from webapp.models import CVE, Notice, Status, Release, Package

cve_data = [
    (
        [
            mock.call.query(CVE),
            mock.call.filter(CVE.id == "CVE-0000-0000"),
        ],
        [],
    ),
    (
        [
            mock.call.query(CVE),
            mock.call.filter(CVE.id == "CVE-0000-0001"),
        ],
        [
            CVE(
                id="CVE-0000-0001",
                notices=[Notice(id="USN-9999-01"), Notice(id="USN-9999-02")],
                statuses=[
                    Status(
                        cve_id="CVE-0000-0001",
                        release_codename="focal",
                        package_name="test_package",
                        status="ignored",
                        description="",
                    ),
                    Status(
                        cve_id="CVE-0000-01",
                        release_codename="bionic",
                        package_name="test_package",
                        status="released",
                        description="",
                    ),
                ],
            ),
        ],
    ),
    (
        [
            mock.call.query(CVE),
            mock.call.filter(CVE.id == "CVE-9999-0000"),
        ],
        [
            CVE(
                id="CVE-9999-0000",
                statuses=[
                    Status(
                        cve_id="CVE-9999-0000",
                        release_codename="focal",
                        package_name="test_package",
                        status="released",
                        description="",
                    ),
                    Status(
                        cve_id="CVE-9999-0000",
                        release_codename="bionic",
                        package_name="test_package",
                        status="released",
                        description="",
                    ),
                    Status(
                        cve_id="CVE-9999-0000",
                        release_codename="xenial",
                        package_name="test_package",
                        status="released",
                        description="",
                    ),
                ],
            ),
        ],
    ),
    (
        [
            mock.call.query(CVE),
            mock.call.filter(CVE.id == "CVE-9999-0001"),
        ],
        [
            CVE(
                id="CVE-9999-0001",
                statuses=[
                    Status(
                        cve_id="CVE-9999-0001",
                        release_codename="focal",
                        package_name="test_package_1",
                        status="released",
                        description="",
                    ),
                ],
            ),
        ],
    ),
    (
        [
            mock.call.query(CVE),
            mock.call.filter(CVE.id == "CVE-9999-0002"),
        ],
        [],
    ),
]

notice_data = [
    (
        [
            mock.call.query(Notice),
            mock.call.filter(Notice.id == "USN-0000-00"),
        ],
        [],
    ),
    (
        [
            mock.call.query(Notice),
            mock.call.filter(Notice.id == "USN-0000-01"),
        ],
        [
            Notice(
                id="USN-0000-01",
                cves=[CVE(id="CVE-9999-0003"), CVE(id="CVE-9999-0004")],
            ),
        ],
    ),
    (
        [
            mock.call.query(Notice),
            mock.call.filter(Notice.id == "USN-0000-02"),
        ],
        [],
    ),
    (
        [
            mock.call.query(Notice),
            mock.call.filter(Notice.id == "USN-0000-03"),
        ],
        [
            Notice(id="USN-0000-03"),
        ],
    ),
    (
        [
            mock.call.query(Notice),
            mock.call.filter(Notice.id == "USN-0000-04"),
        ],
        [
            Notice(id="USN-0000-04"),
        ],
    ),
]

package_data = [
    (
        [
            mock.call.query(Package.name),
            mock.call.filter_by(name="no-exist"),
        ],
        [],
    ),
    (
        [
            mock.call.query(Package),
        ],
        [
            Package(name="test_package"),
            Package(name="test_package_1"),
        ],
    ),
]

status_data = [
    (
        [
            mock.call.query(Status),
            mock.call.filter(Status.cve_id == "CVE-9999-0000"),
        ],
        [
            Status(
                cve_id="CVE-9999-0000",
                release_codename="focal",
                package_name="test_package",
                status="released",
                description="",
            ),
            Status(
                cve_id="CVE-9999-0000",
                release_codename="bionic",
                package_name="test_package",
                status="released",
                description="",
            ),
            Status(
                cve_id="CVE-9999-0000",
                release_codename="xenial",
                package_name="test_package",
                status="released",
                description="",
            ),
        ],
    ),
    (
        [
            mock.call.query(Status),
            mock.call.filter(Status.cve_id == "CVE-9999-0001"),
        ],
        [
            Status(
                cve_id="CVE-9999-0001",
                release_codename="focal",
                package_name="test_package_1",
                status="released",
                description="",
            ),
        ],
    ),
]

release_data = [
    (
        [
            mock.call.query(Release),
            mock.call.filter(Release.codename == "no-exist"),
        ],
        [],
    ),
    (
        [
            mock.call.query(Release),
            mock.call.filter(Release.codename == "new-release"),
        ],
        [],
    ),
    (
        [
            mock.call.query(Release),
            mock.call.filter(Release.version == "31.11"),
        ],
        [],
    ),
    (
        [
            mock.call.query(Release),
            mock.call.filter(Release.name == "New Release"),
        ],
        [],
    ),
    (
        [
            mock.call.query(Release),
            mock.call.filter(Release.codename == "hirsute"),
        ],
        [
            Release(
                codename="hirsute",
                version="21.04",
                name="Hirsute Hippo",
                development=False,
                lts=False,
                release_date=datetime.strptime("2021-04-22", "%Y-%m-%d"),
                esm_expires=datetime.strptime("2022-01-31", "%Y-%m-%d"),
                support_expires=datetime.strptime("2022-01-31", "%Y-%m-%d"),
            ),
        ],
    ),
    (
        [
            mock.call.query(Release),
            mock.call.filter(Release.version == "21.04"),
        ],
        [
            Release(
                codename="hirsute",
                version="21.04",
                name="Hirsute Hippo",
                development=False,
                lts=False,
                release_date=datetime.strptime("2021-04-22", "%Y-%m-%d"),
                esm_expires=datetime.strptime("2022-01-31", "%Y-%m-%d"),
                support_expires=datetime.strptime("2022-01-31", "%Y-%m-%d"),
            ),
        ],
    ),
    (
        [
            mock.call.query(Release),
            mock.call.filter(Release.name == "Hirsute Hippo"),
        ],
        [
            Release(
                codename="hirsute",
                version="21.04",
                name="Hirsute Hippo",
                development=False,
                lts=False,
                release_date=datetime.strptime("2021-04-22", "%Y-%m-%d"),
                esm_expires=datetime.strptime("2022-01-31", "%Y-%m-%d"),
                support_expires=datetime.strptime("2022-01-31", "%Y-%m-%d"),
            ),
        ],
    ),
    (
        [
            mock.call.query(Release),
            mock.call.all(),
        ],
        [
            Release(codename="focal"),
            Release(codename="bionic"),
        ],
    ),
]

data = cve_data + notice_data + status_data + release_data + package_data
