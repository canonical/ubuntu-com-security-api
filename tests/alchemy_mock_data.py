from sqlalchemy.testing import mock

from webapp.models import CVE, Notice, Status, Release, Package

data = [
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
                    ),
                    Status(
                        cve_id="CVE-0000-01",
                        release_codename="bionic",
                        package_name="test_package",
                        status="released",
                    ),
                ],
            ),
        ],
    ),
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
    (
        [
            mock.call.query(Release),
            mock.call.all(),
        ],
        [Release(codename="focal"), Release(codename="bionic")],
    ),
    (
        [
            mock.call.query(Package.name),
            mock.call.filter_by(name="no-exist"),
        ],
        [],
    ),
]
