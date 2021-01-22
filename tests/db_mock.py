from sqlalchemy.testing import mock

from webapp.models import CVE, Notice, Status, Release, Package

data = [
    ([mock.call.query(CVE), mock.call.filter(CVE.id == "CVE-TEST")], []),
    ([mock.call.query(CVE), mock.call.filter(CVE.id == "USN-TEST")], []),
    (
        [mock.call.query(CVE), mock.call.filter(CVE.id == "CVE-TEST-1")],
        [
            CVE(
                id="CVE-TEST-1",
                notices=[Notice(id="USN-TEST-1"), Notice(id="USN-TEST-2")],
                statuses=[
                    Status(
                        cve_id="CVE-TEST-1",
                        release_codename="focal",
                        package_name="test_package",
                        status="ignored",
                    ),
                    Status(
                        cve_id="CVE-TEST-1",
                        release_codename="bionic",
                        package_name="test_package",
                        status="released",
                    ),
                ],
            ),
        ],
    ),
    (
        [mock.call.query(Notice), mock.call.filter(Notice.id == "USN-TEST-1")],
        [
            Notice(
                id="USN-TEST-1",
                cves=[CVE(id="CVE-TEST-1"), CVE(id="CVE-TEST-2")],
            ),
        ],
    ),
    ([mock.call.query(Release), mock.call.all()], [Release(codename="focal")]),
    (
        [
            mock.call.query(Package.name),
            mock.call.filter_by(name="no-exist"),
        ],
        [],
    ),
    (
        [
            mock.call.query(Package.name),
            mock.call.filter_by(name="linux"),
        ],
        [Package(name="linux")],
    ),
]
