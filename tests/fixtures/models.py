from datetime import datetime

from webapp.models import Notice, Release, Status, CVE, Package


def make_models():
    release = Release(
        codename="testrelease",
        name="Ubuntu Testrelease 00.04 LTS",
        version="00.04",
        lts=True,
        development=False,
        release_date=datetime.now(),
        esm_expires=datetime.now(),
        support_expires=datetime.now(),
    )

    package = Package(
        name="testpackage",
        source="A wonderful (test) package",
        launchpad="https://launchpad.net/test-package",
        ubuntu="test-package-ubuntu",
        debian="test-package-debian",
    )

    notice = Notice(
        id="USN-1111-01",
        is_hidden=False,
        published=datetime.now(),
        summary="",
        details="",
        instructions="",
        releases=[release],
    )
    notice.cves = []

    cve = CVE(
        id="CVE-1111-0001",
        published=datetime.now(),
        description="",
        ubuntu_description="",
        notes={},
        priority="critical",
        cvss3=2.3,
        impact={},
        codename="test_name",
        mitigation="",
        references={},
        patches={},
        tags={},
        bugs={},
        status="active",
        notices=[notice],
    )

    status = Status(
        status="pending",
        cve=cve,
        package=package,
        release=release,
    )

    return {
        "release": release,
        "package": package,
        "cve": cve,
        "status": status,
        "notice": notice,
    }
