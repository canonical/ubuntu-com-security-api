from datetime import datetime

from webapp.models import (
    Notice,
    Release,
    Status,
    CVE,
    Package,
)


def make_cve(
    id,
    published=datetime.now(),
    description="",
    ubuntu_description="",
    notes=[
        {
            "author": "mysql",
            "note": "mysql-1.2 is not affected by this CVE",
        }
    ],
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
):
    cve = CVE(
        id=id,
        published=published,
        description=description,
        ubuntu_description=ubuntu_description,
        notes=notes,
        priority=priority,
        cvss3=cvss3,
        impact=impact,
        codename=codename,
        mitigation=mitigation,
        references=references,
        patches=patches,
        tags=tags,
        bugs=bugs,
        status=status,
    )
    return cve


def make_notice(
    id,
    is_hidden=False,
    published=datetime.now(),
    summary="",
    details="",
    instructions="",
    releases=[],
    cves=[],
):
    return Notice(
        id=id,
        is_hidden=is_hidden,
        published=published,
        summary=summary,
        details=details,
        instructions=instructions,
        releases=releases,
        cves=cves,
    )


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

    cve = make_cve("CVE-1111-0001")

    status = Status(
        status="pending",
        cve=cve,
        package=package,
        release=release,
    )

    notice = make_notice("USN-1111-01", releases=[release], cves=[cve])

    return {
        "release": release,
        "package": package,
        "cve": cve,
        "status": status,
        "notice": notice,
    }
