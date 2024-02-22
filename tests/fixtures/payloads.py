"""
This CVE is missing a status field. It should not show up
in get requests for all CVEs,but should show up when you
make a get request by its CVE id
"""
cve1 = {
    "id": "CVE-9999-0001",
    "codename": "testcodename",
    "packages": [
        {
            "debian": "https://tracker.debian.org/pkg/test_package_1",
            "name": "test_package_1",
            "source": "https://ubuntu.com/security/cve?package=test_package_1",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease",
                    "status": "released",
                    "pocket": "fips",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=test_package_1"
            ),
        }
    ],
    "impact": {
        "baseMetricV3": {
            "cvssV3": {
                "attackComplexity": "LOW",
                "attackVector": "Local",
                "availabilityImpact": "NONE",
                "baseScore": 4.4,
                "baseSeverity": "MEDIUM",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "NONE",
                "privilegesRequired": "HIGH",
                "scope": "UNCHANGED",
                "userInteraction": "NONE",
                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
                "version": "3.1",
            },
            "exploitabilityScore": 0.8,
            "impactScore": 3.6,
        }
    },
    "priority": "critical",
    "published": "2020-08-01 12:42:54",
}

cve2 = {
    "id": "CVE-9999-0002",
    "codename": "testcodename2",
    "packages": [
        {
            "debian": "https://tracker.debian.org/pkg/test_package_2",
            "name": "test_package_2",
            "source": "https://ubuntu.com/security/cve?package=test_package21",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease",
                    "status": "released",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=test_package_2"
            ),
        }
    ],
    "published": "2020-11-01 12:42:54",
    "priority": "high",
    "status": "active",
}

cve3 = {
    "id": "CVE-9999-0003",
    "codename": "testcodename3",
    "packages": [
        {
            "debian": "https://tracker.debian.org/pkg/test_package_3",
            "name": "test_package_3",
            "source": "https://ubuntu.com/security/cve?package=test_package_3",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease",
                    "status": "released",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=test_package_3"
            ),
        }
    ],
    "priority": "medium",
    "published": "2019-12-01 12:42:54",
    "status": "active",
}

cve4 = {
    "id": "CVE-9999-0004",
    "codename": "testcodename4",
    "packages": [
        {
            "debian": "https://tracker.debian.org/pkg/test_package_4",
            "name": "test_package_3",
            "source": "https://ubuntu.com/security/cve?package=test_package_4",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease",
                    "status": "released",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=test_package_4"
            ),
        }
    ],
    "priority": "medium",
    "published": "2022-12-01 12:42:54",
    "status": "active",
}

cve5 = {
    "id": "CVE-9999-0005",
    "packages": [
        {
            "debian": "https://tracker.debian.org/pkg/test_package_5",
            "name": "test_package_3",
            "source": "https://ubuntu.com/security/cve?package=test_package_5",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease3",
                    "status": "released",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=test_package_5"
            ),
        }
    ],
    "published": "2020-12-01 12:42:54",
    "priority": "low",
    "status": "active",
}

cve6 = {
    "id": "CVE-9999-0006",
    "packages": [
        {
            "debian": "https://tracker.debian.org/pkg/test_package_6",
            "name": "test_package_3",
            "source": "https://ubuntu.com/security/cve?package=test_package_6",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease2",
                    "status": "released",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=test_package_6"
            ),
        }
    ],
    "published": "2020-12-01 12:42:54",
    "priority": "negligible",
    "status": "active",
}

cve7 = {
    "id": "CVE-9999-0007",
    "packages": [
        {
            "debian": "https://tracker.debian.org/pkg/test_package_6",
            "name": "test_package_3",
            "source": "https://ubuntu.com/security/cve?package=test_package_6",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease",
                    "status": "needed",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=test_package_6"
            ),
        }
    ],
    "published": "2020-12-01 12:42:54",
    "priority": "negligible",
    "status": "active",
}

cve8 = {
    "id": "CVE-9999-0008",
    "packages": [
        {
            "debian": "https://tracker.debian.org/pkg/test_package_6",
            "name": "test_package_3",
            "source": "https://ubuntu.com/security/cve?package=test_package_6",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease2",
                    "status": "needs-triage",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=test_package_6"
            ),
        }
    ],
    "published": "2020-12-01 12:42:54",
    "priority": "negligible",
    "status": "active",
}

notice = {
    "cves": ["CVE-9999-0003", "CVE-9999-0004"],
    "id": "USN-9999-01",
    "description": "This is the description",
    "instructions": "These are the instructions",
    "published": "2020-12-01 12:42:54",
    "references": [],
    "release_packages": {
        "testrelease": [
            {
                "description": "Linux kernel for OEM systems",
                "is_source": "false",
                "name": "linux-oem",
                "version": "4.15.0-1080.90",
                "channel": "Test channel",
            }
        ],
    },
    "summary": "Summary",
    "title": "Title",
}

ssn_notice = {
    "cves": [],
    "id": "SSN-1-1",
    "description": "This is an SSN",
    "instructions": "These are the instructions",
    "published": "2022-07-27 12:42:54",
    "references": [],
    "release_packages": {
        "testrelease": [
            {
                "description": "Linux kernel for OEM systems",
                "is_source": "false",
                "name": "linux-oem",
                "version": "4.15.0-1080.90",
                "package_type": "golang",
                "pocket": "soss",
                "channel": "Test channel",
            }
        ],
    },
    "summary": "Summary",
    "title": "Title",
}

release = {
    "name": "Created Release",
    "version": "99.04",
    "codename": "createdrelease",
    "lts": False,
    "development": True,
    "release_date": "2021-04-22",
    "esm_expires": "2022-01-31",
    "support_expires": "2022-01-31",
}

release2 = {
    "name": "New Created Release",
    "version": "99.05",
    "codename": "testrelease2",
    "lts": False,
    "development": True,
    "release_date": "2021-04-22",
    "esm_expires": "2022-01-31",
    "support_expires": "2022-01-31",
}


release3 = {
    "name": "Another Created Release",
    "version": "99.06",
    "codename": "testrelease3",
    "lts": False,
    "development": True,
    "release_date": "2021-04-22",
    "esm_expires": "2022-01-31",
    "support_expires": "2022-01-31",
}
