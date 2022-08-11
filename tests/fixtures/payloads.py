cve1 = {
    "id": "CVE-9999-0001",
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
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=test_package_1"
            ),
        }
    ],
}

cve2 = {
    "id": "CVE-9999-0002",
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
