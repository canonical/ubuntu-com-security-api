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
            "debian": "https://tracker.debian.org/pkg/mysql",
            "name": "mysql",
            "source": "https://ubuntu.com/security/cve?package=mysql",
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
                "=any&searchon=sourcenames&keywords=mysql"
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
        },
        "baseMetricV4": {
            "cvssV4": {
                "version": "4.0",
                "vectorString": (
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
                    + "VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
                ),
                "baseMetrics": {
                    "exploitabilityMetrics": {
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "attackRequirements": "NONE",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                    },
                    "vulnerableSystemImpactMetrics": {
                        "confidentialityImpact": "NONE",
                        "integrityImpact": "NONE",
                        "availabilityImpact": "NONE",
                    },
                    "subsequentSystemImpactMetrics": {
                        "confidentialityImpact": "NONE",
                        "integrityImpact": "NONE",
                        "availabilityImpact": "NONE",
                    },
                },
                "supplementalMetrics": {
                    "safety": "NOT DEFINED",
                    "automatable": "NOT DEFINED",
                    "recovery": "NOT DEFINED",
                    "valueDensity": "NOT DEFINED",
                    "vulnerabilityResponseEffort": "NOT DEFINED",
                    "providerUrgency": "NOT DEFINED",
                },
                "environmentalMetrics": {
                    "modifiedBaseMetrics": {
                        "exploitabilityMetrics": {
                            "attackVector": "NOT DEFINED",
                            "attackComplexity": "NOT DEFINED",
                            "attackRequirements": "NOT DEFINED",
                            "privilegesRequired": "NOT DEFINED",
                            "userInteraction": "NOT DEFINED",
                        },
                        "vulnerableSystemImpactMetrics": {
                            "confidentialityImpact": "NOT DEFINED",
                            "integrityImpact": "NOT DEFINED",
                            "availabilityImpact": "NOT DEFINED",
                        },
                        "subsequentSystemImpactMetrics": {
                            "confidentialityImpact": "NOT DEFINED",
                            "integrityImpact": "NOT DEFINED",
                            "availabilityImpact": "NOT DEFINED",
                        },
                    },
                    "securityRequirements": {
                        "confidentialityRequirements": "NOT DEFINED",
                        "integrityRequirements": "NOT DEFINED",
                        "availabilityRequirements": "NOT DEFINED",
                    },
                },
                "threatMetrics": {"exploitMaturity": "NOT DEFINED"},
                "baseScore": 0.0,
                "baseSeverity": "NONE",
                "baseEnvironmentalScore": 0.0,
                "baseEnvironmentalSeverity": "NONE",
                "baseThreatScore": 0.0,
                "baseThreatSeverity": "NONE",
                "baseThreatEnvironmentalScore": 0.0,
                "baseThreatEnvironmentalSeverity": "NONE",
            }
        },
    },
    "priority": "critical",
    "published": "2020-08-01 12:42:54",
}

cve2 = {
    "id": "CVE-9999-0002",
    "codename": "testcodename2",
    "packages": [
        {
            "debian": "https://tracker.debian.org/pkg/mysql",
            "name": "mysql-8.0",
            "source": "https://ubuntu.com/security/cve?package=mysql-8.0",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease",
                    "status": "released",
                    "pocket": "realtime",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=mysql"
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
            "debian": "https://tracker.debian.org/pkg/postgresql-14",
            "name": "postgresql-14",
            "source": "https://ubuntu.com/security/cve?package=postgresql-14",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease",
                    "status": "released",
                    "pocket": "esm-infra-legacy",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=postgresql-14"
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
            "debian": "https://tracker.debian.org/pkg/postgresql",
            "name": "test_package_3",
            "source": "https://ubuntu.com/security/cve?package=postgresql",
            "statuses": [
                {
                    "description": "",
                    "release_codename": "testrelease",
                    "status": "released",
                }
            ],
            "ubuntu": (
                "https://packages.ubuntu.com/search?suite=all&section=all&arch"
                "=any&searchon=sourcenames&keywords=postgresql"
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
