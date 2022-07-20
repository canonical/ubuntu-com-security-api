#! /usr/bin/env python3

# Standard library
import argparse
import json
import os
from datetime import datetime
from http.cookiejar import MozillaCookieJar

# Packages
from macaroonbakery import httpbakery


parser = argparse.ArgumentParser(
    description="Create security notices in the API"
)
# parser.add_argument("file_path", action="store", type=str)
parser.add_argument(
    "--host", action="store", type=str, default="http://localhost:8030"
)
args = parser.parse_args()


client = httpbakery.Client(cookies=MozillaCookieJar(".login"))

# if os.path.exists(client.cookies.filename):
client.cookies.load(ignore_discard=True)

notice_endpoint = f"{args.host}/security/notices/LSN-0000-0.json"

# Put the stuff
response = client.request(
    "PUT",
    url=notice_endpoint,
    json={
        "id": "LSN-0000-0",
        "description": "Tim Boddy, Gustavo Grieco and others discovered that Expat, that is\nintegrated in xmltok library, incorrectly handled certain files.\nAn attacker could possibly use these issues to cause a denial of\nservice, or possibly execute arbitrary code. These issues were only\naddressed in Ubuntu 16.04 ESM. (CVE-2012-1148, CVE-2015-1283,\nCVE-2016-0718, CVE-2016-4472, CVE-2018-20843, CVE-2019-15903,\nCVE-2021-46143, CVE-2022-22822, CVE-2022-22823, CVE-2022-22824,\nCVE-2022-22825, CVE-2022-22826, CVE-2022-22827)\n\nIt was discovered that Expat, that is integrated in xmltok library,\nincorrectly handled encoding validation of certain files. An attacker\ncould possibly use this issue to cause a denial of service, or\npossibly execute arbitrary code. (CVE-2022-25235)\n\nIt was discovered that Expat, that is integrated in xmltok library,\nincorrectly handled namespace URIs of certain files. An attacker\ncould possibly use this issue to cause a denial of service, or\npossibly execute arbitrary code. (CVE-2022-25236)\n\n",
        "references": [],
        "cves": [
            "CVE-2012-1148",
            "CVE-2015-1283",
            "CVE-2016-0718",
            "CVE-2016-4472",
            "CVE-2018-20843",
            "CVE-2019-15903",
            "CVE-2021-46143",
            "CVE-2022-22822",
            "CVE-2022-22823",
            "CVE-2022-22824",
            "CVE-2022-22825",
            "CVE-2022-22826",
            "CVE-2022-22827",
            "CVE-2022-25235",
            "CVE-2022-25236",
        ],
        "release_packages": {
            "focal": [
                {
                    "name": "libxmltok",
                    "version": "1.2-4ubuntu0.20.04.1~esm1",
                    "description": "XML Parser Toolkit, runtime libraries",
                    "is_source": "true",
                },
                {
                    "name": "libxmltok1",
                    "version": "1.2-4ubuntu0.20.04.1~esm1",
                    "is_source": "false",
                    "source_link": "https://launchpad.net/ubuntu/+source/libxmltok",
                    "version_link": None,
                    "is_visible": "true",
                    "pocket": "esm-apps",
                },
                {
                    "name": "libxmltok1-dev",
                    "version": "1.2-4ubuntu0.20.04.1~esm1",
                    "is_source": "false",
                    "source_link": "https://launchpad.net/ubuntu/+source/libxmltok",
                    "version_link": None,
                    "is_visible": "false",
                    "pocket": "esm-apps",
                },
            ],
            "bionic": [
                {
                    "name": "libxmltok",
                    "version": "1.2-4ubuntu0.18.04.1~esm1",
                    "description": "XML Parser Toolkit, runtime libraries",
                    "is_source": "true",
                },
                {
                    "name": "libxmltok1",
                    "version": "1.2-4ubuntu0.18.04.1~esm1",
                    "is_source": "false",
                    "source_link": "https://launchpad.net/ubuntu/+source/libxmltok",
                    "version_link": None,
                    "is_visible": "true",
                    "pocket": "esm-apps",
                },
                {
                    "name": "libxmltok1-dev",
                    "version": "1.2-4ubuntu0.18.04.1~esm1",
                    "is_source": "false",
                    "source_link": "https://launchpad.net/ubuntu/+source/libxmltok",
                    "version_link": None,
                    "is_visible": "false",
                    "pocket": "esm-apps",
                },
            ],
            "xenial": [
                {
                    "name": "libxmltok",
                    "version": "1.2-3ubuntu0.16.04.1~esm2",
                    "description": "XML Parser Toolkit, runtime libraries",
                    "is_source": "true",
                },
                {
                    "name": "libxmltok1",
                    "version": "1.2-3ubuntu0.16.04.1~esm2",
                    "is_source": "false",
                    "source_link": "https://launchpad.net/ubuntu/+source/libxmltok",
                    "version_link": None,
                    "is_visible": "true",
                    "pocket": "esm-apps",
                },
                {
                    "name": "libxmltok1-dev",
                    "version": "1.2-3ubuntu0.16.04.1~esm2",
                    "is_source": "false",
                    "source_link": "https://launchpad.net/ubuntu/+source/libxmltok",
                    "version_link": None,
                    "is_visible": "false",
                    "pocket": "esm-apps",
                },
            ],
        },
        "title": "xmltok library vulnerabilities",
        "published": "2022-07-19T17:11:00.158312",
        "summary": "Several security issues were fixed in libxmltok.\n",
        "instructions": "In general, a standard system update will make all the necessary changes.\n",
        "is_hidden": "True",
    },
)

print(response, response.text)
