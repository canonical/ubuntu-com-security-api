#!/usr/bin/python3
"""
Download artifacts script for ubuntu-com-security-api.

This module provides utilities to download the latest apt news and OVAL notices
from their respective sources and package them as .tar.gz files.

It fetches apt news from the Ubuntu MOTD API and OVAL notices from the
Canonical security metadata service.

Dependencies:
    - beautifulsoup4: Must be installed for parsing HTML/XML content.
      Install via `pip install beautifulsoup4`.

Environment Variables:
    APT_MOTD_URL (str): URL for the apt news JSON endpoint.
        Defaults to "https://motd.ubuntu.com/aptnews.json".
    OVAL_NEWS_URL (str): Base URL for the OVAL notices XML endpoint.
        Defaults to "https://security-metadata.canonical.com/oval/".

Usage:
    Run as a standalone script to download artifacts to a specified destination:

        $ python download-artifacts.py --dest /path/to/destination

    Or import individual functions for use in other modules.
"""
import argparse
import io
import os
import shutil
import tarfile

import requests
from bs4 import BeautifulSoup


APT_MOTD_URL = os.getenv("APT_MOTD_URL", "https://motd.ubuntu.com/aptnews.json")
OVAL_NEWS_URL = os.getenv("OVAL_NEWS_URL", "https://security-metadata.canonical.com")

def download_apt_news(dest_path: str = "/tmp/artifacts") -> None:
    """Download the latest apt news."""

    os.makedirs(dest_path, exist_ok=True)
    dest_file = f"{dest_path}/apt_news.tar.gz"
    print(f"Downloading apt news from {APT_MOTD_URL} to {dest_file}\n")

    response = requests.get(APT_MOTD_URL, timeout=60)
    if response.status_code == 200:
        with tarfile.open(dest_file, "w:gz") as tar:
            news_data = io.BytesIO(response.content)
            tarinfo = tarfile.TarInfo(name="aptnews.json")
            tarinfo.size = len(response.content)
            tar.addfile(tarinfo, news_data)
    else:
        print(f"Failed to fetch news. Status code: {response.status_code}")


def download_oval_notices(dest_path: str = "/tmp/artifacts") -> None:
    """Download the latest OVAL notices."""
    os.makedirs(dest_path, exist_ok=True)

    dest_file = f"{dest_path}/oval_notices.tar.gz"
    print(f"Downloading OVAL notices from {OVAL_NEWS_URL}/oval to {dest_file}\n")

    response = requests.get(f"{OVAL_NEWS_URL}/oval", timeout=60)
    if response.status_code == 200:
        # Parse the HTML response to extract links to OVAL notices
        soup = BeautifulSoup(response.content.decode("utf-8"), "html.parser")
        rows = soup.body.table.find_all("tr")
        links = []
        for row in rows:
            if row.a:
                links.append(f"{OVAL_NEWS_URL}{row.a['href']}")

        # Download each OVAL notice and save it to the destination path
        tars_path = f"{dest_path}/temp_oval/"
        os.makedirs(tars_path, exist_ok=True)
        for link in links:
            file_name = os.path.basename(link)
            print(f"Downloading OVAL notice {file_name}")
            notice_response = requests.get(link, timeout=60)

            if notice_response.status_code == 200:
                # Write file to destination path
                with open(f"{tars_path}/{file_name}", "wb") as f:
                    f.write(notice_response.content)
                print(f"Notice {link} downloaded.\n")
            else:
                raise Exception(f"Failed to fetch OVAL notice {link}. Status code: {notice_response.status_code}")
            
        # Download all oval notices, and save data to aggregated tar.gz file
        with tarfile.open(dest_file, "w:gz") as tar:
            # Finally package the aggregated tar.gz file
            tar.add(tars_path, arcname="oval_notices/")
            print(f"All OVAL notices downloaded and packaged into {dest_file}\n")
        shutil.rmtree(tars_path, ignore_errors=True)
    else:
        print(f"Failed to fetch OVAL notices. Status code: {response.status_code}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run this script to download the latest apt news and OVAL notices as .tar.gz files."
    )
    parser.add_argument(
        "--dest",
        type=str,
        default="/tmp/artifacts",
        help="Destination path for the downloaded .tar.gz files (default location: /tmp/artifacts)",
    )
    
    args = parser.parse_args()
    download_apt_news(dest_path=args.dest)
    download_oval_notices(dest_path=args.dest)
