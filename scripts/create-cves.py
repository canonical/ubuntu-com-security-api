#! /usr/bin/env python3

# Standard library
import argparse
import json
import os
from datetime import datetime
from http.cookiejar import MozillaCookieJar

# Packages
from macaroonbakery import httpbakery


parser = argparse.ArgumentParser(description="Create CVEs through the local API")
parser.add_argument("file_path", action="store", type=str)
parser.add_argument(
    "--host", action="store", type=str, default="http://localhost:8030"
)
args = parser.parse_args()


client = httpbakery.Client(cookies=MozillaCookieJar(".login"))

if os.path.exists(client.cookies.filename):
    client.cookies.load(ignore_discard=True)

notice_endpoint = f"{args.host}/security/cves.json"

# Make a first call to make sure we are logged in
response = client.request("PUT", url=notice_endpoint)
client.cookies.save(ignore_discard=True)

# Post the stuff
with open(args.file_path) as json_file:
    response = client.request(
        "PUT",
        url=notice_endpoint,
        json=json.load(json_file),
    )

print(response, response.text)
