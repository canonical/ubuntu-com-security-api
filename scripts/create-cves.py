#! /usr/bin/env python3

# Standard library
import argparse
import json
import os
from http.cookiejar import MozillaCookieJar

# Packages
from macaroonbakery import httpbakery

parser = argparse.ArgumentParser(
    description="Create or update CVEs in the API",
)
parser.add_argument("file_path", action="store", type=str)
parser.add_argument(
    "--host",
    action="store",
    type=str,
    default="http://localhost:8109",
)
parser.add_argument(
    "--auth",
    action="store",
    type=str,
    default="jujucharms",
)
args = parser.parse_args()


notice_endpoint = f"{args.host}/security/updates/oauth/cves.json"

client = httpbakery.Client(cookies=MozillaCookieJar(".login"))

if args.auth != "oauth":
    if os.path.exists(client.cookies.filename):
        client.cookies.load(ignore_discard=True)
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
