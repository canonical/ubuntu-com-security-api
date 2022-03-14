#! /usr/bin/env python3

# Standard library
import argparse
import os
from http.cookiejar import MozillaCookieJar

# Packages
from macaroonbakery import httpbakery


parser = argparse.ArgumentParser(
    description="Delete security notices from the API"
)
parser.add_argument(
    "notice_ids", metavar="notice_id", action="store", nargs="+", type=str
)
parser.add_argument(
    "--host", action="store", type=str, default="http://localhost:8030"
)
args = parser.parse_args()


client = httpbakery.Client(cookies=MozillaCookieJar(".login"))

if os.path.exists(client.cookies.filename):
    client.cookies.load(ignore_discard=True)

# Make a first call to make sure we are logged in
response = client.request("POST", url=f"{args.host}/security/notices.json")
client.cookies.save(ignore_discard=True)

# Delete each of the USN's
for notice_id in args.notice_ids:
    response = client.request(
        method="DELETE",
        url=f"{args.host}/security/notices/{notice_id}.json",
    )

    print(response, response.text)
