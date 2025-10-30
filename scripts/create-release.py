#! /usr/bin/env python3

# Standard library
import argparse
import json
import os
from http.cookiejar import MozillaCookieJar

# Packages
from macaroonbakery import httpbakery


parser = argparse.ArgumentParser(description="Create a releases in the API")
parser.add_argument("file_path", action="store", type=str)
parser.add_argument(
    "--host", action="store", type=str, default="http://localhost:8030"
)
args = parser.parse_args()
parser.add_argument(
    "--auth",
    action="store",
    type=str,
    default="jujucharms",
)


client = httpbakery.Client(cookies=MozillaCookieJar(".login"))

if os.path.exists(client.cookies.filename):
    client.cookies.load(ignore_discard=True)

notice_endpoint = f"{args.host}/security/updates/releases.json"

# Make a first call to make sure we are logged in
response = client.request("POST", url=notice_endpoint)
try:
    client.cookies.save(ignore_discard=True)
except TypeError:
    pass

# Post the stuff
with open(args.file_path) as json_file:
    response = client.request(
        "POST",
        url=notice_endpoint,
        json=json.load(json_file),
    )

print(response, response.text)
