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


notice_endpoint = f"{args.host}/security/updates/cves.json"

client = httpbakery.Client(cookies=MozillaCookieJar(".login"))
if args.auth == "oauth":
    # For OAuth, make an initial request to get the authorization URL
    print("Initiating OAuth flow...")

    try:
        with open(args.file_path) as json_file:
            response = client.request(
                "PUT",
                url=notice_endpoint,
                json=json.load(json_file),
            )

        print(f"Response: {response}")
        print(f"Response text: {response.text}")

        if response.status_code == 302:
            print("\n🔗 Please visit this URL to authorize the application:")
            print(f"   {response.text}")
            print(
                "\nAfter authorization, the script will continue automatically.",
            )
        else:
            print(f"Unexpected response code: {response.status_code}")

    except Exception as e:
        print(f"OAuth flow error: {e}")
else:
    # Non-OAuth authentication (jujucharms)
    if os.path.exists(client.cookies.filename):
        client.cookies.load(ignore_discard=True)
    # Make a first call to make sure we are logged in
    response = client.request("PUT", url=notice_endpoint)
    # Ignore failures to save the cookie
    try:
        client.cookies.save(ignore_discard=True)
    except TypeError:
        pass

    # Post the stuff
    with open(args.file_path) as json_file:
        response = client.request(
            "PUT",
            url=notice_endpoint,
            json=json.load(json_file),
        )

    print(response, response.text)
