# ubuntu.com security API

API functions under ubuntu.com for querying CVEs and security notices.

<!-- To check the API documentation go to https://ubuntu.com/security/api/docs. -->

## Local development

The simplest way to run the API locally is using [the dotrun snap](https://github.com/canonical-web-and-design/dotrun):

``` bash
dotrun  # In the root of the project folder
```

This will start a database, import some sample data and run the server. Exiting the server with `ctrl + c` should automatically stop the database again.

Once the server has started, you can query CVEs, Notices or Releases from the API:

- http://0.0.0.0:8030/security/notices.json
- http://0.0.0.0:8030/security/cves.json
- http://0.0.0.0:8030/security/releases.json

Or view the API documentation at http://0.0.0.0:8030/security/api/docs.

## Using virtualenv and docker 

```bash
docker compose up -d
virtualenv .venv
source .venv/bin/activate
pip install -r requirements.txt
set -a
source .env
set +a
./entrypoint 0.0.0.0:8030
```

## Managing the project

It's best to run and manage the project using `dotrun` if possible. This will install `pip` dependencies automatically, and will also include any expected system level dependencies.

### Dotrun commands

A number of "scripts" are defined in `package.json` for running with `dotrun`. These could usually also be run with `yarn run {scriptname}`.

- `dotrun start`: Run `serve` (this is the same as simply running `dotrun`)
- `dotrun serve`: Start the database and the API service
- `dotrun start-db`: Start and attach to the database without starting the API
- `dotrun delete-db`: Stop and delete the database
- `dotrun test`: Run `lint-python`, and then `test-python`
- `dotrun lint-python`: Check the format of the Python code
- `dotrun format-python`: Automatically format the Python code with `black`
- `dotrun test-python`: Run Python tests to check the API functionality
- `dotrun clean`: Delete databases, containers and temporary development files

### API and database management scripts

There are also some extra Python scripts to help with manipulating the API and database. There can also be run through `dotrun`:

``` bash
dotrun exec scripts/create-cves.py scripts/payloads/cves.json  # Create a new CVE through the API
dotrun exec scripts/create-notice.py scripts/payloads/usn-4414-2.json  # Create a Notice through the API
dotrun exec scripts/create-release.py scripts/payloads/testy.json  # Create a Release through the API
dotrun exec scripts/delete-cves.py CVE-2019-20504  # Delete a CVE
dotrun exec scripts/delete-notices.py USN-4414-2  # Delete a notice
dotrun exec scripts/delete-release.py testy  # Delete a release
dotrun exec scripts/generate-sample-security-data.py  # Fill the database with thousands of fake records
```

### Flask scripts

There are additionally some flask scripts to run needed database modifications.

```bash
flask insert_numerical_cve_ids # For each cve in the database, update the numerical_id column. Can be run repeatedly.
```

## Uploading CVES

You can use the convenience script provided in `scripts/create-cves.py` to upload cves to the local instance, using either macaroons or oauth2.
To use macaroons, run the following commands

```bash
python scripts/create-cves.py --host http://0.0.0.0:8030 scripts/payloads/cves.json 
```

To use oauth2, run the following commands

```bash
python scripts/create-cves.py --auth oauth --host http://0.0.0.0:8030 scripts/payloads/cves.json 
```

## Uploading via HTTP

You can also use regular http requests to upload CVES e.g with [`curl`](https://curl.se/docs/manpage.html). To use a long running token, pass the following header 
```bash
curl -v -H "Auth-Type: oauth" -X PUT --data @<file_path> http://0.0.0.0:8030/security/updates/cves.json

. . .
< HTTP/1.1 302 FOUND
< Server: gunicorn
< Date: Thu, 11 Dec 2025 13:23:05 GMT
< Connection: close
< Content-Type: text/html; charset=utf-8
< Content-Length: 71
< Auth-Token: gAAAAABpOsW5ZPi0NFvcZPqyFZGMhw1Nj1_Iwsg_pYzxjgPH6jba6N95hBPWyu0NHIXHuyOlpCI6YrzVHr9E4AssVppi0xSivnEjq5OOIxBJ9fSf9k6yT8QQfJqNXB9XnIae8s1VnJRof-4a5Ny5ggYtUK-v1W7zzN4aMlk34lBqtzXzeSl2AYuKQsp3CXhTjqtgIdHDRRwGDD_rN9zXei-E7UNN2AsE2qnFRqGLuzEavlOx8dtdZhavTupa8wS-PC65hnj_rMgtS3bHoUmqp19a5GeHPbLJ8Q==
< Vary: Accept-Encoding
< X-View-Name: webapp.views.bulk_upsert_cve
< X-Clacks-Overhead: GNU Terry Pratchett
< Permissions-Policy: interest-cohort=()
< X-Frame-Options: SAMEORIGIN
< X-Content-Type-Options: NOSNIFF
< X-VCS-Revision: 4cdc17aa2fe5a9e2515604ef0eae392672359ccd
< X-Request-Id: 01494c91-fd02-484a-b5a2-9dc4c8d56d8d
< 
* shutting down connection #0
https://launchpad.net/+authorize-token?oauth_token=jTWTQD0r58FbTHN4VSrH
```
You'll get a 302 link which you should open to grant authorization, as well as a token in the response header `Auth-Token`. Save this token, as it will be used to sign future requests
To use the token, pass the following header: 
```bash
curl -v -H "Auth-Type: oauth" -H "Authorization: Bearer <Auth-Token>" -X PUT --data @<file_path> http://0.0.0.0:8030/security/updates/cves.json
```