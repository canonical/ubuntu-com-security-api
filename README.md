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
