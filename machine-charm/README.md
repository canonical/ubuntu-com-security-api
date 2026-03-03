<!--
Avoid using this README file for information that is maintained or published elsewhere, e.g.:

* charmcraft.yaml > published on Charmhub
* documentation > published on (or linked to from) Charmhub
* detailed contribution guide > documentation or CONTRIBUTING.md

Use links instead.
-->

# ubuntu-security-api-vm

Charmhub package name: ubuntu-security-api-vm
More information: https://charmhub.io/ubuntu-security-api-vm

This is a machine charm to run the ubuntu-security-api on virtual machines.

## Prerequisites

- **Juju 3.x** (see [Juju installation docs](https://documentation.ubuntu.com/juju/3.6/howto/manage-juju/))
- **Ubuntu 24.04** host (required for `--destructive-mode` packing)
- A Juju model bootstrapped and ready for deployment

## Running locally

This charm requires postgres, which can be added using

```bash
juju deploy postgresql --channel 16/stable
```

In order to add the files included in the repo, we have to pack the charm using destructive mode on an Ubuntu 24.04 host:

```bash
charmcraft pack --destructive-mode
```

Then deploy the charm, and integrate with the postgresql charm.

```bash
juju deploy ./ubuntu-security-api-vm_amd64.charm

juju integrate ubuntu-security-api-vm postgresql
```

### Configuring the charm

You'll also need to set the secrets required in the config before the application can run.

Create the secrets:

```bash
juju add-secret secret-key secret-key=<somesecret>
juju add-secret oauth-token-salt oauth-token-salt=<somesecret>
```

Then grant permissions and set the config:

```bash
juju grant-secret secret-key ubuntu-security-api-vm
juju grant-secret oauth-token-salt ubuntu-security-api-vm
juju config ubuntu-security-api-vm secret-key=secret:<secret-id>
juju config ubuntu-security-api-vm oauth-token-salt=secret:<secret-id>
```

Once the deployment settles, the application status will change to `application has started`. You can now make http requests to the charm application, using its ip address e.g.

```bash
juju status
. . .
ubuntu-security-api-vm/2*  active    idle       3        10.191.230.150  8000/tcp  application has started
. . .
curl -v 10.191.230.150:8000/security/cves.json
```

### Optional configuration

You can also tune the Gunicorn worker settings:

```bash
juju config ubuntu-security-api-vm workers=4
juju config ubuntu-security-api-vm timeout=300
```

| Option    | Type    | Default | Description                                      |
| --------- | ------- | ------- | ------------------------------------------------ |
| `workers` | integer | 3       | Number of Gunicorn worker processes              |
| `timeout` | integer | 500     | Seconds before a non-responsive worker is killed |


## Using charm actions

This charm exposes three actions:

- `upload-database`
- `show-install-logs`
- `show-gunicorn-logs`

You can list available actions with:

```bash
juju actions ubuntu-security-api-vm
```

### `upload-database`

Use this action to restore a PostgreSQL snapshot from a file already present on the unit in `/tmp`.

> **Note:** The gunicorn service is stopped during the database restore and migration process. Expect brief downtime while the action runs. The service is restarted automatically once the restore completes.

1. Copy the database file to the unit:

```bash
juju scp ./database.sql ubuntu-security-api-vm/0:/tmp/database.sql
```

2. Run the action:

```bash
juju run ubuntu-security-api-vm/0 upload-database filename=database.sql --wait
```

The action restores the database, runs migrations, and returns a success or failure message.

### `show-install-logs`

Use this action to retrieve installation logs from `/var/log/install.log`:

```bash
juju run ubuntu-security-api-vm/0 show-install-logs --wait
```

### `show-gunicorn-logs`

Use this action to retrieve application logs from `/var/log/gunicorn.log`:

```bash
juju run ubuntu-security-api-vm/0 show-gunicorn-logs --wait
```

## Other resources

- See the [Juju documentation](https://documentation.ubuntu.com/juju/3.6/howto/manage-charms/) for more information about developing and improving charms.
