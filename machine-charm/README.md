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

## Running locally

This charm requires postgres, which can be added using

```bash
juju deploy postgresql --channel 16/stable
```

In order to add the files included in the repo, we have to pack the charm using destructive mode, i.e.

```bash
charmcraft pack --destructive-mode
```

Then deploy the charm, and integrate with the postgresql charm.

```bash
juju deploy ./ubuntu-security-api-vm_amd64.charm

juju relate ubuntu-security-api-vm postgresql
```

### Configuring the charm

You'll also need to set the secret is required in the config file before the application can run. e.g.

To create

```bash
juju add-secret secret-key secret-key=<somesecret>
juju add-secret oauth-token-salt secret-key=<somesecret>
```

Then grant permissions, and set the config

```bash
juju grant-secret secret-key ubuntu-security-api-vm
juju grant-secret oauth-token-salt ubuntu-security-api-vm
juju config ubuntu-security-api-vm oauth-token-salt=secret:d6id5jn91c5s41im2dtg
juju config ubuntu-security-api-vm secret-key=secret:d6idfa791c5s41im2dug
```

## Other resources

- See the [Juju documentation](https://documentation.ubuntu.com/juju/3.6/howto/manage-charms/) for more information about developing and improving charms.
