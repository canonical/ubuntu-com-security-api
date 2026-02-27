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

## Development

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

## Other resources

- See the [Juju documentation](https://documentation.ubuntu.com/juju/3.6/howto/manage-charms/) for more information about developing and improving charms.
