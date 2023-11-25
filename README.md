
Software which is powering https://ldap.flipdot.space/
(only reachable from within the flipdot network)

# Installation

Install [poetry](https://python-poetry.org/docs/#installation) and run the following command:

```
poetry install
```

You can add dependencies with `poetry add <package>` and remove them with `poetry remove <package>`.

# Deployment

UWSGI and a config is included, you can use it to start the server:

The software is deployed at rail.fd with the systemd file in this project.
Checkout `./ldap-user.service`.

We are currently not using a CI/CD pipeline.
We are aiming to use saltstack for deployment, please checkout https://code.flipdot.org/flipdot/salt-ssh

In the meanwhile, this might be helpful:

```
rsync -avP --exclude config.py . ldap.flipdot.space:/opt/ldap-user
```