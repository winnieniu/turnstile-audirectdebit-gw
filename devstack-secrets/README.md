# Devstack pre-generated shared secret for testing

This directory contains pre-generated shared secrets that are intended for use
with developer testing the Australia Direct Debit Turnstile gateway, in order to ease
developer setup time.

This directory should be volume-mounted into the `turnstile-audirectdebit-gw`
docker container and mapped to the filesystem path `/run/secrets`.

**Under no circumstances** should these pre-generated secrets ever be used for
the deployment of `turnstile-audirectdebit-gw` in live production. Please refer
to the top-level `README.md` file in this project for instructions on how to
generate unique shared secrets.
