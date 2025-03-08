# VWP

VWP The `vaultwarden-password-syncer` will scrape your vaultwarden instance and
store a local copy using the standard unix password manager:
[`pass`](https://www.passwordstore.org/).

In order to use the utility you need to put a config file in
`$XDG_CONFIG_HOME/vwp/config.yaml`. The file should have the following contents.

```yaml
contexts:
  - name: CONTEXT-NAME
    server: VAULTWARDEN-SERVER-ADDRESS
    username: VAULTWARDEN-USERNAME
    password:
      type: plaintext
      value: VAULTWARDEN-MASTER-PASSWORD
currentContext: CONTEXT-NAME
```

Currently only plaintext passwords are supported (ugh I know right :face-with-rolling-eyes:).

Currently the repo is a work in progress and upon running
```shell
$ vwp
```

The utility will proceed to print out all of your secrets to stdout in JSON format.

## Can I use this with Bitwarden?

VWP probably works with Bitwarden considering the API compatibility, but your
mileage may vary.
