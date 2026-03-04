# notes

## Sign Commits

Git commit signing proves who committed the code. npm/github provenance proves
how and where the package was built.

Configure Git to use SSH for signing:

```sh
git config --global gpg.format ssh
```

```sh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
```

### Add the key to github

Copy the contents of your `.pub` file and paste it into the **Signing Keys**
section of your account settings.
