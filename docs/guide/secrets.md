# Secrets

Personal secrets are stored under your user account, encrypted with a key derived from your SSH agent signature. Each secret has its own unique encryption key.

## Basic usage

```sh
ssh [-A] <user>@<host> [-p <port>] <command> [args]
```

`get`, `set`, `del`, and `move` require SSH agent forwarding (`-A`).

## Storing secrets

```sh
# Store interactively (echo hidden)
ssh -A -t alice@keys.example.com set account/github

# Store from a pipe
echo "hunter2" | ssh -A alice@keys.example.com set account/github
```

## Retrieving secrets

```sh
ssh -A alice@keys.example.com get account/github
```

## Using secrets in scripts

```sh
export GITHUB_TOKEN=$(ssh -A alice@keys.example.com get tokens/github)
```

## Listing secrets

```sh
# List all personal secrets
ssh alice@keys.example.com list

# List under a prefix
ssh alice@keys.example.com list account

# Glob match (trailing * filters by prefix)
ssh alice@keys.example.com ls account/git*
ssh alice@keys.example.com ls account/*
```

`list` and `ls` are aliases. See [Colors](/guide/colors) for output formatting details.

## Deleting secrets

```sh
# Delete a personal secret (prompts for confirmation)
ssh -A alice@keys.example.com del account/github

# Using the alias
ssh -A alice@keys.example.com delete account/github
```

You will be asked to confirm before the secret is deleted. The secret must exist and be decryptable — if decryption fails, the delete is aborted.

## Moving secrets

```sh
# Rename a secret
ssh -A alice@keys.example.com move account/github account/github-old

# Move a personal secret into a vault
ssh -A alice@keys.example.com move tokens/deploy team:deploy/token

# Move a vault secret to personal storage
ssh -A alice@keys.example.com move team:deploy/token tokens/deploy
```

The source secret is decrypted and re-encrypted at the destination, then the source is deleted. If the destination is a vault, you will be shown the vault members and asked to confirm before proceeding.
