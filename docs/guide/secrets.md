# Secrets

Personal secrets are stored under your user account, encrypted with a key derived from your SSH agent signature. Each secret has its own unique encryption key.

## Basic usage

```sh
ssh [-A] <user>@<host> [-p <port>] <command> [args]
```

`get` and `set` require SSH agent forwarding (`-A`).

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
