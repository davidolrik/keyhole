# Overview

Keyhole is an SSH server that encrypts secrets at rest using a key derived from your SSH private key. The private key **never leaves your machine** — instead, your local SSH agent signs a deterministic challenge, and the signature is fed through HKDF to produce an AES-256-GCM encryption key.

```sh
ssh -A alice@keys.example.com get account/github
```

## Two-factor encryption

Decrypting any secret requires two independent factors:

| Factor               | Held by                  |
| -------------------- | ------------------------ |
| Your SSH private key | Your machine (via agent) |
| The server secret    | The keyhole server       |

Neither is sufficient on its own. A compromised server exposes only ciphertext; a stolen SSH key is useless without the server secret.

## Requirements

- Go 1.26+
- An Ed25519 SSH key (`ssh-keygen -t ed25519`)
- `ssh-agent` running and loaded with your key (`ssh-add`)

## Next steps

- [Installation](./installation) — build from source or pull the Docker image
- [Server Setup](./server-setup) — start the server and bootstrap the first admin
