# keyhole

An SSH-based secret storage server. Store and retrieve secrets using your existing SSH key — no new credentials to manage, no browser, no agent to install.

```sh
ssh -A alice@keys.example.com get account/github
```

## How it works

Keyhole is an SSH server that encrypts secrets at rest using a key derived from your SSH private key. The private key **never leaves your machine** — instead, your local SSH agent signs a deterministic challenge, and the signature is fed through HKDF to produce an AES-256-GCM encryption key.

Decrypting any secret requires two independent factors:

| Factor               | Held by                  |
| -------------------- | ------------------------ |
| Your SSH private key | Your machine (via agent) |
| The server secret    | The keyhole server       |

Neither is sufficient on its own. A compromised server exposes only ciphertext; a stolen SSH key is useless without the server secret.

### Encryption scheme

#### Personal secrets

```hcl
challenge  = SHA-256(server_secret + ":" + "keyhole-v1:" + username + ":" + path)
signature  = agent.Sign(your_ed25519_key, challenge)
key        = HKDF-SHA256(signature, info="keyhole-key-v1")
on-disk    = AES-256-GCM(key, nonce=random_12_bytes, plaintext)
```

#### Vault secrets

Vaults use a random 512-byte vault key shared among members:

```hcl
secret_key = HKDF-SHA256(vault_key, info="keyhole-vault-v1:<path>")
on-disk    = AES-256-GCM(secret_key, nonce=random_12_bytes, plaintext)
```

Each member's copy of the vault key is wrapped with a key derived from their SSH agent signature.

Ed25519 is required — its signatures are deterministic, which means the same challenge always produces the same key. RSA signatures are probabilistic and are rejected.

## Installation

### From source

```sh
go install go.olrik.dev/keyhole@latest
```

Or build manually:

```sh
git clone https://github.com/davidolrik/keyhole
cd keyhole
go build -o keyhole .
```

### Docker

```sh
docker pull ghcr.io/davidolrik/keyhole:latest
```

## Server setup

### Binary

```sh
keyhole serve --listen :2222 --data ~/.keyhole --admin alice
```

### Docker Compose

```yaml
services:
  keyhole:
    image: ghcr.io/davidolrik/keyhole:latest
    ports:
      - "2222:2222"
    volumes:
      - ./data:/data
    environment:
      - KEYHOLE_LISTEN=:2222
      - KEYHOLE_DATA_DIR=/data
      - KEYHOLE_ADMINS=alice
      - KEYHOLE_SERVER_SECRET=
```

### First run

On first start keyhole generates and persists:

- `host_key` — Ed25519 SSH host key (fingerprint logged on startup)
- `server_secret` — 64-character alphanumeric string (minimum 64 characters required; the server will refuse to start with a shorter secret)

**Back up `server_secret`.** Losing it makes all stored secrets permanently unrecoverable.

## Configuration

Configuration is resolved in precedence order: **defaults < config file < environment < CLI flags**.

### CLI flags

| Flag       | Short | Default      | Description                             |
| ---------- | ----- | ------------ | --------------------------------------- |
| `--listen` | `-L`  | `:2222`      | Address to listen on                    |
| `--data`   | `-D`  | `~/.keyhole` | Data directory                          |
| `--admin`  |       |              | Comma-separated list of admin usernames |
| `--config` | `-C`  |              | Path to HCL config file                 |

### Environment variables

| Variable          | Description                                              |
| ----------------- | -------------------------------------------------------- |
| `KEYHOLE_LISTEN`  | Address to listen on                                     |
| `KEYHOLE_DATA_DIR`| Data directory                                           |
| `KEYHOLE_ADMINS`  | Comma-separated list of admin usernames                  |
| `KEYHOLE_SERVER_SECRET` | Alphanumeric server secret (minimum 64 characters) |

### Config file (HCL)

By default, keyhole looks for `keyhole.hcl` inside the data directory. Override with `--config`.

```hcl
listen        = ":2222"
data_dir      = "/var/lib/keyhole"
admins        = ["alice", "bob"]
server_secret = "your-alphanumeric-secret"  # minimum 64 characters
```

### Bootstrap the first admin

After starting the server, add your public key manually (one-time setup):

```sh
mkdir -p ~/.keyhole/alice/.ssh
cp ~/.ssh/id_ed25519.pub ~/.keyhole/alice/.ssh/authorized_keys
```

From then on, new users self-register with an invite code (see below).

## Usage

### Commands

```sh
ssh [-A] <user>@<host> [-p <port>] <command> [args]
```

#### Personal secrets

| Command           | Description                                      |
| ----------------- | ------------------------------------------------ |
| `get <path>`      | Decrypt and print a secret                       |
| `set <path>`      | Encrypt and store a secret                       |
| `del <path>`      | Delete a secret (alias: `delete`)                |
| `list [prefix]`   | List secrets (alias: `ls`)                       |
| `move <src> <dst>`| Move a secret between paths or vaults            |

#### Vault secrets

Use colon syntax to target a vault: `vault:path`.

| Command                    | Description                       |
| -------------------------- | --------------------------------- |
| `get <vault>:<path>`       | Decrypt a vault secret            |
| `set <vault>:<path>`       | Encrypt a vault secret            |
| `del <vault>:<path>`       | Delete a vault secret             |
| `list <vault>:[prefix]`    | List vault secrets                |

#### Vault management

| Command                         | Description                                           |
| ------------------------------- | ----------------------------------------------------- |
| `vault create <name>`           | Create a vault (you become owner)                     |
| `vault invite <name> <user>`    | Invite a user to a vault (admin/owner)                |
| `vault accept <name> <token>`   | Accept a vault invitation                             |
| `vault promote <name> <user>`   | Promote a member to admin (admin/owner)               |
| `vault demote <name> <user>`    | Demote an admin to member (admin/owner)               |
| `vault revoke <name> <user>`    | Remove a user from a vault (admin/owner)              |
| `vault members <name>`          | List vault members and roles                          |
| `vault destroy <name>`          | Permanently destroy a vault (owner only)              |

#### Administration

| Command           | Description                                      |
| ----------------- | ------------------------------------------------ |
| `invite`          | Generate a single-use invite code _(admin only)_ |
| `register <code>` | Register your SSH key                            |
| `help`            | Show usage                                       |

`get`, `set`, `del`, and `move` require SSH agent forwarding (`-A`).

### Storing and retrieving secrets

```sh
# Store (interactive prompt, echo hidden)
ssh -A -t alice@keys.example.com set account/github

# Store from a pipe
echo "hunter2" | ssh -A alice@keys.example.com set account/github

# Retrieve
ssh -A alice@keys.example.com get account/github

# Use in a script
export GITHUB_TOKEN=$(ssh -A alice@keys.example.com get tokens/github)
```

### Deleting secrets

```sh
# Delete a personal secret (prompts for confirmation)
ssh -A alice@keys.example.com del account/github

# Delete a vault secret
ssh -A alice@keys.example.com del team:deploy/old-key
```

`delete` is an alias for `del`.

### Moving secrets

```sh
# Move a personal secret to a new path
ssh -A alice@keys.example.com move account/github account/github-old

# Move a personal secret into a vault (prompts for confirmation showing vault members)
ssh -A alice@keys.example.com move tokens/deploy team:deploy/token

# Move a vault secret to personal storage
ssh -A alice@keys.example.com move team:deploy/token tokens/deploy
```

The source secret is deleted after a successful move. If the move target is a vault, you will be shown the vault members and asked to confirm before proceeding.

### Vault workflow

```sh
# Create a shared vault
ssh -A alice@keys.example.com vault create team

# Invite a colleague
ssh -A alice@keys.example.com vault invite team bob
# → vault invite token: kh_v_...

# Bob accepts the invitation
ssh -A bob@keys.example.com vault accept team kh_v_...

# Store a secret in the vault
ssh -A alice@keys.example.com set team:deploy/api-key

# Bob retrieves it
ssh -A bob@keys.example.com get team:deploy/api-key
```

### Listing

```sh
# List all personal secrets
ssh alice@keys.example.com list

# List under a prefix
ssh alice@keys.example.com list account

# Glob match (trailing * filters by prefix)
ssh alice@keys.example.com ls account/git*
ssh alice@keys.example.com ls account/*

# List vault secrets
ssh alice@keys.example.com list team:
```

List output shows directory components in blue when the terminal supports color. Color is on by default and can be disabled by forwarding `NO_COLOR=1` or `TERM=dumb`.

### Invites and registration

User accounts are created via single-use invite codes. An admin generates a code:

```sh
ssh -A alice@keys.example.com invite
# → kh_a3f9b2c1d4e567890abcdef...
```

The new user registers using the code. They will be shown their key fingerprint and asked to confirm before the account is created:

```sh
ssh -i ~/.ssh/id_ed25519 bob@keys.example.com register kh_a3f9b2c1d4e567890abcdef...
# Registering key: ssh-ed25519 AAAA...
# Fingerprint: SHA256:xxxx
# Accept? [y/N]: y
# Registration successful. You can now connect as bob.
```

Invite codes are single-use and expire after 72 hours. They are consumed atomically on successful registration. If registration is declined, the code remains valid for another attempt.

## Colors

Keyhole colors list output by default — directory prefixes appear in blue. Colors are detected automatically:

| Condition                | Result     |
| ------------------------ | ---------- |
| Default                  | Colors on  |
| `NO_COLOR=1` forwarded   | Colors off |
| `TERM=dumb` forwarded    | Colors off |
| `ssh -t` (PTY allocated) | Colors on  |

To disable colors without `-t`:

```sh
ssh -o SetEnv=NO_COLOR=1 alice@keys.example.com list
```

Or add to `~/.ssh/config`:

```ssh-config
Host keys.example.com
    SetEnv NO_COLOR=1
```

## Data layout

```plain
{data_dir}/
├── host_key                        # Ed25519 host key (PEM)
├── server_secret                   # Server-side encryption factor (min 64 alphanumeric chars)
├── keyhole.hcl                     # Config file (optional)
├── audit.log                       # Structured audit log
├── invites/
│   ├── kh_<random>                 # Pending invite codes (contain creation timestamp)
│   └── consumed/
│       └── kh_<random>             # Used invite codes (moved here atomically)
├── vaults/
│   └── {name}/
│       ├── meta.json               # {"owner","created"}
│       ├── members.json            # {"user":"role",...}
│       ├── keys/
│       │   └── {user}.enc          # Wrapped vault key per member
│       ├── pending/
│       │   └── {user}.invite       # Invite-wrapped vault key (JSON: wrapped key + timestamp)
│       └── secrets/
│           └── {path}.enc          # Encrypted vault secret
└── {username}/
    ├── .ssh/
    │   └── authorized_keys         # User's registered public key
    └── account/
        ├── github.enc              # Encrypted secret: nonce(12B) + ciphertext
        └── tokens/
            └── api.enc
```

File permissions: directories `0700`, files `0600`.

## Audit log

All connections, authentication failures, and commands are logged to `{data_dir}/audit.log` as JSON (one object per line):

```json
{"time":"2026-03-04T12:00:00Z","level":"INFO","msg":"connect","user":"alice","remote":"1.2.3.4:54321","key":"SHA256:abc..."}
{"time":"2026-03-04T12:00:01Z","level":"INFO","msg":"command","user":"alice","remote":"1.2.3.4:54321","op":"get","path":"account/github","result":"ok"}
{"time":"2026-03-04T12:00:02Z","level":"WARN","msg":"auth_denied","user":"mallory","remote":"5.6.7.8:9999","reason":"non-Ed25519 key type ssh-rsa"}
```

The log is append-only and survives server restarts.

## Security notes

- **Ed25519 only.** RSA and ECDSA keys are rejected at authentication. Ed25519 signatures are deterministic, which is required for reproducible key derivation.
- **Path isolation.** Secrets are namespaced per user; one user cannot access another's secrets. Paths containing `..`, `.`, or any component starting with `.` are rejected.
- **Secret size limit.** Secrets are capped at 64 KB.
- **Agent required for get/set.** If the SSH agent is not forwarded, the server returns an error immediately rather than hanging.
- **No shell.** The server accepts only structured commands; there is no shell access.
- **Vault key wrapping.** Vault keys are individually wrapped per member using their SSH agent signature, so revoking a member does not require re-encrypting all vault secrets.
- **Two-phase vault invite.** Invite tokens wrap the vault key with a temporary HKDF-derived key; on accept, the vault key is re-wrapped with the member's agent key. Vault invites expire after 72 hours.
- **Server secret backup.** Store `server_secret` somewhere safe and separate from the data directory. Without it, every stored secret is permanently inaccessible. The server secret must be at least 64 characters; the server will refuse to start with a shorter value.

## Requirements

- Go 1.26+
- An Ed25519 SSH key (`ssh-keygen -t ed25519`)
- `ssh-agent` running and loaded with your key (`ssh-add`)
