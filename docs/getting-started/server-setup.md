# Server Setup

## Binary

```sh
keyhole serve --listen :2222 --data ~/.keyhole --admin alice
```

## Docker Compose

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

## First run

On first start keyhole generates and persists:

- `host_key` — Ed25519 SSH host key (fingerprint logged on startup)
- `server_secret` — 64-character alphanumeric string

::: warning
**Back up `server_secret`.** Losing it makes all stored secrets permanently unrecoverable.
:::

## Bootstrap the first admin

After starting the server, add your public key manually (one-time setup):

```sh
mkdir -p ~/.keyhole/alice/.ssh
cp ~/.ssh/id_ed25519.pub ~/.keyhole/alice/.ssh/authorized_keys
```

From then on, new users self-register with an [invite code](/guide/invites).
