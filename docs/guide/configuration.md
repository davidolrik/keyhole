# Configuration

Configuration is resolved in precedence order: **defaults < config file < environment < CLI flags**.

## CLI flags

| Flag       | Short | Default      | Description                             |
| ---------- | ----- | ------------ | --------------------------------------- |
| `--listen` | `-L`  | `:2222`      | Address to listen on                    |
| `--data`   | `-D`  | `~/.keyhole` | Data directory                          |
| `--admin`  |       |              | Comma-separated list of admin usernames |
| `--config` | `-C`  |              | Path to HCL config file                 |

## Environment variables

| Variable                | Description                             |
| ----------------------- | --------------------------------------- |
| `KEYHOLE_LISTEN`        | Address to listen on                    |
| `KEYHOLE_DATA_DIR`      | Data directory                          |
| `KEYHOLE_ADMINS`        | Comma-separated list of admin usernames |
| `KEYHOLE_SERVER_SECRET` | Alphanumeric server secret (minimum 64 characters) |

## Config file (HCL)

By default, keyhole looks for `keyhole.hcl` inside the data directory. Override with `--config`.

```hcl
listen        = ":2222"
data_dir      = "/var/lib/keyhole"
admins        = ["alice", "bob"]
server_secret = "your-alphanumeric-secret"  # minimum 64 characters
```
