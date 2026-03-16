# Commands

```sh
ssh [-A] <user>@<host> [-p <port>] <command> [args]
```

`get` and `set` require SSH agent forwarding (`-A`).

## Personal secrets

| Command           | Description                |
| ----------------- | -------------------------- |
| `get <path>`      | Decrypt and print a secret |
| `set <path>`      | Encrypt and store a secret |
| `list [prefix]`   | List secrets (alias: `ls`) |

## Vault secrets

Use colon syntax to target a vault: `vault:path`.

| Command                  | Description            |
| ------------------------ | ---------------------- |
| `get <vault>:<path>`     | Decrypt a vault secret |
| `set <vault>:<path>`     | Encrypt a vault secret |
| `list <vault>:[prefix]`  | List vault secrets     |

## Vault management

| Command                         | Description                             |
| ------------------------------- | --------------------------------------- |
| `vault create <name>`           | Create a vault (you become owner)       |
| `vault invite <name> <user>`    | Invite a user to a vault (admin/owner)  |
| `vault accept <name> <token>`   | Accept a vault invitation               |
| `vault promote <name> <user>`   | Promote a member to admin (admin/owner) |
| `vault members <name>`          | List vault members and roles            |
| `vault destroy <name>`          | Permanently destroy a vault (owner only)|

## Administration

| Command           | Description                                      |
| ----------------- | ------------------------------------------------ |
| `invite`          | Generate a single-use invite code _(admin only)_ |
| `register <code>` | Register your SSH key                            |
| `help`            | Show usage                                       |
