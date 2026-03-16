# Vaults

Vaults let teams share secrets. Each vault has its own encryption key, and each member gets an individually wrapped copy — revoking a member never requires re-encrypting vault secrets.

## Vault roles

| Role     | Permissions                          |
| -------- | ------------------------------------ |
| `owner`  | Full control (one per vault)         |
| `admin`  | Can invite and promote members       |
| `member` | Can read and write secrets           |

## Creating a vault

```sh
ssh -A alice@keys.example.com vault create team
```

You become the owner of the vault.

## Inviting members

```sh
ssh -A alice@keys.example.com vault invite team bob
# → vault invite token: kh_v_...
```

Share the invite token with the user out-of-band (e.g. via a secure channel).

## Accepting an invitation

```sh
ssh -A bob@keys.example.com vault accept team kh_v_...
```

## Promoting members

```sh
ssh -A alice@keys.example.com vault promote team bob
```

Promotes a `member` to `admin`.

## Listing members

```sh
ssh -A alice@keys.example.com vault members team
```

## Destroying a vault

```sh
ssh -A alice@keys.example.com vault destroy team
```

This permanently deletes the vault and all its secrets. Only the vault owner can destroy a vault. You will be prompted to type the vault name to confirm — this action cannot be undone.

## Vault secrets

Use colon syntax to target a vault — `vault:path`:

```sh
# Store a secret in the vault
ssh -A alice@keys.example.com set team:deploy/api-key

# Retrieve it
ssh -A bob@keys.example.com get team:deploy/api-key

# List vault secrets
ssh alice@keys.example.com list team:
```

## Workflow example

```sh
# Alice creates a shared vault
ssh -A alice@keys.example.com vault create team

# Alice invites Bob
ssh -A alice@keys.example.com vault invite team bob
# → vault invite token: kh_v_...

# Bob accepts the invitation
ssh -A bob@keys.example.com vault accept team kh_v_...

# Alice stores a secret in the vault
ssh -A alice@keys.example.com set team:deploy/api-key

# Bob retrieves it
ssh -A bob@keys.example.com get team:deploy/api-key
```
