# Audit Log

All connections, authentication failures, and commands are logged to `{data_dir}/audit.log` as JSON (one object per line).

## Format

```json
{"time":"2026-03-04T12:00:00Z","level":"INFO","msg":"connect","user":"alice","remote":"1.2.3.4:54321","key":"SHA256:abc..."}
{"time":"2026-03-04T12:00:01Z","level":"INFO","msg":"command","user":"alice","remote":"1.2.3.4:54321","op":"get","path":"account/github","result":"ok"}
{"time":"2026-03-04T12:00:02Z","level":"WARN","msg":"auth_denied","user":"mallory","remote":"5.6.7.8:9999","reason":"non-Ed25519 key type ssh-rsa"}
{"time":"2026-03-04T12:00:03Z","level":"ERROR","msg":"command","user":"bob","remote":"10.0.0.1:9999","op":"get","path":"missing/secret","result":"error","err":"file does not exist"}
```

## Event types

In addition to connection, authentication, and command events, the following operations produce dedicated audit entries:

| Event           | Description                         |
| --------------- | ----------------------------------- |
| `registration`  | User registered with an invite code |
| `vault_get`     | Secret read from a vault            |
| `vault_set`     | Secret written to a vault           |
| `vault_del`     | Secret deleted from a vault         |
| `vault_create`  | Vault created                       |
| `vault_invite`  | User invited to a vault             |
| `vault_accept`  | User accepted a vault invitation    |
| `vault_promote` | Member promoted to admin            |
| `vault_demote`  | Admin demoted to member             |
| `vault_revoke`  | User revoked from a vault           |
| `vault_destroy` | Vault destroyed                     |

Vault operations that are denied (e.g. a non-member attempting to read a vault secret) are logged as `vault_<op>_denied` at `WARN` level with a `reason` field.

Example:

```json
{"time":"2026-03-04T12:00:05Z","level":"INFO","msg":"registration","user":"bob","remote":"10.0.0.1:9999","key":"SHA256:xxx","invite_code":"kh_abc123"}
{"time":"2026-03-04T12:00:06Z","level":"INFO","msg":"vault_create","actor":"alice","remote":"1.2.3.4:54321","vault":"team"}
{"time":"2026-03-04T12:00:07Z","level":"INFO","msg":"vault_invite","actor":"alice","remote":"1.2.3.4:54321","vault":"team","target":"bob"}
{"time":"2026-03-04T12:00:08Z","level":"INFO","msg":"vault_del","actor":"alice","remote":"1.2.3.4:54321","vault":"team"}
{"time":"2026-03-04T12:00:09Z","level":"WARN","msg":"vault_get_denied","actor":"mallory","remote":"5.6.7.8:9999","vault":"team","reason":"not a member"}
```

## Log levels

| Level   | Events                                             |
| ------- | -------------------------------------------------- |
| `INFO`  | Connections, successful commands, vault operations |
| `WARN`  | Authentication denials, vault access denials       |
| `ERROR` | Failed commands                                    |

The log is append-only and survives server restarts.
