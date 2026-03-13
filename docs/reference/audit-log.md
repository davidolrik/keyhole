# Audit Log

All connections, authentication failures, and commands are logged to `{data_dir}/audit.log` as JSON (one object per line).

## Format

```json
{"time":"2026-03-04T12:00:00Z","level":"INFO","msg":"connect","user":"alice","remote":"1.2.3.4:54321","key":"SHA256:abc..."}
{"time":"2026-03-04T12:00:01Z","level":"INFO","msg":"command","user":"alice","remote":"1.2.3.4:54321","op":"get","path":"account/github","result":"ok"}
{"time":"2026-03-04T12:00:02Z","level":"WARN","msg":"auth_denied","user":"mallory","remote":"5.6.7.8:9999","reason":"non-Ed25519 key type ssh-rsa"}
{"time":"2026-03-04T12:00:03Z","level":"ERROR","msg":"command","user":"bob","remote":"10.0.0.1:9999","op":"get","path":"missing/secret","result":"error","err":"file does not exist"}
```

## Log levels

| Level   | Events                       |
| ------- | ---------------------------- |
| `INFO`  | Connections, successful commands |
| `WARN`  | Authentication denials       |
| `ERROR` | Failed commands               |

The log is append-only and survives server restarts.
