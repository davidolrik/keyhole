# Data Layout

```plaintext
{data_dir}/
├── host_key                        # Ed25519 host key (PEM)
├── server_secret                   # Server-side encryption factor (alphanumeric)
├── keyhole.hcl                     # Config file (optional)
├── audit.log                       # Structured audit log
├── invites/
│   └── kh_<random>                 # Pending invite codes (empty files)
├── vaults/
│   └── {name}/
│       ├── meta.json               # {"owner","created"}
│       ├── members.json            # {"user":"role",...}
│       ├── keys/
│       │   └── {user}.enc          # Wrapped vault key per member
│       ├── pending/
│       │   └── {user}.invite       # Invite-wrapped vault key
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

## File permissions

- Directories: `0700`
- Files: `0600`
