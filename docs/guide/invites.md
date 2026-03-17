# Invites and Registration

User accounts are created via single-use invite codes.

## Generating an invite

An admin generates a code:

```sh
ssh -A alice@keys.example.com invite
# → kh_a3f9b2c1d4e567890abcdef...
```

## Registering

The new user registers using the code. They will be shown their key fingerprint and asked to confirm before the account is created:

```sh
ssh -i ~/.ssh/id_ed25519 bob@keys.example.com register kh_a3f9b2c1d4e567890abcdef...
# Registering key: ssh-ed25519 AAAA...
# Fingerprint: SHA256:xxxx
# Accept? [y/N]: y
# Registration successful. You can now connect as bob.
```

## How invite codes work

- Invite codes are **single-use** and **expire after 72 hours**.
- Codes are consumed atomically (moved to a `consumed/` directory) on successful registration.
- If registration is declined, the code remains valid for another attempt.
- Only admins can generate invite codes.
