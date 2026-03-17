# Security Notes

## Ed25519 only

RSA and ECDSA keys are rejected at authentication. Ed25519 signatures are deterministic, which is required for reproducible key derivation. RSA signatures are probabilistic — the same input produces different signatures each time — so they cannot be used to derive stable encryption keys.

## Path isolation

Secrets are namespaced per user; one user cannot access another's secrets. Paths containing `..`, `.`, or any component starting with `.` are rejected.

## Secret size limit

Secrets are capped at 64 KB.

## Agent required for get/set

If the SSH agent is not forwarded, the server returns an error immediately rather than hanging.

## No shell

The server accepts only structured commands; there is no shell access.

## Vault key wrapping

Vault keys are individually wrapped per member using their SSH agent signature, so revoking a member does not require re-encrypting all vault secrets.

## Two-phase vault invite

Invite tokens wrap the vault key with a temporary HKDF-derived key; on accept, the vault key is re-wrapped with the member's agent key. The HKDF info parameter includes the vault name and target username for domain separation. See [Encryption](/security/encryption) for details.

## Invite expiration

Both user invite codes and vault invite tokens expire after 72 hours. Expired invites are rejected. User invite codes are consumed atomically using a filesystem rename to prevent race conditions.

## Server secret backup

::: danger
Store `server_secret` somewhere safe and separate from the data directory. Without it, every stored secret is permanently inaccessible.
:::
