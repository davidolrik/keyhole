---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Keyhole"
  text: "SSH-based secret manager"
  image:
    src: /keyhole.png
    alt: Keyhole
  tagline: Store and retrieve secrets using your existing SSH key — no new credentials, no browser, no agent to install.
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started/
    - theme: alt
      text: View on GitHub
      link: https://github.com/davidolrik/keyhole

features:
  - title: Ed25519 Encryption
    details: Secrets are encrypted at rest using AES-256-GCM with keys derived from your SSH agent signature via HKDF. Your private key never leaves your machine.
  - title: SSH-Native
    details: No new credentials to manage. Connect with your existing Ed25519 SSH key and agent. Single-use invite codes handle user registration.
  - title: Shared Vaults
    details: Create shared vaults for teams. Each member gets an individually wrapped copy of the vault key — revoking a member never requires re-encrypting secrets.
---
