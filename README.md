<div align="center">

# keep-node

*Self-sovereign security appliance for your passwords and secrets.*

</div>

## About

keep-node turns a small Linux box into a private security appliance. Each node runs your core security services (a [Vaultwarden](https://github.com/dani-garcia/vaultwarden) password manager, secrets, identity) and holds only a [FROST](https://eprint.iacr.org/2020/852) threshold key share, so no single device can decrypt your vault. Run two or more and they sync to each other, so if one goes down the others keep serving. Built for non-technical users: no seed phrases.

Part of the [Keep](https://github.com/privkeyio/keep) ecosystem; the node daemon, vault, and threshold signing are reused from [`keep`](https://github.com/privkeyio/keep) (`keep-web`, `keep-core`).

> **Status: early MVP scaffold.** Today it boots Vaultwarden in a NixOS VM (M0). Threshold volume-gating, multi-node sync, and hardware support are in progress.

## Features

- **Threshold custody**: the box holds one FROST share; steal it and get nothing.
- **Multi-node HA**: nodes sync, so a single failure doesn't take your vault down.
- **Seedless**: recovery via a device quorum, no 24 words to lose.
- **Open**: MIT software on commodity hardware.

## Quick Start

Requires [Nix](https://nixos.org/download) with flakes enabled.

```bash
# Run the test suite (boots a VM, no hardware needed: Vaultwarden + keep-web)
nix flake check

# Boot the M0 VM interactively to poke at it
nix build .#checks.x86_64-linux.m0.driverInteractive
./result/bin/nixos-test-driver --interactive
```

## License

[MIT](LICENSE)
