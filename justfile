# KeepNode dev tasks. `just <task>`

# Boot the appliance as a local QEMU VM (Vaultwarden reachable at http://localhost:8222)
run-vm:
    nix run .#keep-node-vm

# Run the MVP test suite (M0 today)
test:
    nix flake check -L

# Just the M0 single-node test
test-m0:
    nix build -L .#checks.x86_64-linux.m0

# Format Nix files
fmt:
    nix fmt
