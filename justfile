# KeepNode dev tasks. `just <task>`

# Run the test suite (boots VMs)
test:
    nix flake check -L

# Just the single-node test
test-single:
    nix build -L .#checks.x86_64-linux.single-node

# Boot the single-node VM interactively (Vaultwarden + keep-web) and get the test-driver REPL
vm:
    nix build .#checks.x86_64-linux.single-node.driverInteractive
    ./result/bin/nixos-test-driver --interactive

# Format Nix files
fmt:
    nix fmt
