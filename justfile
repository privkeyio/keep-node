# KeepNode dev tasks. `just <task>`

# Run the MVP test suite (boots VMs; M0 today)
test:
    nix flake check -L

# Just the M0 single-node test
test-m0:
    nix build -L .#checks.x86_64-linux.m0

# Boot the M0 VM interactively (Vaultwarden + keep-web) and get the test-driver REPL
vm:
    nix build .#checks.x86_64-linux.m0.driverInteractive
    ./result/bin/nixos-test-driver --interactive

# Format Nix files
fmt:
    nix fmt
