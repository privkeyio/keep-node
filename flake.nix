{
  description = "KeepNode - self-sovereign security appliance (MVP scaffold)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # keep.url = "github:privkeyio/keep";   # TODO(M0): expose keep-web as a package, wire here
  };

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      # The appliance as a bootable VM for M0 development (no hardware required).
      #   nix run .#keep-node-vm        # boots a QEMU VM running Vaultwarden
      nixosConfigurations.keep-node-vm = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./nixos/keep-node.nix
          ./nixos/vm.nix
        ];
      };

      # Run the MVP test suite:  nix flake check
      checks.${system} = {
        m0 = pkgs.testers.runNixOSTest ./tests/m0-single-node.nix;
        # m1 = pkgs.testers.runNixOSTest ./tests/m1-ha-failover.nix;  # stub, see file
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.just
          pkgs.jq
        ];
      };

      formatter.${system} = pkgs.nixfmt-rfc-style;
    };
}
