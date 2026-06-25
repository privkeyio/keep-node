{
  description = "KeepNode - self-sovereign security appliance (MVP scaffold)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # keep-web (headless daemon, FROST co-signer, NIP-46 bunker) is built from privkeyio/keep.
    # keep has no flake, so consume the source and build it here.
    keep = {
      url = "github:privkeyio/keep";
      flake = false;
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      keep,
      treefmt-nix,
    }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      treefmtEval = treefmt-nix.lib.evalModule pkgs {
        projectRootFile = "flake.nix";
        programs.nixfmt.enable = true;
      };

      keep-web = pkgs.rustPlatform.buildRustPackage {
        pname = "keep-web";
        version = "0.4.9";
        src = keep;
        cargoLock.lockFile = "${keep}/Cargo.lock";
        # Build only the keep-web crate from the workspace.
        buildAndTestSubdir = "keep-web";
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.openssl ];
        doCheck = false; # workspace tests, not needed to ship the binary
        meta.mainProgram = "keep-web";
      };

      # keep-cli (binary `keep`): drives the FROST/OPRF threshold unlock at boot
      # (frost-gate mode=oprf). Built from the same source, just a different workspace crate.
      # serialport (hardware-signer dep) needs libudev at build time, hence udev/systemd.
      keep-cli = pkgs.rustPlatform.buildRustPackage {
        pname = "keep-cli";
        version = "0.4.9";
        src = keep;
        cargoLock.lockFile = "${keep}/Cargo.lock";
        buildAndTestSubdir = "keep-cli";
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [
          pkgs.openssl
          pkgs.udev
          pkgs.systemd
        ];
        doCheck = false; # workspace tests, not needed to ship the binary
        meta.mainProgram = "keep";
      };
    in
    {
      packages.${system} = {
        inherit keep-web keep-cli;
        default = keep-web;
      };

      # The test suite. The tests boot real NixOS VMs (no hardware needed) and are the
      # appliance's verification. Pattern follows nix-community/lanzaboote's nix/tests.
      #   nix flake check                                         # run all (incl. formatting)
      #   nix build .#checks.x86_64-linux.single-node             # one test
      #   nix build .#checks.x86_64-linux.single-node.driverInteractive
      #     ./result/bin/nixos-test-driver --interactive          # boot + poke the VM
      checks.${system} = {
        single-node = pkgs.testers.runNixOSTest {
          imports = [ ./tests/single-node.nix ];
          _module.args.keepWebPackage = keep-web;
        };
        frost-gate = pkgs.testers.runNixOSTest {
          imports = [ ./tests/frost-gate.nix ];
        };
        formatting = treefmtEval.config.build.check self;
        # ha-failover = pkgs.testers.runNixOSTest { imports = [ ./tests/ha-failover.nix ]; };  # stub
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.just
          pkgs.jq
        ];
      };

      # `nix fmt` formats the tree; `checks.formatting` enforces it in CI.
      formatter.${system} = treefmtEval.config.build.wrapper;
    };
}
