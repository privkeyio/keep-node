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
    # Measured boot: Lanzaboote builds + signs the Unified Kernel Image so systemd-stub measures
    # the kernel/initrd/cmdline into TPM PCR 11. Consumed only by the opt-in keepNode.measuredBoot
    # module and the measured-boot test; pinned so the boot stack is reproducible.
    lanzaboote = {
      url = "github:nix-community/lanzaboote/v1.1.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      keep,
      treefmt-nix,
      lanzaboote,
    }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      # Derived from the pinned `keep` source so meta.version can't drift from the actual crate
      # version: keep sets it once in [workspace.package] and the crates inherit it.
      keepVersion =
        (builtins.fromTOML (builtins.readFile "${keep}/Cargo.toml")).workspace.package.version;

      treefmtEval = treefmt-nix.lib.evalModule pkgs {
        projectRootFile = "flake.nix";
        programs.nixfmt.enable = true;
      };

      keep-web = pkgs.rustPlatform.buildRustPackage {
        pname = "keep-web";
        version = keepVersion;
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
      # The `tpm-attestation` feature links tpm2-tss so the box can produce its own
      # measured-boot quote (`--tpm-tcti`): the dealer/box must attest, since holders
      # refuse a share or evaluation from an unattested peer. tss-esapi-sys runs
      # bindgen, hence rustPlatform.bindgenHook.
      keep-cli = pkgs.rustPlatform.buildRustPackage {
        pname = "keep-cli";
        version = keepVersion;
        src = keep;
        cargoLock.lockFile = "${keep}/Cargo.lock";
        buildAndTestSubdir = "keep-cli";
        buildFeatures = [ "tpm-attestation" ];
        nativeBuildInputs = [
          pkgs.pkg-config
          pkgs.rustPlatform.bindgenHook
        ];
        buildInputs = [
          pkgs.openssl
          pkgs.udev
          pkgs.systemd
          pkgs.tpm2-tss
        ];
        doCheck = false; # workspace tests, not needed to ship the binary
        meta.mainProgram = "keep";
      };

      # Pure-eval guard for the frostGate sealPcrs hardening: the module must reject a sealPcrs
      # that binds the TPM seal to nothing. An empty list makes --tpm2-pcrs= bind no PCRs
      # (fail-open: the key releases regardless of boot state); an out-of-range index is a typo
      # that would seal to a PCR that does not exist. This catches a future refactor that drops
      # the non-empty assertion or the 0-23 type bound, without booting a VM.
      frostGateToplevelEvals =
        sealPcrs:
        builtins.tryEval
          (nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              ./nixos/keep-node.nix
              {
                fileSystems."/" = {
                  device = "/dev/disk/by-label/root";
                  fsType = "ext4";
                };
                boot.loader.grub.enable = false;
                keepNode.frostGate = {
                  enable = true;
                  volumeDevice = "/dev/disk/by-id/ata-x";
                  inherit sealPcrs;
                };
              }
            ];
          }).config.system.build.toplevel.drvPath;
      # Split into named accept/reject outcomes so a failure names the violated expectation:
      # a broken control (a valid set fails to evaluate) means the base config regressed and is
      # distinct from the real security regression (a bad sealPcrs value is accepted).
      validPcrsEvaluate =
        (frostGateToplevelEvals [ 7 ]).success # a nominal PCR set evaluates
        && (frostGateToplevelEvals [ 23 ]).success; # upper boundary of 0-23 still evaluates
      badPcrsRejected =
        !(frostGateToplevelEvals [ ]).success # empty list is rejected (fail-open guard)
        && !(frostGateToplevelEvals [ (-1) ]).success # negative index is rejected (type bound)
        && !(frostGateToplevelEvals [ 24 ]).success # out-of-range index is rejected (type bound)
        && !(frostGateToplevelEvals [
          7
          24
        ]).success; # partially-bad list is rejected
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
        ingress = pkgs.testers.runNixOSTest {
          imports = [ ./tests/ingress.nix ];
        };
        oprf-unlock = pkgs.testers.runNixOSTest {
          imports = [ ./tests/oprf-unlock.nix ];
          _module.args.keepCliPackage = keep-cli;
        };
        measured-boot = pkgs.testers.runNixOSTest {
          imports = [ ./tests/measured-boot.nix ];
          _module.args.lanzaboote = lanzaboote;
        };
        measured-seal = pkgs.testers.runNixOSTest {
          imports = [ ./tests/measured-seal.nix ];
          _module.args.lanzaboote = lanzaboote;
        };
        formatting = treefmtEval.config.build.check self;
        frost-gate-assertions = pkgs.runCommand "frost-gate-assertions" { } (
          if !validPcrsEvaluate then
            "echo 'frost-gate-assertions control broke: a valid sealPcrs set unexpectedly failed to evaluate (base config or nixpkgs regression, not the sealPcrs guard)' >&2; exit 1"
          else if !badPcrsRejected then
            "echo 'frostGate sealPcrs guard regression: a bad sealPcrs value (empty, negative, or out-of-range PCR) was unexpectedly accepted' >&2; exit 1"
          else
            "touch $out"
        );
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
