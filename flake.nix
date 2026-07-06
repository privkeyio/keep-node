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
    # nostr-vpn (`nvpn`): the node-to-node encrypted mesh transport (boringtun userspace WireGuard,
    # Nostr coordination). Consumed as source and built here (no flake); pinned so the mesh binary is
    # reproducible. Only the headless `nvpn` CLI crate is built, never the desktop GUI (which the
    # workspace excludes anyway). Pinned to the v4.0.87 release commit: later `master` commits (the
    # "direct TUN lanes" work) import a fips-endpoint API newer than the published 0.3.52 the lockfile
    # pins, so they do not build from crates.io. Bump to the next tag whose Cargo.lock matches.
    nostr-vpn = {
      url = "github:mmalmi/nostr-vpn/9f5d7017f3e7248f9679824481f2ff7a5ca6dd83";
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
      nostr-vpn,
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

      # nvpn: the headless mesh daemon/CLI. Only the `nvpn` binary crate is built
      # (crates/nostr-vpn-cli); the iced desktop GUI under linux/ is excluded from the workspace, so
      # this pulls in no GTK. Default features (embedded-fips) only; `paid-exit` stays off. Deps are
      # all crates.io (no git deps in Cargo.lock), so cargoLock needs no outputHashes. A transitive
      # dep runs bindgen (libclang via bindgenHook) and links libdbus, hence dbus.
      nvpn = pkgs.rustPlatform.buildRustPackage {
        pname = "nvpn";
        version =
          (builtins.fromTOML (builtins.readFile "${nostr-vpn}/Cargo.toml")).workspace.package.version;
        src = nostr-vpn;
        cargoLock.lockFile = "${nostr-vpn}/Cargo.lock";
        buildAndTestSubdir = "crates/nostr-vpn-cli";
        nativeBuildInputs = [
          pkgs.pkg-config
          pkgs.rustPlatform.bindgenHook
        ];
        buildInputs = [ pkgs.dbus ];
        doCheck = false; # workspace tests, not needed to ship the binary
        meta.mainProgram = "nvpn";
      };

      # A pre-generated FROST 2-of-2 group so a test can drive the frost-gate OPRF mode end to end.
      # The frost-gate module bakes the group npub into its unit at build time (cfg.group), but
      # `keep frost generate` is random and runs at boot; this resolves that impedance mismatch by
      # generating the group in a derivation (generate/export/import are offline, no relay/TPM
      # needed) so the npub is known at eval time (read via IFD) and the box/holder DBs can be
      # copied into the VMs. Non-reproducible (random keygen) but built once and cached; that is
      # fine for a test fixture. `box` is the dealer DB (holds the group + both shares, so it can
      # run oprf-provision); `holder` holds imported share 2; `npub` is the group id.
      frostGroupFixture = pkgs.runCommand "frost-group-fixture" { nativeBuildInputs = [ keep-cli ]; } ''
        export HOME="$TMPDIR" KEEP_PASSWORD=fixturepass123 KEEP_YES=1
        mkdir -p "$out"
        keep --no-mlock --path "$out/box" init >/dev/null
        gen="$(keep --no-mlock --path "$out/box" frost generate -t 2 -s 2 --name g 2>&1)"
        npub="$(printf '%s' "$gen" | grep -aoE 'npub1[a-z0-9]{50,}' | head -1)"
        [ -n "$npub" ] || { echo "fixture: no npub from frost generate" >&2; exit 1; }
        printf '%s' "$npub" > "$out/npub"
        kshare="$(printf 'sp1\nsp1\n' | keep --no-mlock --path "$out/box" frost export --share 2 --group "$npub" 2>&1 | grep -aoE 'kshare1[a-z0-9]+' | head -1)"
        [ -n "$kshare" ] || { echo "fixture: no kshare from frost export" >&2; exit 1; }
        keep --no-mlock --path "$out/holder" init >/dev/null
        printf '%s\n\nsp1\n' "$kshare" | keep --no-mlock --path "$out/holder" frost import >/dev/null
      '';

      # A shared Vaultwarden JWT signing key (rsa_key.pem, 2048-bit RSA PKCS#8) for the multi-node
      # HA test: both nodes install THESE bytes so a token minted on one validates on the other.
      # Test-only (real deploys deliver an out-of-band key); generated once and cached.
      vaultRsaKeyFixture = pkgs.runCommand "vault-rsa-key" { nativeBuildInputs = [ pkgs.openssl ]; } ''
        mkdir -p "$out"
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$out/rsa_key.pem"
        openssl rsa -in "$out/rsa_key.pem" -pubout -out "$out/rsa_key.pub.pem" 2>/dev/null
      '';

      # Two pre-generated nvpn mesh identities for the declarative-onboarding test. Each `$out/<id>` is
      # the pair nvpn init writes (config.toml + its 0600 nostr secret), and `$out/npub-<id>` is the
      # identity's npub, read via IFD so the test can bake the PEER's npub into the declarative roster at
      # eval time (the frostGroupFixture pattern; onboarding needs the npub known before boot). Test-only
      # (the secret sits world-readable in /nix/store); a real deploy injects an out-of-band identity
      # path, exactly as `keepNode.mesh.identityDir` warns. Non-reproducible (random keygen), cached.
      # An ed25519 "operator" SSH keypair for the admin-access test: the pubkey goes into
      # keepNode.adminAuthorizedKeys, the private key drives the ssh client. Test-only (the private key
      # sits in the world-readable store); a real deploy uses the operator's own out-of-band key.
      adminKeyFixture = pkgs.runCommand "admin-ssh-key" { nativeBuildInputs = [ pkgs.openssh ]; } ''
        mkdir -p "$out"
        ssh-keygen -t ed25519 -N "" -C keepadmin-test -f "$out/id"
      '';

      nvpnIdentityFixture = pkgs.runCommand "nvpn-identity-fixture" { nativeBuildInputs = [ nvpn ]; } ''
        mkdir -p "$out"
        for id in a b; do
          export XDG_CONFIG_HOME="$TMPDIR/$id-cfg"
          npub="$(nvpn init 2>&1 | grep -aoE 'npub1[a-z0-9]+' | head -1)"
          [ -n "$npub" ] || { echo "nvpn-identity-fixture: no npub generated for $id" >&2; exit 1; }
          printf '%s' "$npub" > "$out/npub-$id"
          mkdir -p "$out/$id"
          cp "$XDG_CONFIG_HOME/nvpn/config.toml" "$out/$id/config.toml"
          cp "$XDG_CONFIG_HOME/nvpn/.config.toml.nostr-secret-key.secret" "$out/$id/secret"
        done
      '';

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

      # The hardened appliance, as it lands on real hardware: UEFI, Vaultwarden on, keep-web and
      # frost-gate off (frost-gate TPM unlock is opt-in and added later). debug-access is NOT
      # included and Vaultwarden signups default-deny, so this is the secure default profile.
      keepnodeSystem = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./nixos/keep-node.nix
          ./nixos/appliance.nix
        ];
      };

      # The insecure bring-up profile: the hardened appliance plus the opt-in debug-access module
      # (console autologin, password SSH, LAN web UI over self-signed TLS) and open Vaultwarden
      # signups. Used only because there is no mesh/Tor transport yet, so the box has to be
      # reachable over the plain LAN to be provisioned. Do not ship this as the default.
      keepnodeDebugSystem = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./nixos/keep-node.nix
          ./nixos/appliance.nix
          ./nixos/debug-access.nix
          {
            keepNode.debugAccess.enable = true;
            keepNode.vaultwarden.signupsAllowed = nixpkgs.lib.mkForce true;
          }
        ];
      };

      # The image the installer ships: the HARDENED appliance plus bring-up admin SSH. No debug-access,
      # no known password, signups default-deny. `keepNode.adminAccess.lanBringup` exposes the key-only
      # SSH on the LAN (a fresh node has no mesh yet) and reads the operator's key from a runtime file
      # that `install-keepnode --ssh-key` writes at install time (the closure is fixed at ISO-build time,
      # so the key can't be baked into config). Once the node joins the mesh, redeploy with lanBringup
      # off for the mesh-only posture. This replaces the old debug-profile installer image.
      keepnodeBringupSystem = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./nixos/keep-node.nix
          ./nixos/appliance.nix
          {
            keepNode.adminAccess = {
              enable = true;
              authorizedKeysFile = "/etc/keepnode/admin_authorized_keys";
              lanBringup = true;
            };
          }
        ];
      };

      # A self-contained UEFI installer ISO. It embeds the full appliance closure (see
      # installer.nix) so `install-keepnode /dev/DISK --ssh-key <k>` wipes the target and installs
      # offline: USB boot -> install (enroll key) -> reach the hardened node over key-only SSH.
      installerSystem = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          keepnodeToplevel = keepnodeBringupSystem.config.system.build.toplevel;
        };
        modules = [
          (nixpkgs + "/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix")
          ./nixos/installer.nix
        ];
      };
    in
    {
      packages.${system} = {
        inherit keep-web keep-cli nvpn;
        default = keep-web;
        # `nix build .#installer-iso` -> result/iso/*.iso ; dd it to a USB stick.
        installer-iso = installerSystem.config.system.build.isoImage;
      };

      nixosConfigurations = {
        keepnode = keepnodeSystem;
        keepnode-debug = keepnodeDebugSystem;
        installer = installerSystem;
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
        oprf-gate = pkgs.testers.runNixOSTest {
          imports = [ ./tests/oprf-gate.nix ];
          _module.args = {
            keepCliPackage = keep-cli;
            inherit frostGroupFixture;
          };
        };
        oprf-unlock = pkgs.testers.runNixOSTest {
          imports = [ ./tests/oprf-unlock.nix ];
          _module.args.keepCliPackage = keep-cli;
        };
        oprf-unlock-2of3 = pkgs.testers.runNixOSTest {
          imports = [ ./tests/oprf-unlock-2of3.nix ];
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
        ha-failover = pkgs.testers.runNixOSTest {
          imports = [ ./tests/ha-failover.nix ];
          _module.args = {
            inherit vaultRsaKeyFixture;
            nvpnPackage = nvpn;
          };
        };
        mesh = pkgs.testers.runNixOSTest {
          imports = [ ./tests/mesh.nix ];
          _module.args.nvpnPackage = nvpn;
        };
        mesh-onboarding = pkgs.testers.runNixOSTest {
          imports = [ ./tests/mesh-onboarding.nix ];
          _module.args = {
            nvpnPackage = nvpn;
            inherit nvpnIdentityFixture;
          };
        };
        mesh-admin-ssh = pkgs.testers.runNixOSTest {
          imports = [ ./tests/mesh-admin-ssh.nix ];
          _module.args = {
            nvpnPackage = nvpn;
            inherit nvpnIdentityFixture adminKeyFixture;
          };
        };
        adminaccess-bringup = pkgs.testers.runNixOSTest {
          imports = [ ./tests/adminaccess-bringup.nix ];
          _module.args = { inherit adminKeyFixture; };
        };
        mesh-replication = pkgs.testers.runNixOSTest {
          imports = [ ./tests/mesh-replication.nix ];
          _module.args = {
            nvpnPackage = nvpn;
            inherit vaultRsaKeyFixture;
          };
        };
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
