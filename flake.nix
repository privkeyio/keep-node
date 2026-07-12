{
  description = "KeepNode - self-sovereign security appliance (MVP scaffold)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # keep-web (headless daemon, FROST co-signer, NIP-46 bunker) is built from privkeyio/keep.
    # keep has no flake, so consume the source and build it here. Pinned to a tagged RELEASE, not
    # main-HEAD, so the appliance builds from a curated, known-good version rather than whatever main
    # happens to be; bump the tag to adopt a newer release deliberately.
    keep = {
      url = "github:privkeyio/keep/v0.7.3";
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

    # wisp: the on-box nostr relay (Zig), run bound to the mesh interface. Provides the relay the
    # threshold-OPRF quorum + (later) relay-based mesh peer discovery coordinate over, dogfooding
    # privkey's own relay instead of nostr-rs-relay. Pinned to a tagged RELEASE (not main-HEAD), same
    # as keep; bump the tag to adopt a newer release.
    wisp = {
      url = "github:privkeyio/wisp/v0.5.11";
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
      wisp,
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

      # Like frostGroupFixture but a 2-of-3 group, for the through-the-gate 2-of-3 boot test. `box` is
      # the dealer DB (group + all shares, runs oprf-provision); `holder` holds share 2 and `holder2`
      # holds share 3, so the box plus ANY ONE holder is a quorum. Same IFD/eval-time npub rationale as
      # the 2-of-2 fixture (the gate bakes the npub at build time).
      frostGroupFixture2of3 =
        pkgs.runCommand "frost-group-fixture-2of3" { nativeBuildInputs = [ keep-cli ]; }
          ''
            export HOME="$TMPDIR" KEEP_PASSWORD=fixturepass123 KEEP_YES=1
            mkdir -p "$out"
            keep --no-mlock --path "$out/box" init >/dev/null
            gen="$(keep --no-mlock --path "$out/box" frost generate -t 2 -s 3 --name g 2>&1)"
            npub="$(printf '%s' "$gen" | grep -aoE 'npub1[a-z0-9]{50,}' | head -1)"
            [ -n "$npub" ] || { echo "fixture: no npub from frost generate" >&2; exit 1; }
            printf '%s' "$npub" > "$out/npub"
            import_share() {
              ksh="$(printf 'sp1\nsp1\n' | keep --no-mlock --path "$out/box" frost export --share "$1" --group "$npub" 2>&1 | grep -aoE 'kshare1[a-z0-9]+' | head -1)"
              [ -n "$ksh" ] || { echo "fixture: no kshare for share $1" >&2; exit 1; }
              keep --no-mlock --path "$2" init >/dev/null
              printf '%s\n\nsp1\n' "$ksh" | keep --no-mlock --path "$2" frost import >/dev/null
            }
            import_share 2 "$out/holder"
            import_share 3 "$out/holder2"
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

      # Pure-eval guard for the adminAccess bring-up SSH firewall scoping: when lanBringupInterface
      # names a NIC, the bring-up opening must land on that interface and NOT on the global (all-
      # interface) allowedTCPPorts list, so a public/WAN NIC is never opened; with no interface named
      # it falls back to the global list (the generic image, which can't know the NIC name).
      adminAccessFirewall =
        {
          lanBringup,
          lanBringupInterface,
        }:
        (nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            ./nixos/admin-access.nix
            {
              fileSystems."/" = {
                device = "/dev/disk/by-label/root";
                fsType = "ext4";
              };
              boot.loader.grub.enable = false;
              networking.firewall.enable = true;
              keepNode.adminAccess = {
                enable = true;
                authorizedKeys = [ "ssh-ed25519 AAAAeval-only-fixture-key keepadmin-eval" ];
                inherit lanBringup lanBringupInterface;
              };
            }
          ];
        }).config.networking.firewall;
      lanBringupScopingHolds =
        let
          scoped = adminAccessFirewall {
            lanBringup = true;
            lanBringupInterface = "eth0";
          };
          global = adminAccessFirewall {
            lanBringup = true;
            lanBringupInterface = null;
          };
          off = adminAccessFirewall {
            lanBringup = false;
            lanBringupInterface = null;
          };
        in
        # scoped: port 22 opened on the named NIC, and NOT on the global all-interface list
        builtins.elem 22 (scoped.interfaces.eth0.allowedTCPPorts or [ ])
        && !(builtins.elem 22 scoped.allowedTCPPorts)
        # scoped: the mesh interface (utun100, the default meshInterface) STILL opens port 22;
        # scoping the bring-up opening must never drop the mesh opening.
        && builtins.elem 22 (scoped.interfaces.utun100.allowedTCPPorts or [ ])
        # no interface named: fall back to the global list, and eth0 is NOT opened (the scoped per-NIC
        # opening only appears in the scoped case).
        && builtins.elem 22 global.allowedTCPPorts
        && !(builtins.elem 22 (global.interfaces.eth0.allowedTCPPorts or [ ]))
        # bring-up off: no global opening at all, and eth0 is NOT opened.
        && !(builtins.elem 22 off.allowedTCPPorts)
        && !(builtins.elem 22 (off.interfaces.eth0.allowedTCPPorts or [ ]));

      # Pure-eval guard for the adminAccess anti-lockout assertion: key-only SSH with no authorized
      # key (and no runtime keys file) is a permanent remote lockout, so the module must refuse to
      # build. Forcing the system toplevel triggers assertions; tryEval turns a fired assertion into
      # success=false. Catches a refactor that drops or weakens the guard, without booting a VM.
      adminAccessToplevelEvals =
        {
          authorizedKeys,
          authorizedKeysFile ? null,
        }:
        builtins.tryEval
          (nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              ./nixos/admin-access.nix
              {
                fileSystems."/" = {
                  device = "/dev/disk/by-label/root";
                  fsType = "ext4";
                };
                boot.loader.grub.enable = false;
                networking.firewall.enable = true;
                keepNode.adminAccess = {
                  enable = true;
                  inherit authorizedKeys authorizedKeysFile;
                };
              }
            ];
          }).config.system.build.toplevel.drvPath;
      adminAccessAntiLockoutHolds =
        # A real key builds (control); empty or whitespace-only keys with no runtime file are rejected
        # (the lockout guard fires, including through the `trim` so "  " is not mistaken for a key); a
        # real key alongside blank entries still builds (the guard must not over-reject a list that has
        # one usable key); the installer's authorizedKeysFile escape satisfies it (path populated at
        # install). The negative cases assert only `.success == false`, not which assertion fired: tryEval
        # surfaces no message. That is attributable to the anti-lockout guard only because every fixture
        # holds the module's other assertions passing (firewall on, no debugAccess, lanBringupInterface
        # null), so the sole eval difference from the control is `authorizedKeys`.
        (adminAccessToplevelEvals {
          authorizedKeys = [ "ssh-ed25519 AAAAeval-only-fixture-key keepadmin-eval" ];
        }).success
        && !(adminAccessToplevelEvals { authorizedKeys = [ ]; }).success
        && !(adminAccessToplevelEvals {
          authorizedKeys = [
            ""
            "   "
          ];
        }).success
        && (adminAccessToplevelEvals {
          authorizedKeys = [
            ""
            "ssh-ed25519 AAAAeval-only-fixture-key keepadmin-eval"
          ];
        }).success
        && (adminAccessToplevelEvals {
          authorizedKeys = [ ];
          authorizedKeysFile = "/run/keys/admin_authorized_keys";
        }).success
        # A RELATIVE-path authorizedKeysFile is REFUSED (a distinct absolute-path guard): sshd silently
        # ignores a non-absolute AuthorizedKeysFile, so a path typo would satisfy the non-null anti-lockout
        # check above yet provision no key , the same silent remote lockout. An empty string is refused too.
        && !(adminAccessToplevelEvals {
          authorizedKeys = [ ];
          authorizedKeysFile = "run/keys/admin_authorized_keys";
        }).success
        && !(adminAccessToplevelEvals {
          authorizedKeys = [ ];
          authorizedKeysFile = "";
        }).success;

      # Pure-eval guard for the mesh-interface single source of truth: setting keepNode.mesh.interface
      # once must propagate to every mesh-scoped service's meshInterface, so they cannot drift apart.
      # A refactor that reverts one service to a hardcoded default flips this red.
      meshInterfaceInheritance =
        let
          c =
            (nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [
                wisp.nixosModules.wisp # wisp.nix references services.wisp (upstream module)
                ./nixos/mesh.nix
                ./nixos/wisp.nix
                ./nixos/admin-access.nix
                ./nixos/vault-replication.nix
                {
                  fileSystems."/" = {
                    device = "/dev/disk/by-label/root";
                    fsType = "ext4";
                  };
                  boot.loader.grub.enable = false;
                  keepNode.mesh.interface = "utun-consolidation-probe";
                }
              ];
            }).config;
        in
        c.keepNode.wisp.meshInterface == "utun-consolidation-probe"
        && c.keepNode.adminAccess.meshInterface == "utun-consolidation-probe"
        && c.keepNode.vaultReplication.meshReplication.meshInterface == "utun-consolidation-probe";

      # The full Tier-4 appliance end-state, composed in ONE system: measured boot + frost-gate in oprf
      # mode (sealPcrs 7+11) + the nvpn mesh + vault replication + wisp + admin-access, all enabled at
      # once. This is the stack docs/hardware.md walks an operator to assemble on real hardware, and the
      # only place every module is composed together , the VM tests each cover a subset (measured-seal:
      # measuredBoot + frostGate tpm; oprf-gate: frostGate oprf; mesh-replication: mesh + replication).
      # A cross-module assertion conflict or option clash introduced by a later refactor would otherwise
      # surface only when the operator builds this on metal; forcing toplevel.drvPath under tryEval turns
      # it into an eval-time check (no VM, no hardware). All values are valid eval-only fixtures: paths
      # need not exist (nothing is realised), and the fake npubs/endpoints satisfy the modules' non-null
      # assertions (group/peers[].npub are plain strings, no format check).
      tier4System = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./nixos/keep-node.nix # composes frost-gate + mesh + vault-replication + admin-access + vaultwarden
          ./nixos/appliance.nix # UEFI + fileSystems (measured-boot mkForce-overrides systemd-boot)
          lanzaboote.nixosModules.lanzaboote # measuredBoot sets boot.lanzaboote.*, defined by this input
          ./nixos/measured-boot.nix
          wisp.nixosModules.wisp # wisp.nix references services.wisp, defined by this input
          ./nixos/wisp.nix
          {
            security.tpm2.enable = true;
            keepNode.measuredBoot.enable = true;
            keepNode.frostGate = {
              enable = true;
              mode = "oprf";
              volumeDevice = "/dev/disk/by-id/ata-VAULT-eval-fixture";
              keepPackage = keep-cli;
              keepDbPath = "/var/lib/keep-box";
              group = "npub1eval0only0fixture0group0000000000000000000000000000000000";
              relay = "wss://relay.example:7777";
              keepPasswordCred = "/var/lib/keep-node/keep-password.cred";
              oprfShareCred = "/var/lib/keep-node/oprf-share.cred";
              sealPcrs = [
                7
                11
              ];
              quorum = {
                threshold = 2;
                total = 3;
              };
            };
            keepNode.mesh = {
              enable = true;
              package = nvpn;
              selfEndpoint = "192.0.2.10:51820";
              identityDir = "/run/secrets/nvpn-id";
              stateDir = "/var/lib/vaultwarden/mesh"; # subdir of frostGate.dataDir, per the disjointness guard
              peers = [
                {
                  npub = "npub1eval0only0fixture0peer00000000000000000000000000000000000";
                  endpoint = "192.0.2.11:51820";
                }
              ];
            };
            keepNode.wisp.enable = true;
            keepNode.vaultReplication = {
              rsaKeyFile = "/run/secrets/rsa_key.pem";
              role = "active";
              litestream.enable = true;
              meshReplication.enable = true;
            };
            keepNode.adminAccess = {
              enable = true;
              authorizedKeys = [ "ssh-ed25519 AAAAeval-only-fixture-key keepadmin-eval" ];
            };
          }
        ];
      };
      tier4CompositionEvals = builtins.tryEval tier4System.config.system.build.toplevel.drvPath;

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
        keep-state-replication = pkgs.testers.runNixOSTest {
          imports = [ ./tests/keep-state-replication.nix ];
          _module.args = {
            keepWebPackage = keep-web;
            wispModule = wisp.nixosModules.wisp;
          };
        };
        vw-client-check = pkgs.testers.runNixOSTest {
          imports = [ ./tests/vw-client-check.nix ];
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
            wispModule = wisp.nixosModules.wisp;
          };
        };
        oprf-gate-2of3 = pkgs.testers.runNixOSTest {
          imports = [ ./tests/oprf-gate-2of3.nix ];
          _module.args = {
            keepCliPackage = keep-cli;
            frostGroupFixture = frostGroupFixture2of3;
            wispModule = wisp.nixosModules.wisp;
          };
        };
        duress-freeze = pkgs.testers.runNixOSTest {
          imports = [ ./tests/duress-freeze.nix ];
          _module.args = {
            keepCliPackage = keep-cli;
            wispModule = wisp.nixosModules.wisp;
          };
        };
        oprf-attestation-reject = pkgs.testers.runNixOSTest {
          imports = [ ./tests/oprf-attestation-reject.nix ];
          _module.args = {
            keepCliPackage = keep-cli;
            wispModule = wisp.nixosModules.wisp;
          };
        };
        oprf-unlock = pkgs.testers.runNixOSTest {
          imports = [ ./tests/oprf-unlock.nix ];
          _module.args = {
            keepCliPackage = keep-cli;
            wispModule = wisp.nixosModules.wisp;
          };
        };
        oprf-unlock-2of3 = pkgs.testers.runNixOSTest {
          imports = [ ./tests/oprf-unlock-2of3.nix ];
          _module.args = {
            keepCliPackage = keep-cli;
            wispModule = wisp.nixosModules.wisp;
          };
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
        adminaccess-bringup-scoping = pkgs.runCommand "adminaccess-bringup-scoping" { } (
          if lanBringupScopingHolds then
            "touch $out"
          else
            "echo 'adminAccess bring-up firewall scoping regression: with lanBringupInterface set the SSH opening was not scoped to the named NIC (it hit the global all-interface list) or dropped the mesh interface opening, or the named NIC opening leaked into the null-fallback/off cases, or the null fallback stopped opening the global list' >&2; exit 1"
        );
        adminaccess-antilockout = pkgs.runCommand "adminaccess-antilockout" { } (
          if adminAccessAntiLockoutHolds then
            "touch $out"
          else
            "echo 'adminAccess anti-lockout regression: the module either built with no usable key (empty or whitespace-only authorizedKeys and no authorizedKeysFile, a permanent key-only-SSH remote lockout) or refused a valid config (a real inline key, or the installer authorizedKeysFile escape)' >&2; exit 1"
        );
        mesh-interface-consolidation = pkgs.runCommand "mesh-interface-consolidation" { } (
          if meshInterfaceInheritance then
            "touch $out"
          else
            "echo 'mesh interface consolidation regression: keepNode.mesh.interface did not propagate to one of keepNode.{wisp,adminAccess,vaultReplication.meshReplication}.meshInterface (a service reverted to a hardcoded default and can drift from nvpn device)' >&2; exit 1"
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
        installer-guards = pkgs.testers.runNixOSTest {
          imports = [ ./tests/installer-guards.nix ];
          _module.args = {
            inherit adminKeyFixture;
            # install-keepnode's guards abort before the install, so the embedded closure is never
            # installed (it is still built into the test VM's store) -- a minimal stand-in keeps the
            # test build light instead of the full appliance.
            keepnodeToplevel =
              (nixpkgs.lib.nixosSystem {
                inherit system;
                modules = [
                  {
                    boot.loader.grub.enable = false;
                    fileSystems."/" = {
                      device = "/dev/vda";
                      fsType = "ext4";
                    };
                    system.stateVersion = "24.11";
                  }
                ];
              }).config.system.build.toplevel;
          };
        };
        wisp-mesh = pkgs.testers.runNixOSTest {
          imports = [ ./tests/wisp-mesh.nix ];
          _module.args = {
            nvpnPackage = nvpn;
            inherit nvpnIdentityFixture;
            wispModule = wisp.nixosModules.wisp;
          };
        };
        mesh-discovery = pkgs.testers.runNixOSTest {
          imports = [ ./tests/mesh-discovery.nix ];
          _module.args = {
            nvpnPackage = nvpn;
            inherit nvpnIdentityFixture;
            wispModule = wisp.nixosModules.wisp;
          };
        };
        mesh-replication = pkgs.testers.runNixOSTest {
          imports = [ ./tests/mesh-replication.nix ];
          _module.args = {
            nvpnPackage = nvpn;
            inherit vaultRsaKeyFixture;
          };
        };
        # The UEFI installer ISO an operator flashes to bring up a box (docs/hardware.md: `nix build
        # .#installer-iso` -> dd to USB). It is a shipped artifact but was not gated by CI, so a module
        # change or keep bump could silently break the one image the hardware bring-up depends on, found
        # only when flashing on the day. Building it here (same expression as packages.installer-iso)
        # catches that on push-to-main / full-ci; it is excluded from the per-PR fast subset.
        installer-iso = installerSystem.config.system.build.isoImage;
        # Guards that the full documented Tier-4 stack (measuredBoot + frostGate oprf + mesh + vault
        # replication + wisp + admin-access, all enabled together) still evaluates its system toplevel.
        # tryEval turns a cross-module assertion conflict or an undefined-option error (e.g. a module
        # claiming an option another also sets, or a dropped lanzaboote/wisp import) into a red check at
        # eval time, instead of when the operator assembles the stack on real hardware.
        tier4-composition = pkgs.runCommand "tier4-composition" { } (
          if tier4CompositionEvals.success then
            "touch $out"
          else
            "echo 'Tier-4 appliance composition regression: the full end-state (measuredBoot + frostGate oprf + mesh + vaultReplication + wisp + adminAccess enabled together, the stack docs/hardware.md builds on real hardware) failed to evaluate its system toplevel. A later refactor introduced a cross-module assertion conflict or an undefined-option error (e.g. a module now claims an option another module sets, a coupling assertion became unsatisfiable, or a lanzaboote/wisp input import was dropped).' >&2; exit 1"
        );
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
