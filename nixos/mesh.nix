# keep-node mesh transport: the encrypted node-to-node overlay that carries vault replication
# between nodes. Runs nostr-vpn's `nvpn` daemon (boringtun USERSPACE WireGuard + Nostr-authenticated
# peers) headless. This first increment packages and runs the daemon and forms a static two-node
# mesh; a later increment points the replicator at the peer's mesh IP. boringtun means the daemon
# needs only /dev/net/tun (the generic tun module) plus CAP_NET_ADMIN, never a kernel `wg` module,
# which is all a plain VM provides.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.keepNode.mesh;
  # When the FROST gate encrypts the vault volume, the mesh identity (a Nostr private key) must not be
  # persisted in the clear: it has to live on the mounted encrypted volume, and never be written to the
  # bare root fs if the gate failed to unlock. Same fail-closed rule the rsa-key installer follows.
  gateEnabled = config.keepNode.frostGate.enable or false;
  # The gate mounts the decrypted LUKS mapper here; the prepare guard requires the identity dir to be
  # backed by exactly this device, matching the frost-gate mount guard.
  mapperDevice = "/dev/mapper/${config.keepNode.frostGate.mapperName or "keep-vault"}";
  # Declarative onboarding is on once a static roster is configured. It provisions + boot-enables the
  # mesh from config; empty `peers` leaves the old manual (test/onboard-by-hand) behaviour untouched.
  declarative = cfg.peers != [ ];
  # `nvpn set` roster args: each peer is both a participant and a static endpoint hint. This node's own
  # npub is added at runtime (read from the placed identity), since it isn't known at eval time.
  participantArgs = lib.concatMapStringsSep " " (
    p: "--participant ${lib.escapeShellArg p.npub}"
  ) cfg.peers;
  peerEndpointArgs = lib.concatMapStringsSep " " (
    p: "--fips-peer-endpoint ${lib.escapeShellArg "${p.npub}=${p.endpoint}"}"
  ) cfg.peers;
in
{
  options.keepNode.mesh = {
    enable = lib.mkEnableOption "nvpn encrypted mesh transport (nostr-vpn)";

    package = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "The nvpn package (built from mmalmi/nostr-vpn).";
    };

    listenPort = lib.mkOption {
      type = lib.types.port;
      default = 51820;
      description = "UDP port the mesh (boringtun WireGuard underlay) listens on; opened in the firewall.";
    };

    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/keep-node-mesh";
      description = ''
        HOME for the nvpn daemon: its Nostr mesh identity (`.config/nvpn/config.toml`, a secret key)
        lives here. On a FROST-gated node this MUST sit on the encrypted volume (e.g. a subdirectory of
        `keepNode.frostGate.dataDir`), so the mesh private key is not persisted in the clear; a
        fail-closed guard refuses to start the mesh unless it resolves onto the encrypted mapper while
        the gate is enabled. Defaults to a plain state dir, correct for an ungated bring-up node.
      '';
    };

    # --- Declarative onboarding (co-owned cluster, static endpoints) ---
    # When `peers` is set, the mesh is provisioned + started from config at boot with no imperative
    # `nvpn init/set`: the node joins a mutual static roster the operator authored (both npubs known at
    # deploy time). This is the path upstream nvpn proves (static endpoints, no relay discovery).
    networkId = lib.mkOption {
      type = lib.types.str;
      default = "keepnode";
      description = "The shared mesh network id all nodes in the cluster set (`nvpn set --network-id`).";
    };

    selfEndpoint = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "192.0.2.10:51820";
      description = ''
        This node's own advertised underlay endpoint (`ip:port`) that peers dial. Required for
        declarative onboarding (`peers` set). Static-endpoint mesh, so peers reach it here directly.
      '';
    };

    peers = lib.mkOption {
      default = [ ];
      description = ''
        The static roster of OTHER nodes in the cluster. Non-empty turns on declarative onboarding:
        the mesh identity, roster, and peer endpoints are applied from this config at boot and the
        daemon comes up with no manual `nvpn set`. Each peer's npub must be known at deploy time (the
        operator owns the cluster). Empty leaves the mesh in manual/onboarding-by-hand mode.
      '';
      type = lib.types.listOf (
        lib.types.submodule {
          options = {
            npub = lib.mkOption {
              type = lib.types.str;
              description = "The peer's nvpn Nostr identity (npub).";
            };
            endpoint = lib.mkOption {
              type = lib.types.str;
              example = "192.0.2.11:51820";
              description = "The peer's advertised underlay endpoint (`ip:port`).";
            };
          };
        }
      );
    };

    identityDir = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Absolute path string to a pre-generated nvpn identity to install (a directory holding
        `config.toml` and `secret`, as produced by `nvpn init`), instead of self-generating one at
        first boot. Lets the deployer fix each node's npub ahead of time so the roster can be authored
        declaratively. Must be a path string on the target host (delivered out-of-band, e.g. via
        agenix/sops onto the encrypted volume), NOT a Nix-path literal, so the secret key is never
        copied into the world-readable Nix store.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null;
        message = "keepNode.mesh.enable is true but keepNode.mesh.package is null: no nvpn binary to run.";
      }
      {
        assertion = !declarative || cfg.selfEndpoint != null;
        message = "keepNode.mesh.peers is set (declarative onboarding) but keepNode.mesh.selfEndpoint is null: the node must advertise its own ip:port endpoint for peers to reach it.";
      }
    ];

    # boringtun is a userspace WireGuard: the daemon opens /dev/net/tun (generic tun module) and needs
    # CAP_NET_ADMIN, never a kernel wg module. Ensure tun is loadable.
    boot.kernelModules = [ "tun" ];

    # nvpn on PATH for provisioning (init/set) and status (ip/status), by the operator or the test.
    environment.systemPackages = [ cfg.package ];

    # The mesh underlay (WireGuard) speaks UDP on the listen port; peers must reach it.
    networking.firewall.allowedUDPPorts = [ cfg.listenPort ];

    # Ungated: pre-create the identity dir on the (plain) root fs. Gated: DO NOT create it here, since
    # tmpfiles runs at early boot before the FROST volume is mounted and would land it on the
    # unencrypted disk; keep-node-mesh-prepare creates it on the mounted encrypted volume instead.
    systemd.tmpfiles.rules = lib.optionals (!gateEnabled) [ "d ${cfg.stateDir} 0700 root root -" ];

    # Provision the mesh identity (+ the declarative roster). Runs on a gated node (to place the key on
    # the encrypted volume, fail-closed) and/or when `peers` is set (declarative onboarding), before the
    # daemon. On a gated node the mapper guard keeps the private key off unencrypted disk if the gate
    # failed to unlock; mirrors the rsa-key installer's guard.
    systemd.services.keep-node-mesh-prepare = lib.mkIf (gateEnabled || declarative) {
      description = "Provision the nvpn mesh identity + roster (fail-closed on a gated node)";
      after = lib.optional gateEnabled "keep-node-frost-gate.service";
      requires = lib.optional gateEnabled "keep-node-frost-gate.service";
      before = [ "keep-node-mesh.service" ];
      requiredBy = [ "keep-node-mesh.service" ];
      path = [
        pkgs.util-linux
        pkgs.coreutils
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        UMask = "0077";
        PrivateTmp = true;
        TimeoutStartSec = "90s";
      };
      script = ''
        set -euo pipefail
        d=${lib.escapeShellArg cfg.stateDir}
        ${lib.optionalString gateEnabled ''
          # `findmnt -T` needs an existing path, and the identity dir does not exist yet on first run, so
          # walk up to the nearest existing ancestor and resolve the SOURCE device backing THAT. Require
          # it to be the encrypted mapper: a gate that failed to unlock leaves the ancestor on the root
          # fs, and a bind mount / tmpfs / second unencrypted partition would otherwise pass a mere
          # "not /" check -> demand the exact mapper device, so anything but the mounted encrypted volume
          # fails closed rather than persist the mesh key in cleartext. Matches the frost-gate guard.
          p="$d"
          while [ ! -e "$p" ] && [ "$p" != "/" ]; do p="$(dirname "$p")"; done
          src="$(findmnt -nro SOURCE -T "$p" 2>/dev/null || echo none)"
          if [ "$src" != ${lib.escapeShellArg mapperDevice} ]; then
            echo "keep-node-mesh-prepare: identity dir $d is not on the encrypted volume (backing device '$src', expected ${mapperDevice}); refusing to persist the mesh private key in cleartext. Set keepNode.mesh.stateDir onto the encrypted volume (a subdirectory of keepNode.frostGate.dataDir)." >&2
            exit 1
          fi
        ''}
        install -d -m 0700 "$d"
        # Deny group/other on everything created here (the config holds the Nostr private key; the
        # .config dirs would otherwise inherit a looser umask).
        umask 077
        cfgdir="$d/.config/nvpn"
        # Identity: install a pre-generated one (fixed npub, for a declarative roster) or self-generate,
        # HERE past the guard, on the encrypted volume -- never by a raw operator `nvpn init` against an
        # unencrypted path. Idempotent: only when absent, so a redeploy never clobbers the persisted key.
        if [ ! -e "$cfgdir/config.toml" ]; then
          ${
            if cfg.identityDir != null then
              ''
                install -d -m 0700 "$cfgdir"
                install -m 0600 ${lib.escapeShellArg cfg.identityDir}/config.toml "$cfgdir/config.toml"
                install -m 0600 ${lib.escapeShellArg cfg.identityDir}/secret "$cfgdir/.config.toml.nostr-secret-key.secret"
              ''
            else
              ''HOME="$d" ${lib.getExe cfg.package} init''
          }
        fi
        ${lib.optionalString declarative ''
          # Declarative roster + STATIC peer endpoints (no relay discovery -- the path upstream proves).
          # This node is a participant too; read its own npub from the placed identity.
          selfnpub="$(${pkgs.gawk}/bin/awk '/^\[nostr\]/{n=1;next} /^\[/{n=0} n&&/^public_key/{print $3}' "$cfgdir/config.toml" | tr -d '"')"
          [ -n "$selfnpub" ] || { echo "keep-node-mesh-prepare: could not read this node's npub from $cfgdir/config.toml" >&2; exit 1; }
          # Two calls, mirroring the proven tests/mesh.nix sequence: set the roster on the ACTIVE
          # network first, THEN the network-id + endpoints. Combining `--network-id` with `--participant`
          # makes nvpn try to SELECT a network by that id (which does not exist yet) -> "network not
          # found"; on its own, `--network-id` renames the active network.
          HOME="$d" ${lib.getExe cfg.package} set --participant "$selfnpub" ${participantArgs}
          HOME="$d" ${lib.getExe cfg.package} set --network-id ${lib.escapeShellArg cfg.networkId} \
            --listen-port ${toString cfg.listenPort} --fips-advertise-endpoint true \
            --endpoint ${lib.escapeShellArg cfg.selfEndpoint} \
            ${peerEndpointArgs} \
            --fips-nostr-discovery-enabled false
        ''}
      '';
    };

    systemd.services.keep-node-mesh = {
      description = "nvpn encrypted mesh transport (nostr-vpn private mesh)";
      # Order after the provision unit whenever it exists (gated node, or declarative onboarding): it
      # places the identity on the encrypted volume and applies the roster before the daemon connects.
      after = lib.optional (gateEnabled || declarative) "keep-node-mesh-prepare.service";
      requires = lib.optional (gateEnabled || declarative) "keep-node-mesh-prepare.service";
      # Declarative onboarding: bring the mesh up at boot from config (identity + roster provisioned by
      # keep-node-mesh-prepare). Without a static roster, stay manual (started by onboarding/the test)
      # so an unconfigured node never auto-connects to nothing.
      wantedBy = lib.optional declarative "multi-user.target";
      # The daemon shells out to `ip` (iproute2) to configure its userspace-WireGuard tun interface
      # and routes; without it on PATH, tunnel setup fails with ENOENT.
      path = [ pkgs.iproute2 ];
      # The daemon still runs as root (opening /dev/net/tun needs it here), but its filesystem blast
      # radius is locked down below; dropping to a dedicated non-root User= is the remaining hardening
      # step (blocked on making /dev/net/tun reachable without uid 0).
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} connect";
        # nvpn reads $HOME/.config/nvpn/config.toml.
        Environment = "HOME=${cfg.stateDir}";
        Restart = "on-failure";
        RestartSec = 2;
        # Even while running as root, bound the process to the one capability boringtun needs
        # (open /dev/net/tun, configure the interface via `ip`): without a CapabilityBoundingSet a
        # root process keeps the full set, so AmbientCapabilities alone would confine nothing. Pair
        # with NoNewPrivileges so no setuid/setcap helper can regain dropped caps.
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        NoNewPrivileges = true;
        # Filesystem confinement: the daemon parses hostile WireGuard/Nostr traffic, so a memory-safety
        # bug in boringtun must not be able to write arbitrary files or tamper with the rest of the box.
        # ProtectSystem=strict makes the whole fs read-only except ReadWritePaths (only the mesh
        # identity dir); ProtectHome hides /root and /home; PrivateTmp isolates /tmp. The tun device is
        # allow-listed explicitly (DevicePolicy=closed denies all other device nodes). This is
        # write/integrity confinement, NOT confidentiality: while still running as root the daemon can
        # READ any other root-readable secret on disk (ProtectSystem only remounts read-only, it hides
        # nothing beyond /root and /home) -- closing that read gap is the job of the deferred non-root
        # User= drop, under which DAC alone denies a compromised daemon those root-owned key files. A
        # later host-DNS increment (nvpn's `.fips` resolver writes /etc/systemd/resolved.conf.d) will
        # also need those /etc paths added here; the static relay-less mesh in this increment does not.
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ReadWritePaths = [ cfg.stateDir ];
        DevicePolicy = "closed";
        DeviceAllow = [ "/dev/net/tun rw" ];
        # Kernel- and syscall-surface confinement against that same boringtun-RCE threat, mirroring the
        # Rust relay client hardened in frost-gate.nix. Address families: AF_INET/AF_INET6 for the UDP
        # underlay, AF_NETLINK for the `ip` interface/route setup, AF_UNIX for local libc lookups; every
        # other family is denied (no AF_PACKET raw sniffing, no AF_ALG). @system-service is the standard
        # service syscall allow-set; boringtun is pure-Rust with no JIT, so MemoryDenyWriteExecute blocks
        # injected shellcode without breaking it. ProtectKernelModules is safe because `tun` is loaded at
        # boot (boot.kernelModules above), so the daemon never needs to load a module itself.
        SystemCallFilter = [ "@system-service" ];
        SystemCallArchitectures = "native";
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
      };
    };
  };
}
