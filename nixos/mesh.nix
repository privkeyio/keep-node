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
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null;
        message = "keepNode.mesh.enable is true but keepNode.mesh.package is null: no nvpn binary to run.";
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

    # Gated only: fail-closed preparation. Runs after the FROST gate, refuses to proceed unless the
    # identity dir resolves onto a real mount (not the '/' root fs), then creates it 0700 on the
    # encrypted volume. This is what keeps the mesh private key off unencrypted disk when the gate is
    # on (and off it entirely if the gate failed to unlock). Mirrors the rsa-key installer's guard.
    systemd.services.keep-node-mesh-prepare = lib.mkIf gateEnabled {
      description = "Prepare the nvpn mesh identity dir on the encrypted volume (fail-closed)";
      after = [ "keep-node-frost-gate.service" ];
      requires = [ "keep-node-frost-gate.service" ];
      before = [ "keep-node-mesh.service" ];
      requiredBy = [ "keep-node-mesh.service" ];
      path = [
        pkgs.util-linux
        pkgs.coreutils
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        d=${lib.escapeShellArg cfg.stateDir}
        # `findmnt -T` needs an existing path, and the identity dir does not exist yet on first run, so
        # walk up to the nearest existing ancestor and resolve the SOURCE device backing THAT. Require
        # it to be the encrypted mapper: a gate that failed to unlock leaves the ancestor on the root fs,
        # and a bind mount / tmpfs / second unencrypted partition would otherwise pass a mere "not /"
        # check -> demand the exact mapper device instead, so anything but the mounted encrypted volume
        # fails closed rather than persist the mesh key in cleartext. Matches the frost-gate mount guard.
        p="$d"
        while [ ! -e "$p" ] && [ "$p" != "/" ]; do p="$(dirname "$p")"; done
        src="$(findmnt -nro SOURCE -T "$p" 2>/dev/null || echo none)"
        if [ "$src" != ${lib.escapeShellArg mapperDevice} ]; then
          echo "keep-node-mesh-prepare: identity dir $d is not on the encrypted volume (backing device '$src', expected ${mapperDevice}); refusing to persist the mesh private key in cleartext. Set keepNode.mesh.stateDir onto the encrypted volume (a subdirectory of keepNode.frostGate.dataDir)." >&2
          exit 1
        fi
        install -d -m 0700 "$d"
      '';
    };

    systemd.services.keep-node-mesh = {
      description = "nvpn encrypted mesh transport (nostr-vpn private mesh)";
      # On a gated node, only start once the identity dir is prepared on the encrypted volume (which
      # itself requires the gate to have unlocked+mounted); no-op ordering on an ungated node.
      after = lib.optional gateEnabled "keep-node-mesh-prepare.service";
      requires = lib.optional gateEnabled "keep-node-mesh-prepare.service";
      # The daemon shells out to `ip` (iproute2) to configure its userspace-WireGuard tun interface
      # and routes; without it on PATH, tunnel setup fails with ENOENT.
      path = [ pkgs.iproute2 ];
      # Deliberately NOT wantedBy multi-user.target in this increment: the mesh identity (`nvpn init`)
      # and the peer roster/endpoints (`nvpn set`) are provisioned first (by onboarding, or by the
      # test), then this is started. A later increment provisions them declaratively and enables it at
      # boot. The daemon still runs as root (opening /dev/net/tun needs it here), but its filesystem
      # blast radius is locked down below; dropping to a dedicated non-root User= is the remaining
      # hardening step (blocked on making /dev/net/tun reachable without uid 0).
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
