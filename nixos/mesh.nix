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
  # Relay-based discovery replaces static per-peer endpoints: keep the npub roster, drop the endpoints,
  # turn on Nostr discovery, and write the relay list into config.toml ([nostr].relays; no `set` flag).
  discoveryEnabled = cfg.discovery.enable;
  relaysToml = lib.concatMapStringsSep ", " (r: ''"${r}"'') cfg.discovery.relays;
  # `nvpn set` roster args: each peer is both a participant and a static endpoint hint. This node's own
  # npub is added at runtime (read from the placed identity), since it isn't known at eval time.
  participantArgs = lib.concatMapStringsSep " " (
    p: "--participant ${lib.escapeShellArg p.npub}"
  ) cfg.peers;
  peerEndpointArgs = lib.concatMapStringsSep " " (
    p: "--fips-peer-endpoint ${lib.escapeShellArg "${p.npub}=${p.endpoint}"}"
  ) cfg.peers;
  # Flags shared by both `nvpn set` mode branches below: this node's own network id, listen port, and
  # advertised endpoint. Each branch then appends its mode-specific discovery/endpoint flags.
  baseSetArgs = "--network-id ${lib.escapeShellArg cfg.networkId} --listen-port ${toString cfg.listenPort} --fips-advertise-endpoint true --endpoint ${lib.escapeShellArg cfg.selfEndpoint}";
in
{
  imports = [ ./mesh-interface.nix ];

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
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "192.0.2.11:51820";
              description = ''
                The peer's advertised underlay endpoint (`ip:port`). Required in static mode; leave null
                (the default) in `discovery.enable` mode, where the endpoint is discovered over a relay.
              '';
            };
          };
        }
      );
    };

    discovery = {
      enable = lib.mkEnableOption ''
        relay-based endpoint discovery instead of static peer endpoints: peers advertise and learn each
        other's current address over a Nostr relay (nvpn kind-37195 adverts), so nodes with dynamic or
        LAN-local addresses form the mesh without a fixed `endpoint` per peer. The npub roster
        (`peers[].npub`) still gates who may join, so authenticity stays npub-gated; the relay only
        brokers addresses for already-trusted npubs. It is, though, an availability and metadata
        dependency: it sees the adverts (npubs + endpoints) and, if unreachable, discovery stalls'';

      relays = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "wss://bootstrap.example.com:7777" ];
        description = ''
          Nostr relay URLs peers use to discover each other (written to `[nostr] relays`). These must be
          reachable OFF the mesh (a not-yet-meshed node can't use the mesh-bound relay to join), e.g. a
          bootstrap wisp on a reachable address. Use `wss://`: in discovery mode the node publishes its
          npub and advertised endpoint to these relays, so over plaintext `ws://` that mesh metadata is
          cleartext and unauthenticated, readable/tamperable by an on-path attacker. `ws://` is rejected
          unless `allowInsecureWs` is set. nvpn refuses to advertise RFC1918 addresses, so a node behind
          a private address advertises whatever routable endpoint it is given (`selfEndpoint`).
        '';
      };

      allowInsecureWs = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Test-only. When true, `discovery.relays` may use plaintext `ws://` instead of `wss://`. This
          exists solely so the VM test can run against an in-VM plaintext wisp relay; it MUST never be
          enabled in production, where discovery adverts (npub + endpoint) must stay over TLS (`wss://`).
        '';
      };
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
        # The node advertises its own dialable address (selfEndpoint) in BOTH modes; discovery only
        # changes how PEERS' addresses are learned (over the relay vs configured), not the node's own.
        assertion = !declarative || cfg.selfEndpoint != null;
        message = "keepNode.mesh.peers is set (declarative onboarding) but keepNode.mesh.selfEndpoint is null: the node must advertise its own ip:port endpoint (statically to peers, or over the relay in discovery mode).";
      }
      {
        # Static mode dials each peer at a fixed endpoint; discovery mode learns it over a relay.
        assertion = !declarative || discoveryEnabled || lib.all (p: p.endpoint != null) cfg.peers;
        message = "keepNode.mesh: every peer needs an `endpoint` in static mode (or set keepNode.mesh.discovery.enable to discover endpoints over a relay).";
      }
      {
        assertion = !discoveryEnabled || cfg.discovery.relays != [ ];
        message = "keepNode.mesh.discovery.enable is true but keepNode.mesh.discovery.relays is empty: peers need at least one off-mesh Nostr relay to discover each other over.";
      }
      {
        # discovery.enable only takes effect through the declarative provisioning block, which is gated on
        # a non-empty peers roster; with peers = [] the whole block AND wantedBy = multi-user.target are
        # skipped, so the mesh would silently never start.
        assertion = !discoveryEnabled || declarative;
        message = "keepNode.mesh.discovery.enable is true but keepNode.mesh.peers is empty: discovery is provisioned only for a declarative roster, so with no peers the mesh is never started. Provide the peer npub roster in keepNode.mesh.peers.";
      }
      {
        # discovery.relays are the one external value in this module interpolated RAW (no escapeShellArg)
        # into the root-run sed program and into config.toml. Constrain every entry to a ws(s):// URL over
        # a safe charset so no shell/sed/TOML metacharacter (quote, backslash, bracket, newline, ...) can
        # inject into the prepare unit or corrupt the TOML -- this is what makes that raw write safe.
        assertion =
          !discoveryEnabled
          || lib.all (r: builtins.match "wss?://[A-Za-z0-9.:/_%?=&#-]+" r != null) cfg.discovery.relays;
        message = "keepNode.mesh.discovery.relays must each be a ws:// or wss:// URL using only the characters [A-Za-z0-9.:/_%?=&#-]: a relay containing shell or TOML metacharacters would inject into the root prepare unit's config.toml write.";
      }
      {
        # In discovery mode the node publishes its npub + advertised endpoint to these relays; over
        # plaintext ws:// that metadata is cleartext and the relay is unauthenticated (eavesdrop/MITM of
        # adverts). Require wss:// unless the test-only allowInsecureWs opt-in is set. Mirrors the same
        # gate on keepNode.frostGate.allowInsecureWs.
        assertion =
          !discoveryEnabled
          || cfg.discovery.allowInsecureWs
          || lib.all (r: lib.hasPrefix "wss://" r) cfg.discovery.relays;
        message = "keepNode.mesh.discovery.relays contains a plaintext ws:// relay: discovery publishes this node's npub and advertised endpoint over them, so they must be wss://. Set keepNode.mesh.discovery.allowInsecureWs = true to permit ws:// (TEST-ONLY: the adverts then travel in cleartext and are MITM-able, and it must never be set on a real deployment).";
      }
      {
        # Declarative onboarding pins peers to the npubs baked into each node's static roster (relay
        # discovery is off). Self-generating an identity here yields a RANDOM npub no peer lists, so the
        # mesh silently never forms -- the self npub must be fixed at deploy time via a pre-placed identity.
        assertion = !declarative || cfg.identityDir != null;
        message = "keepNode.mesh.peers is set (declarative onboarding) but keepNode.mesh.identityDir is null: the node would self-generate a random npub that no peer's roster lists, so the mesh would never form. Provide a pre-generated identity so this node's npub is fixed at deploy time.";
      }
      {
        # The whole reason identityDir is a path STRING (not a Nix path) is to keep the mesh secret key
        # off the world-readable /nix/store. A path literal (`./secrets/a`) coerces into the store, 0444
        # and pushed to any binary cache -- exactly the cleartext-key leak the FROST gate exists to stop.
        # Reject it at eval time instead of leaving it to the option's prose.
        assertion = cfg.identityDir == null || !lib.hasPrefix builtins.storeDir cfg.identityDir;
        message = "keepNode.mesh.identityDir (${toString cfg.identityDir}) is inside the Nix store: that copies the mesh Nostr secret key into the world-readable /nix/store. Deliver it out-of-band to a path on the target host (e.g. /run/secrets/... via agenix/sops), never as a Nix path literal.";
      }
    ];

    # Dedicated non-root identity the mesh daemon runs as, so a boringtun/Nostr RCE cannot read
    # root-owned secrets on disk. A FIXED system user (not DynamicUser): the identity dir persists on
    # the encrypted volume across boots and must keep a stable owner, and StateDirectory cannot express
    # the LUKS-mapper placement the prepare unit's guard requires.
    users.users.keep-node-mesh = {
      isSystemUser = true;
      group = "keep-node-mesh";
      description = "keep-node nvpn mesh daemon";
    };
    users.groups.keep-node-mesh = { };

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
    systemd.tmpfiles.rules = lib.optionals (!gateEnabled) [
      "d ${cfg.stateDir} 0700 keep-node-mesh keep-node-mesh -"
    ];

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
                # Place the secret first and move config.toml (the idempotency sentinel above) into place
                # LAST: an install interrupted between the two files must never leave a config.toml without
                # its secret key, or the guard would skip re-install on every later boot and the daemon
                # would never come up. config.toml existing therefore implies the secret is present too.
                install -m 0600 ${lib.escapeShellArg cfg.identityDir}/secret "$cfgdir/.config.toml.nostr-secret-key.secret"
                install -m 0600 ${lib.escapeShellArg cfg.identityDir}/config.toml "$cfgdir/config.toml.tmp"
                mv -f "$cfgdir/config.toml.tmp" "$cfgdir/config.toml"
              ''
            else
              ''HOME="$d" ${lib.getExe cfg.package} init''
          }
        fi
        ${lib.optionalString declarative ''
          # Declarative onboarding: apply the npub roster, then either static endpoints or discovery.
          # This node is a participant too; read its own npub from the placed identity.
          selfnpub="$(${pkgs.gawk}/bin/awk '/^\[nostr\]/{n=1;next} /^\[/{n=0} n&&/^public_key/{print $3}' "$cfgdir/config.toml" | tr -d '"')"
          [ -n "$selfnpub" ] || { echo "keep-node-mesh-prepare: could not read this node's npub from $cfgdir/config.toml" >&2; exit 1; }
          # Publish the resolved npub (public value) so consumers read this one file instead of
          # re-parsing config.toml's TOML with their own copy of the brittle awk above.
          printf '%s' "$selfnpub" > "$d/selfnpub"
          # Roster first on the ACTIVE network, THEN the network-id: combining `--network-id` with
          # `--participant` makes nvpn SELECT a network by that id (which does not exist yet) -> "network
          # not found"; on its own `--network-id` renames the active network.
          HOME="$d" ${lib.getExe cfg.package} set --participant "$selfnpub" ${participantArgs}
          ${
            if discoveryEnabled then
              ''
                # Discovery mode: peers advertise + learn endpoints over the relay(s), so no static
                # `--endpoint`/`--fips-peer-endpoint`. This node still advertises its OWN address
                # (--endpoint) so peers can dial it; only the PEERS' endpoints are discovered. Without a
                # concrete own endpoint, a wildcard bind falls to STUN, and with no reachable STUN server
                # the node advertises nothing and the mesh never forms (true dynamic-IP nodes need
                # STUN/external discovery, out of scope here). nvpn refuses to advertise RFC1918
                # addresses, so selfEndpoint must be a routable address peers can reach.
                HOME="$d" ${lib.getExe cfg.package} set ${baseSetArgs} \
                  --fips-nostr-discovery-enabled true \
                  --fips-bootstrap-enabled false
                # `nvpn set` has no relay flag, so write [nostr].relays into config.toml -- AFTER the set
                # above, whose read-modify-write of config.toml would otherwise drop it. `nvpn init` seeds
                # its own default PUBLIC relays, so an append-only guard would never apply the configured
                # relay; instead converge to the desired set on every boot (rotation-safe: an operator can
                # drop a hostile relay). Delete any existing relays line, then insert the configured one
                # under [nostr]: idempotent, no duplicate TOML key. The relay URLs are asserted to be
                # ws(s):// over a safe charset, so this raw interpolation cannot inject shell/sed/TOML
                # metacharacters.
                ${pkgs.gnused}/bin/sed -i \
                  -e '/^relays = /d' \
                  -e '/^\[nostr\]/a relays = [ ${relaysToml} ]' \
                  "$cfgdir/config.toml"
              ''
            else
              ''
                # Static mode: dial each peer at its fixed endpoint; disable Nostr discovery AND
                # bootstrap-peer transit (nvpn init seeds public fips_bootstrap_peers, "dialed as fallback
                # transit", which would phone home to third-party relays). Every endpoint is set, so
                # neither is needed; this keeps traffic on the operator's own endpoints only.
                HOME="$d" ${lib.getExe cfg.package} set ${baseSetArgs} \
                  ${peerEndpointArgs} \
                  --fips-nostr-discovery-enabled false \
                  --fips-bootstrap-enabled false
              ''
          }
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
      # Runs as a dedicated NON-root user. Opening /dev/net/tun needs CAP_NET_ADMIN, not uid 0
      # (the device is mode 0666 and boringtun's TUNSETIFF only needs the capability, which is granted
      # ambiently below and survives exec into `ip`), so the daemon , which parses hostile
      # WireGuard/Nostr traffic , holds no ability to READ other root-owned secrets on disk (DAC denies
      # it), closing the confidentiality gap that ProtectSystem alone could not. Same pattern as the
      # userspace-tun VPN units in nixpkgs (geph, firezone, lokinet).
      serviceConfig = {
        User = "keep-node-mesh";
        Group = "keep-node-mesh";
        # CAP_NET_ADMIN must act on the HOST network namespace and real tun device, so do not let a
        # user namespace shadow it (nixpkgs geph/firezone set this explicitly for the same reason).
        PrivateUsers = false;
        # The identity dir is created by root , the prepare unit (gated/declarative) or a manual
        # `nvpn init` , so hand it to the daemon user at every start. `+` runs this as root regardless
        # of User= above; it is idempotent and covers all onboarding paths without weakening the
        # prepare unit's encrypted-volume placement guard.
        ExecStartPre = "+${pkgs.coreutils}/bin/chown -R keep-node-mesh:keep-node-mesh ${cfg.stateDir}";
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
        # allow-listed explicitly (DevicePolicy=closed denies all other device nodes). With the non-root
        # User= above this now also confines CONFIDENTIALITY: DAC alone denies a compromised daemon the
        # root-owned key files ProtectSystem left readable (it only remounts read-only). A later
        # host-DNS increment (nvpn's `.fips` resolver writes /etc/systemd/resolved.conf.d) will need
        # those /etc paths added here; the static relay-less mesh in this increment does not.
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
