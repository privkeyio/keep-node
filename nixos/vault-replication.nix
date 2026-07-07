# Multi-node HA (M1) support for Vaultwarden. First increment: distribute a SHARED JWT signing key
# (rsa_key.pem) to every node. Vaultwarden signs its session JWTs with this key and generates a
# fresh one on first start if absent; if two nodes generate their own, a token minted on the active
# is rejected by a promoted standby and every client is forced to re-authenticate on failover. So
# the whole cluster must share one key: this module installs the operator-provided key into the
# vault data dir BEFORE vaultwarden starts, and only if absent (so a later replicated key is never
# clobbered). Later increments (DB WAL streaming, file replication, promotion) extend this module.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.keepNode.vaultReplication;
  # The vault data dir: the FROST gate mounts the LUKS volume here, and vaultwarden writes
  # db.sqlite3 / rsa_key.pem / attachments here. Matches keepNode.frostGate.dataDir default.
  dataDir = "/var/lib/vaultwarden";
  # Whether the FROST gate encrypts this data dir. When it does, the shared signing key must only
  # be written after the LUKS volume is mounted, never onto the unencrypted root fs.
  gateEnabled = config.keepNode.frostGate.enable or false;
  # The decrypted LUKS mapper the FROST gate mounts at dataDir. The guard requires dataDir to be
  # backed by exactly this device (not merely "a mountpoint"), matching the frost-gate and mesh guards.
  mapperDevice = "/dev/mapper/${config.keepNode.frostGate.mapperName or "keep-vault"}";
  # Fail-closed mount guard shared by the litestream + vault-files replicators. On a gated node it
  # refuses to run unless the FROST LUKS volume is actually mounted at dataDir, so a failed unlock
  # never persists vault data on unencrypted disk. It pins the exact backing device (the encrypted
  # mapper): a bind mount, tmpfs, or second unencrypted partition landing at dataDir would pass a mere
  # `mountpoint` check but must NOT be trusted with the vault DB replica -- so anything but the mapper
  # fails closed. The `+` prefix runs it OUTSIDE the unit's mount namespace: ProtectSystem/ReadWritePaths
  # bind-mounts dataDir inside the sandbox, so an in-namespace check would read as mounted even when the
  # LUKS volume is absent; running on the host mount table makes the check real. Uses absolute paths
  # since `+` execs do not get the unit `path`. Callers wrap this in `lib.optional gateEnabled`.
  mkMountGuard =
    { name, msg }:
    "+"
    + pkgs.writeShellScript name ''
      set -euo pipefail
      src="$(${pkgs.util-linux}/bin/findmnt -nro SOURCE ${lib.escapeShellArg dataDir} 2>/dev/null || echo none)"
      if [ "$src" != ${lib.escapeShellArg mapperDevice} ]; then
        echo ${lib.escapeShellArg msg} >&2
        exit 1
      fi
    '';
  # Shared replicaDir safety check. Used by BOTH the litestream block and the promote block: promote
  # (guarded on rsaKeyFile) restores from replicaDir destructively, so a node with rsaKeyFile set but
  # litestream disabled still needs this validation. On a gated node it keeps the replica on the
  # encrypted volume, and in all cases it keeps replicaDir inside the unit's single ReadWritePaths
  # entry (dataDir) so the sandbox can write it. Reject `/../` so the string prefix can't be escaped
  # off the mount. Also reject replicaDir under the two synced subtrees (attachments/, sends/): the
  # file sync rsyncs those INTO replicaDir, so a replicaDir inside either would recurse and fill disk.
  replicaDirAssertion = {
    assertion =
      lib.hasPrefix "${dataDir}/" cfg.litestream.replicaDir
      && !lib.hasInfix "/../" cfg.litestream.replicaDir
      && !lib.hasPrefix "${dataDir}/attachments" cfg.litestream.replicaDir
      && !lib.hasPrefix "${dataDir}/sends" cfg.litestream.replicaDir;
    message = "keepNode.vaultReplication.litestream.replicaDir must live under ${dataDir}, but not under ${dataDir}/attachments or ${dataDir}/sends (it is set to ${cfg.litestream.replicaDir}), so the replica inherits the vault data dir's encryption, the service sandbox can create it, and the file sync does not rsync a synced subtree into itself.";
  };

  # rsync-daemon config for the standby's receiver. One module, `vault-replica`, mapped to replicaDir
  # and writable. No chroot (the path is absolute and vaultwarden-owned; the daemon already runs as
  # vaultwarden) and no per-module auth: the mesh is the trust boundary (the port is opened only on
  # the mesh interface), so only the rostered, WireGuard-authenticated peer can reach this at all.
  # Defense in depth beside that firewall rule: this writable, unauthenticated module is scoped to the
  # mesh subnet (`hosts allow`/`hosts deny`), so a firewall misconfig or an extra rostered mesh peer
  # cannot alone reach in and overwrite the vault replica -- the source must sit on the 10.44/16 mesh.
  rsyncdConf = pkgs.writeText "keep-node-vault-rsyncd.conf" ''
    pid file = /run/keep-node-vault-receive/rsyncd.pid
    # `max connections` makes rsync take a lock file; keep both under the writable RuntimeDirectory,
    # since the ProtectSystem=strict sandbox makes the default /var/run read-only.
    lock file = /run/keep-node-vault-receive/rsyncd.lock
    use chroot = false
    max connections = 4
    [vault-replica]
      path = ${cfg.litestream.replicaDir}
      # Accept the active's push (an upload) but refuse any pull: `read only = false` alone still
      # serves downloads, so without `write only = true` any 10.44/16 peer could `rsync`/`litestream
      # restore` the whole vault replica out. The active only ever uploads, so this does not block it.
      read only = false
      write only = true
      # Pin munge symlinks so a pushing peer cannot plant traversing/absolute symlinks into
      # replicaDir; do not rely on the implicit default that only holds while `use chroot = false`.
      munge symlinks = true
      hosts allow = 10.44.0.0/16
      hosts deny = *
  '';
in
{
  imports = [ ./mesh-interface.nix ];

  options.keepNode.vaultReplication = {
    rsaKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Absolute path string to the shared Vaultwarden JWT signing key (`rsa_key.pem`, a 2048-bit
        RSA PKCS#8 private key) to install on this node. Generate it ONCE for the cluster and
        deliver the same bytes to every node so a session token minted on the active node is
        accepted by a promoted standby. Must be a path string on the target host, not a Nix-path
        literal, so the private key is never copied into the world-readable Nix store. Null leaves
        Vaultwarden to generate its own per-node key (single-node only). The key is seeded only if
        absent (a later replication step must never be clobbered), so rotating it means deleting
        `rsa_key.pem` on every node before redeploy; changing this path alone is a silent no-op.
      '';
    };
    rsaKeyPubFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional matching public key (`rsa_key.pub.pem`); derived by Vaultwarden if omitted.";
    };

    litestream = {
      enable = lib.mkEnableOption ''
        Litestream WAL streaming of Vaultwarden's SQLite vault DB. On the ACTIVE node this
        continuously ships db.sqlite3's write-ahead log to a replica directory; a standby (or a
        promotion step) restores from it. This increment writes the replica LOCALLY; a later
        increment ships it to the peer over the encrypted transport (the mesh, which does not exist
        yet). The vault DB stays single-writer, so this is active/standby, not active/active
      '';
      replicaDir = lib.mkOption {
        type = lib.types.str;
        default = "${dataDir}/replica";
        description = ''
          Directory Litestream writes the replica to. Defaults to a subdirectory of the vault data
          dir so that on a FROST-gated node it inherits the encrypted, mounted volume: the replica
          reconstructs the vault DB's contents (server-side secrets) and must not land on unencrypted
          disk. Must stay under the data dir (an assertion below enforces that): on a gated node that
          keeps the replica encrypted-at-rest, and it keeps the path inside the service sandbox's
          writable set so Litestream can actually create it.
        '';
      };
    };

    role = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "active"
          "standby"
        ]
      );
      default = null;
      description = ''
        This node's HA role. "active" serves and writes the vault and (with meshReplication) pushes
        its replica dir to the standby; "standby" receives that replica over the mesh and restores
        from it on promotion. null is single-node (no cross-node push/receive). The vault DB is
        single-writer, so exactly one node is active at a time.
      '';
    };

    meshReplication = {
      enable = lib.mkEnableOption ''
        cross-node replication of the vault replica dir over the nvpn mesh. On the active node a
        timer pushes replicaDir to the standby; on the standby an rsync receiver (reachable ONLY
        over the mesh interface) writes it into replicaDir. Requires keepNode.mesh and a set role.
        The mesh already authenticates peers by npub and encrypts (WireGuard), so it is the trust
        boundary here: the receiver's port is opened only on the mesh interface
      '';
      port = lib.mkOption {
        type = lib.types.port;
        default = 8730;
        description = "TCP port the standby's rsync receiver listens on; opened ONLY on the mesh interface.";
      };
      meshInterface = lib.mkOption {
        type = lib.types.str;
        default = config.keepNode.mesh.interface;
        defaultText = lib.literalExpression "config.keepNode.mesh.interface";
        description = ''
          The nvpn mesh interface. The receiver's port is opened only here, so only rostered mesh
          peers (not the LAN or the underlay) can reach it. Defaults to the shared
          `keepNode.mesh.interface` so it can't drift from nvpn's tunnel device.
        '';
      };
      maxLagSeconds = lib.mkOption {
        type = lib.types.ints.positive;
        default = 90;
        description = ''
          Replication-lag threshold for the standby's health signal. The active stamps a heartbeat
          into the replica on every push; the standby's keep-node-vault-lag-check fails (so
          `systemctl is-failed keep-node-vault-lag-check` reads failed) once the received heartbeat is
          older than this, or missing. Set a few push intervals above the ~15s push cadence so a
          transient hiccup does not flap; a sustained breach means the standby is falling behind.
          The signal cross-compares the two nodes' wall clocks, so it assumes they are roughly
          time-synced (NTP); a heartbeat dated slightly in the future (minor clock skew) is treated as
          fresh, not stale, while a large future skew fails as an implausibly wrong active clock.
        '';
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf (cfg.rsaKeyFile != null) {
      # The installer orders before/requiredBy vaultwarden.service; surface a misconfig instead of
      # wiring those ordering deps to a unit that never materializes.
      assertions = [
        {
          assertion = config.services.vaultwarden.enable;
          message = "keepNode.vaultReplication.rsaKeyFile is set but services.vaultwarden.enable is false: the shared-key installer has nothing to seed a key for.";
        }
      ];

      systemd.services.keep-node-vault-rsa-key = {
        description = "Install the shared Vaultwarden JWT signing key (multi-node HA)";
        wantedBy = [ "multi-user.target" ];
        # Must land the key before Vaultwarden starts (it generates its own if the file is absent),
        # and after the FROST gate has mounted the data volume (no-op ordering if the gate is off).
        before = [ "vaultwarden.service" ];
        requiredBy = [ "vaultwarden.service" ];
        after = [ "keep-node-frost-gate.service" ];
        # When the gate encrypts the data dir, bind to it: a failed unlock must abort the installer so
        # the cluster-wide RSA private key is never written to unencrypted disk. Mirrors the `requires`
        # that vaultwarden.service itself places on the gate.
        requires = lib.optional gateEnabled "keep-node-frost-gate.service";
        # `findmnt` (util-linux) is not on the default service PATH; the guard below needs it.
        path = lib.optional gateEnabled pkgs.util-linux;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          d=${lib.escapeShellArg dataDir}
          ${lib.optionalString gateEnabled ''
            # Defense in depth beside the `requires` above: only write onto the mounted, encrypted
            # volume. Pin the exact encrypted mapper (not a bare `mountpoint` check) so a bind mount,
            # tmpfs, or second unencrypted partition landing at dataDir cannot be trusted with the
            # cluster-wide signing key -- matching the litestream/promote/receive guards. If the gate
            # somehow "succeeded" without mounting, fail closed rather than persist the key in cleartext.
            src="$(findmnt -nro SOURCE "$d" 2>/dev/null || echo none)"
            if [ "$src" != ${lib.escapeShellArg mapperDevice} ]; then
              echo "keep-node-vault-rsa-key: $d is not backed by the encrypted mapper (FROST volume not mounted); refusing to write key to unencrypted disk" >&2
              exit 1
            fi
          ''}
          # vaultwarden.service's StateDirectory would create this, but we run first; make it now with
          # the same owner/mode so systemd does not fight us.
          install -d -o vaultwarden -g vaultwarden -m 0700 "$d"
          # Only seed if absent: never clobber a key a future replication step may have delivered.
          if [ ! -e "$d/rsa_key.pem" ]; then
            install -o vaultwarden -g vaultwarden -m 0600 ${lib.escapeShellArg cfg.rsaKeyFile} "$d/rsa_key.pem"
            ${lib.optionalString (cfg.rsaKeyPubFile != null)
              ''install -o vaultwarden -g vaultwarden -m 0644 ${lib.escapeShellArg cfg.rsaKeyPubFile} "$d/rsa_key.pub.pem"''
            }
          fi
        '';
      };
    })

    (lib.mkIf cfg.litestream.enable {
      # The unit hard-requires vaultwarden.service and reads its db.sqlite3; surface a misconfig
      # instead of wiring ordering deps to a unit that never materializes. Also keep replicaDir under
      # the data dir (shared replicaDirAssertion) so the replica (the vault DB's contents) inherits
      # its encryption-at-rest and stays inside the service sandbox's writable set.
      assertions = [
        {
          assertion = config.services.vaultwarden.enable;
          message = "keepNode.vaultReplication.litestream.enable is true but services.vaultwarden.enable is false: Litestream has no vault DB to replicate.";
        }
        replicaDirAssertion
      ];

      # Litestream's precondition: the DB must be in WAL mode. Vaultwarden defaults it on, but pin
      # it so a future config change can't silently break replication.
      services.vaultwarden.config.ENABLE_DB_WAL = true;

      systemd.services.keep-node-litestream = {
        description = "Litestream WAL replication of the Vaultwarden vault DB";
        wantedBy = [ "multi-user.target" ];
        # Replicate a running DB: start after Vaultwarden has created db.sqlite3, and after the FROST
        # gate mounted the (encrypted) data dir.
        after = [
          "vaultwarden.service"
          "keep-node-frost-gate.service"
        ];
        # Requires vaultwarden: without it there is no DB to replicate, so a stopped/failed vault
        # takes the replicator down too. A vault *restart* leaves db.sqlite3 in place, so Litestream
        # keeps following the same file and does not need to restart in lockstep. When the gate
        # encrypts the data dir, also require it: the replica reconstructs the vault DB, so a failed
        # unlock must abort replication rather than write plaintext to disk. Mirrors the RSA installer.
        requires = [ "vaultwarden.service" ] ++ lib.optional gateEnabled "keep-node-frost-gate.service";
        # Disable the start-limit (default 5 restarts / 10s): first-boot schema migrations can exceed
        # that window, and giving up would leave replication silently off forever. Retry until the DB
        # appears. (This is a [Unit] setting, hence not in serviceConfig.)
        startLimitIntervalSec = 0;
        serviceConfig = {
          # Run as the vaultwarden user: it owns the 0700 data dir, so this is the only uid that can
          # read db.sqlite3 and write Litestream's shadow WAL beside it.
          User = "vaultwarden";
          Group = "vaultwarden";
          ExecStartPre =
            # Defense in depth beside the `requires` above: only write the replica onto the mounted,
            # encrypted volume. If the gate "succeeded" without mounting, fail closed rather than
            # reconstruct the vault DB on the unencrypted root fs. See mkMountGuard for why the guard
            # runs `+`-prefixed on the host mount table.
            lib.optional gateEnabled (mkMountGuard {
              name = "keep-node-litestream-mount-guard";
              msg = "keep-node-litestream: ${dataDir} is not backed by the encrypted mapper (FROST volume not mounted); refusing to write the vault-DB replica to unencrypted disk";
            })
            # vaultwarden.service's StateDirectory creates dataDir at 0700; pre-create the replica
            # subdir 0700 so Litestream never widens it (it would create 0755). This runs as the
            # vaultwarden user (no `+` prefix), so the dir is vaultwarden-owned without a chown.
            ++ [
              "${pkgs.coreutils}/bin/install -d -m 0700 ${lib.escapeShellArg cfg.litestream.replicaDir}"
            ];
          ExecStart = "${pkgs.litestream}/bin/litestream replicate ${lib.escapeShellArg "${dataDir}/db.sqlite3"} ${lib.escapeShellArg "file://${cfg.litestream.replicaDir}"}";
          # db.sqlite3 does not exist until Vaultwarden's first start finishes creating it; retry
          # rather than fail the boot (start-limit disabled above so retries never exhaust).
          Restart = "on-failure";
          RestartSec = 2;
          # Local file:// replica: no network, no privilege escalation, read-only fs except the data
          # dir where db.sqlite3 and the replica (+ its shadow WAL) live.
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          ReadWritePaths = [ dataDir ];
        };
      };

      # Litestream replicates ONLY db.sqlite3, never the attachment/Send files it references
      # (attachments/<cipher>/<id>, sends/<id> -- E2E ciphertext on disk). This sync mirrors those into
      # the same replica dir so a promoted standby has the files a restored row points at. The standalone
      # timer below keeps replicaDir current between pushes; keep-node-vault-mesh-push ALSO pulls this
      # sync in immediately before each push (Wants/After), so the pushed replicaDir has files as fresh
      # as the sync's most recent completion. This NARROWS (does not close) the row-before-file window at
      # the standby: the shipped db.sqlite3 still lags live by litestream's flush interval L (~1s), so a
      # row is only guaranteed to have its file present when the file-sync rsync scan finished within L of
      # the DB snapshot -- i.e. only while the scan duration < litestream lag. On a large attachments/ tree
      # the rsync directory walk can exceed ~1s, leaving a residual gap. Narrowing still matters because
      # once the active is gone at promote time a missing-file gap can no longer self-heal.
      systemd.services.keep-node-vault-files = {
        description = "Replicate Vaultwarden attachments + Sends (multi-node HA)";
        after = [
          "vaultwarden.service"
          "keep-node-frost-gate.service"
        ];
        requires = [ "vaultwarden.service" ] ++ lib.optional gateEnabled "keep-node-frost-gate.service";
        serviceConfig = {
          Type = "oneshot";
          User = "vaultwarden";
          Group = "vaultwarden";
          # Same fail-closed guard as the DB replica: never mirror the (E2E-ciphertext, but still
          # sensitive) files onto unencrypted disk when the gate failed to mount. See mkMountGuard.
          ExecStartPre = lib.optional gateEnabled (mkMountGuard {
            name = "keep-node-vault-files-mount-guard";
            msg = "keep-node-vault-files: ${dataDir} is not backed by the encrypted mapper (FROST volume not mounted); refusing to mirror vault files to unencrypted disk";
          });
          ExecStart = pkgs.writeShellScript "keep-node-vault-files-sync" ''
            set -euo pipefail
            ${pkgs.coreutils}/bin/install -d -m 0700 ${lib.escapeShellArg cfg.litestream.replicaDir}
            # --delete makes this node's local dataDir the source of truth: a file absent from dataDir
            # is deleted from the replica. That is correct ONLY on a node whose dataDir is authoritative
            # (active or single-node). On a standby, replicaDir holds files the active pushed over the
            # mesh while this node's own dataDir is empty, so --delete here would wipe the received
            # replica. It is therefore gated to role != "standby" below (interpolated in): a standby
            # that ever ran this sync adds nothing and removes nothing, leaving the received files intact.
            for sub in attachments sends; do
              # Vaultwarden creates these only on first attachment/Send; ensure the source exists so
              # rsync never errors on a missing source, but with mkdir (not install -m) so we never
              # re-chmod Vaultwarden's own live directory -- replication must not mutate source mode.
              ${pkgs.coreutils}/bin/mkdir -p ${lib.escapeShellArg dataDir}/"$sub"
              # Pre-create the replica subdir at 0700 (the data dir's mode, fail-closed) so rsync -a
              # never widens it past 0700.
              ${pkgs.coreutils}/bin/install -d -m 0700 ${lib.escapeShellArg cfg.litestream.replicaDir}/"$sub"
              # On a live vault Vaultwarden deletes attachments/Sends concurrently, so rsync routinely
              # exits 24 ("some files vanished during transfer") and occasionally 23 ("partial transfer
              # due to error"). Both are benign here and self-heal next cycle, so treat them as success;
              # fail the oneshot only on any other non-zero code.
              rc=0
              ${pkgs.rsync}/bin/rsync -a ${
                lib.optionalString (cfg.role != "standby") "--delete "
              }${lib.escapeShellArg dataDir}/"$sub"/ ${lib.escapeShellArg cfg.litestream.replicaDir}/"$sub"/ || rc=$?
              case "$rc" in
                0 | 23 | 24) ;;
                *) exit "$rc" ;;
              esac
            done
          '';
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          ReadWritePaths = [ dataDir ];
        };
      };
      systemd.timers.keep-node-vault-files = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "20s";
          OnUnitActiveSec = "15s";
          Unit = "keep-node-vault-files.service";
        };
      };
    })

    # Failover promotion. Operator-triggered (NOT wantedBy boot): on loss of the active node, run
    # `systemctl start keep-node-vault-promote` on a standby to make it the active. It restores the
    # vault DB and attachment/Send files from the replica the transport delivered into replicaDir,
    # then (re)starts Vaultwarden. The shared JWT key is already installed (keep-node-vault-rsa-key),
    # so sessions minted on the failed active survive the switch. Guarded on rsaKeyFile so it exists
    # on every HA node (the standby runs it), not only nodes that themselves replicate. On a gated
    # node replicaDir and db.sqlite3 both live on the encrypted mount, and the fail-closed mount guard
    # below refuses to run unless that mount is present, so no plaintext restore hits unencrypted disk.
    #
    # SPLIT-BRAIN WARNING (operator runbook, not yet enforced here): promotion does NOT flip this node's
    # `role`, so a promoted standby keeps running keep-node-vault-receive, and a recovered old active
    # (still role="active") will `--delete`-push its stale replica onto the promoted node, clobbering the
    # authoritative copy. The old active MUST stay down until it is reconfigured (role="standby" or
    # rebuilt from the promoted node) before it is allowed back on the mesh. Fencing is out of scope here.
    (lib.mkIf (cfg.rsaKeyFile != null) {
      # Same replicaDir safety check as the litestream block: this unit restores from replicaDir
      # destructively and may run on a node with litestream disabled, so validate replicaDir here too.
      assertions = [ replicaDirAssertion ];

      systemd.services.keep-node-vault-promote = {
        description = "Promote this node to active: restore the vault from the replica and serve";
        # Order after the FROST gate like the replicators: the restore writes the plaintext vault DB +
        # files, so on a gated node it must land only on the mounted encrypted volume, never bare disk.
        after = [ "keep-node-frost-gate.service" ];
        requires = lib.optional gateEnabled "keep-node-frost-gate.service";
        path = [
          pkgs.coreutils
          pkgs.systemd
        ];
        serviceConfig = {
          Type = "oneshot";
          # Fail-closed guard mirroring the replicators: refuse to restore the plaintext vault onto
          # unencrypted disk when the gate failed to mount. See mkMountGuard for the `+`-prefix reason.
          ExecStartPre = lib.optional gateEnabled (mkMountGuard {
            name = "keep-node-vault-promote-mount-guard";
            msg = "keep-node-vault-promote: ${dataDir} is not backed by the encrypted mapper (FROST volume not mounted); refusing to restore the vault to unencrypted disk";
          });
          # This unit parses bytes a mesh PEER pushed into replicaDir: `litestream restore` (LTX),
          # `sqlite3` (an attacker-derived DB), and the content `rsync`. That is exactly the receiver's
          # untrusted input, but promote historically ran it as UNCONFINED root. Confine it like the
          # rest: it stays root only for `systemctl stop/start vaultwarden` (reaches PID1 over
          # /run/systemd/private, fine under ProtectSystem=strict) and the `chown`/`chmod` of restored
          # files, but the parser blast radius is now bounded -- a memory-safety RCE in
          # sqlite/rsync/litestream can no longer write outside the data dir, exec injected pages, or
          # open arbitrary sockets.
          ProtectSystem = "strict";
          ReadWritePaths = [ dataDir ];
          ProtectHome = true;
          PrivateTmp = true;
          NoNewPrivileges = true;
          # Runs as root, but only to cross the vaultwarden-owned 0700 data dir and fix ownership of the
          # restored files: CAP_DAC_OVERRIDE to read/write across that tree, CAP_CHOWN for `chown -R`,
          # CAP_FOWNER for rsync's `--chmod` on files it does not own. Drop everything else so a parser
          # RCE cannot hold CAP_SYS_RAWIO/CAP_MKNOD; PrivateDevices then scrubs /dev to a minimal set so
          # the raw block-device nodes (/dev/vda, the LUKS mapper) it would otherwise own are gone too --
          # closing the ProtectSystem=strict bypass of writing the raw disk directly.
          CapabilityBoundingSet = [
            "CAP_CHOWN"
            "CAP_DAC_OVERRIDE"
            "CAP_FOWNER"
          ];
          AmbientCapabilities = [ ];
          PrivateDevices = true;
          SystemCallFilter = [ "@system-service" ];
          SystemCallArchitectures = "native";
          # systemctl (AF_UNIX) + any netlink from the tools; no AF_INET (restore/rsync are local).
          RestrictAddressFamilies = [
            "AF_UNIX"
            "AF_NETLINK"
          ];
          MemoryDenyWriteExecute = true;
          RestrictNamespaces = true;
          LockPersonality = true;
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
        script = ''
          set -euo pipefail
          data_dir=${lib.escapeShellArg dataDir}
          replica_dir=${lib.escapeShellArg cfg.litestream.replicaDir}
          [ -d "$replica_dir" ] || { echo "keep-node-vault-promote: no replica at $replica_dir to promote from" >&2; exit 1; }
          # Restore into a temp file FIRST, before touching the live DB: under set -e a partial/corrupt
          # restore, or a replica with no restorable generation, must not leave this node with no DB and
          # the vault down. The restore-to-temp is itself the fail-closed generation guard: litestream
          # restore errors (aborting here, live DB intact) when the replica has nothing to restore, and
          # the sqlite verify below catches an empty/corrupt result -- both before any destructive step.
          # litestream refuses to overwrite an existing file, so restore to a fresh temp name and clean
          # it up on any failure.
          tmp="$data_dir/db.sqlite3.promote-tmp"
          rm -f "$tmp" "$tmp-wal" "$tmp-shm"
          trap 'rm -f "$tmp" "$tmp-wal" "$tmp-shm"' EXIT
          ${pkgs.litestream}/bin/litestream restore -o "$tmp" "file://$replica_dir"
          # Verify the restore opens as a valid SQLite DB before committing to it.
          ${pkgs.sqlite}/bin/sqlite3 "$tmp" 'PRAGMA schema_version;' >/dev/null
          # Only now take the vault down and swap the verified DB in atomically. Stopping vaultwarden
          # also stops keep-node-litestream (it Requires+After vaultwarden), so we resume it below.
          systemctl stop vaultwarden.service || true
          rm -f "$data_dir/db.sqlite3" "$data_dir/db.sqlite3-wal" "$data_dir/db.sqlite3-shm"
          mv "$tmp" "$data_dir/db.sqlite3"
          trap - EXIT
          chown vaultwarden:vaultwarden "$data_dir/db.sqlite3"
          # Bring the attachment/Send files up to the replica's state (the rows reference them).
          for sub in attachments sends; do
            if [ -d "$replica_dir/$sub" ]; then
              # 0700 like the rest of the data dir (never widen to rsync's default 0755).
              ${pkgs.coreutils}/bin/install -d -m 0700 "$data_dir/$sub"
              # The replica arrived over the peer transport (a trust boundary): --no-D drops any
              # device/special files, --safe-links drops absolute/out-of-tree symlinks (attachments
              # and Sends are plain ciphertext files, never symlinks), and --chmod caps restored modes
              # to dir 0700 / file 0600 so a crafted replica cannot land world-readable, special, or
              # escaping-symlink files; chown fixes ownership.
              rc=0
              ${pkgs.rsync}/bin/rsync -a --no-D --safe-links --chmod=D700,F600 --delete "$replica_dir/$sub/" "$data_dir/$sub/" || rc=$?
              # Tolerate 23/24 (partial/vanished) for parity with keep-node-vault-files and robustness.
              case "$rc" in
                0 | 23 | 24) ;;
                *) exit "$rc" ;;
              esac
              chown -R vaultwarden:vaultwarden "$data_dir/$sub"
            fi
          done
          systemctl start vaultwarden.service
          # Stopping vaultwarden above also stopped the replicators (they Require it); resume them so
          # the newly-promoted active streams its WAL + files again and the cluster keeps a replica.
          # Only when they exist on THIS node: they are defined under litestream.enable while promote
          # is under rsaKeyFile, so a promote-only node must not start non-existent units.
          ${lib.optionalString cfg.litestream.enable "systemctl start keep-node-litestream.service keep-node-vault-files.timer"}
        '';
      };
    })

    # Cross-node replication over the nvpn mesh: the active pushes its replica dir to the standby,
    # which receives it into its own replica dir to restore from on promotion. The mesh authenticates
    # peers (npub roster) and encrypts (WireGuard), and the receiver's port is opened ONLY on the mesh
    # interface, so the LAN/underlay cannot reach it -- only the rostered peer.
    (lib.mkIf cfg.meshReplication.enable {
      assertions = [
        {
          assertion = config.keepNode.mesh.enable;
          message = "keepNode.vaultReplication.meshReplication.enable requires keepNode.mesh.enable (the transport it pushes over).";
        }
        {
          assertion = cfg.role != null;
          message = "keepNode.vaultReplication.meshReplication.enable requires keepNode.vaultReplication.role to be \"active\" or \"standby\".";
        }
        replicaDirAssertion
      ];

      # STANDBY: an rsync receiver, running as vaultwarden (the only uid that can write the 0700 data
      # dir), writing the pushed replica into replicaDir.
      systemd.services.keep-node-vault-receive = lib.mkIf (cfg.role == "standby") {
        description = "Receive the vault replica from the active node over the mesh";
        after = [ "keep-node-frost-gate.service" ];
        # When the gate encrypts the data dir, require it: the receiver's install -d + rsync write the
        # vault-DB replica, so a failed unlock must abort here rather than land plaintext on the
        # unencrypted root fs. Mirrors the replicators.
        requires = lib.optional gateEnabled "keep-node-frost-gate.service";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          User = "vaultwarden";
          Group = "vaultwarden";
          RuntimeDirectory = "keep-node-vault-receive"; # holds the daemon pid file
          ExecStartPre =
            # Fail-closed guard beside the `requires` above: refuse to create replicaDir + receive the
            # replica unless the FROST volume is mounted, so the pushed vault-DB replica never lands on
            # unencrypted disk. See mkMountGuard for why it runs `+`-prefixed on the host mount table.
            lib.optional gateEnabled (mkMountGuard {
              name = "keep-node-vault-receive-mount-guard";
              msg = "keep-node-vault-receive: ${dataDir} is not backed by the encrypted mapper (FROST volume not mounted); refusing to receive the vault-DB replica onto unencrypted disk";
            })
            # Pre-create replicaDir (the standby runs no Litestream to create it) at 0700.
            ++ [
              "${pkgs.coreutils}/bin/install -d -m 0700 ${lib.escapeShellArg cfg.litestream.replicaDir}"
            ];
          ExecStart = "${pkgs.rsync}/bin/rsync --daemon --no-detach --port=${toString cfg.meshReplication.port} --config=${rsyncdConf}";
          Restart = "on-failure";
          RestartSec = 2;
          # Bound blast radius: this rsync --daemon is a C parser exposed to any mesh peer, so match the
          # mesh daemon's confinement (it parses less-trusted input yet was harder). No privilege
          # escalation, read-only fs except the data dir, plus the syscall/kernel/namespace lockdown.
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          # This is the single most attacker-reachable parser (a C rsync daemon a hostile peer connects
          # to); scrub /dev so a memory-safety bug cannot reach any world/group-accessible device node.
          PrivateDevices = true;
          ReadWritePaths = [ dataDir ];
          SystemCallFilter = [ "@system-service" ];
          SystemCallArchitectures = "native";
          # AF_INET/AF_INET6 for the mesh TCP it serves, AF_UNIX/AF_NETLINK for libc/local lookups.
          RestrictAddressFamilies = [
            "AF_UNIX"
            "AF_NETLINK"
            "AF_INET"
            "AF_INET6"
          ];
          MemoryDenyWriteExecute = true;
          RestrictNamespaces = true;
          LockPersonality = true;
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

      # Open the receive port ONLY on the mesh interface: the LAN and the WireGuard underlay cannot
      # reach it, only rostered mesh peers.
      # COUPLING: `meshInterface` must match nvpn's actual runtime tun device (default utun100). Nothing
      # in Nix eval can read that runtime name, so the operator MUST keep this option in sync with the
      # device `keepNode.mesh` brings up; a mismatch opens the port on a non-existent iface (fail-closed:
      # unreachable receiver) or, worse, on the wrong one. The rsyncd `hosts allow = 10.44/16` above is
      # the defense-in-depth backstop if this drifts.
      networking.firewall.interfaces.${cfg.meshReplication.meshInterface}.allowedTCPPorts = lib.mkIf (
        cfg.role == "standby"
      ) [ cfg.meshReplication.port ];

      # STANDBY health: the replication-lag signal. The active stamps replicaDir/.push-heartbeat on
      # every push; this reads the RECEIVED heartbeat and fails when it is older than maxLagSeconds (or
      # missing/unreadable), so `systemctl is-failed keep-node-vault-lag-check` is the monitoring
      # signal. A periodic timer runs it. Because the heartbeat advances every push even on an idle
      # active, a fresh heartbeat means "in sync", not merely "no writes lately" -- so this tells a
      # standby that is simply caught up apart from a stalled/partitioned one.
      systemd.services.keep-node-vault-lag-check = lib.mkIf (cfg.role == "standby") {
        description = "Check vault replication lag (standby freshness over the mesh)";
        serviceConfig = {
          Type = "oneshot";
          User = "vaultwarden";
          Group = "vaultwarden";
          ExecStart = pkgs.writeShellScript "keep-node-vault-lag-check" ''
            set -euo pipefail
            heartbeat=${lib.escapeShellArg "${cfg.litestream.replicaDir}/.push-heartbeat"}
            max=${toString cfg.meshReplication.maxLagSeconds}
            if [ ! -r "$heartbeat" ]; then
              echo "keep-node-vault-lag-check: no heartbeat received yet; replication has not delivered a push" >&2
              exit 1
            fi
            stamp="$(${pkgs.coreutils}/bin/head -c 64 "$heartbeat" | ${pkgs.coreutils}/bin/tr -dc '0-9')"
            now="$(${pkgs.coreutils}/bin/date +%s)"
            if [ -z "$stamp" ]; then
              echo "keep-node-vault-lag-check: heartbeat unreadable" >&2
              exit 1
            fi
            lag=$(( now - stamp ))
            # A small negative lag means the active's clock leads ours (minor skew), not staleness: the
            # heartbeat was just received, so treat it as fresh rather than a false alarm. But a large
            # negative lag is an implausibly skewed active clock that would otherwise read fresh forever
            # and mask a real stall, so fail on anything beyond the tolerance. Only genuine over-threshold
            # age fails past that.
            skew=5
            if [ "$lag" -lt "-$skew" ]; then
              echo "keep-node-vault-lag-check: heartbeat is ''${lag}s in the future; clock skew exceeds ''${skew}s" >&2
              exit 1
            fi
            if [ "$lag" -lt 0 ]; then
              lag=0
            fi
            echo "vault replication lag: ''${lag}s (max ''${max}s)"
            if [ "$lag" -gt "$max" ]; then
              echo "keep-node-vault-lag-check: replication lag ''${lag}s exceeds ''${max}s" >&2
              exit 1
            fi
          '';
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
        };
      };
      systemd.timers.keep-node-vault-lag-check = lib.mkIf (cfg.role == "standby") {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "30s";
          OnUnitActiveSec = "30s";
          Unit = "keep-node-vault-lag-check.service";
        };
      };

      # ACTIVE: push the local replica dir to the standby over the mesh on a timer. Runs as root: it
      # reads the mesh daemon's config (HOME) to resolve the peer's mesh IP via `nvpn ip --peer`, and
      # reads the 0700 replica dir. Only the already-encrypted replica bytes leave, over the
      # authenticated mesh, to exactly the rostered peer.
      systemd.services.keep-node-vault-mesh-push = lib.mkIf (cfg.role == "active") {
        description = "Push the vault replica to the standby over the mesh";
        # Order (and pull in) Litestream where it runs on this node so the push does not fire against a
        # not-yet-populated replicaDir on boot; the empty-replica guard below still covers the window.
        # Also pull in a fresh attachment/Send sync (keep-node-vault-files) BEFORE each push, so the
        # pushed replicaDir has files as fresh as the sync's most recent completion. This NARROWS (does
        # not close) the row-before-file window at the standby: the shipped db.sqlite3 still lags live by
        # litestream's flush interval L (~1s), so a row is only guaranteed to have its file present when
        # the file-sync rsync scan finished within L of the DB snapshot -- i.e. only while the scan
        # duration < litestream lag. On a large attachments/ tree the rsync walk can exceed ~1s, leaving a
        # residual gap. Narrowing still matters because the standby cannot self-heal once the active is
        # gone at promote time. Wants (not Requires): a file-sync that fails on 23/24 must not block the
        # push. Note this After also couples the push to vaultwarden's lifecycle (keep-node-vault-files
        # requires+after vaultwarden), so a vaultwarden restart transiently stalls the push chain on the
        # file-sync's start job, bounded by systemd's DefaultTimeoutStartSec (90s).
        after = [
          "keep-node-mesh.service"
        ]
        ++ lib.optionals cfg.litestream.enable [
          "keep-node-litestream.service"
          "keep-node-vault-files.service"
        ];
        wants = lib.optionals cfg.litestream.enable [
          "keep-node-litestream.service"
          "keep-node-vault-files.service"
        ];
        path = [
          pkgs.rsync
          config.keepNode.mesh.package
        ];
        serviceConfig = {
          Type = "oneshot";
          Environment = "HOME=${config.keepNode.mesh.stateDir}";
          ExecStart = pkgs.writeShellScript "keep-node-vault-mesh-push" ''
            set -euo pipefail
            replica=${lib.escapeShellArg cfg.litestream.replicaDir}
            # Refuse to push until the local replica holds a restorable Litestream generation:
            # `rsync --delete` mirrors the source, so shipping a DB-less replicaDir would wipe the
            # standby's only failover DB copy and make promotion impossible. Mere non-emptiness is too
            # weak a guard because keep-node-vault-files pre-creates replicaDir/{attachments,sends}, so
            # replicaDir is non-empty even before any DB generation exists. Litestream's file replica
            # (v0.5 layout) becomes restorable only once it writes LTX files under replicaDir/ltx/
            # (ltx/<level>/<txn>.ltx), so gate on an actual .ltx file. Nothing to ship is not an error.
            set -- "$replica"/ltx/*/*.ltx
            if [ ! -e "$1" ]; then
              echo "keep-node-vault-mesh-push: no restorable DB generation in local replica; skipping push so --delete cannot wipe the standby" >&2
              exit 0
            fi
            # Resolve the single peer's mesh IP (two-node cluster). Empty until the mesh is up; a
            # not-yet-connected mesh is not an error, just nothing to push this cycle.
            peer="$(nvpn ip --peer --discover-secs 0 2>/dev/null | head -n1 | tr -d '[:space:]')"
            if [ -z "$peer" ]; then
              echo "keep-node-vault-mesh-push: no mesh peer yet; skipping this cycle" >&2
              exit 0
            fi
            # Ship the replica first, EXCLUDING the heartbeat so --delete cannot remove the standby's
            # existing one; rsync protects excluded files from --delete by default.
            rsync -a --delete --exclude=/.push-heartbeat "$replica"/ "rsync://$peer:${toString cfg.meshReplication.port}/vault-replica/"
            # Heartbeat for the standby's lag signal: stamp the replica with this push's wall-clock time
            # so that even an idle active (no DB writes) still refreshes it every cycle. The standby
            # compares it to its own clock to tell "a little behind" from "replication stalled". Written
            # and shipped only after the data rsync above succeeds, so it attests a delivered replica, not
            # an attempted push: `set -euo pipefail` guarantees a failed data rsync aborts before this, so
            # the standby keeps its OLD heartbeat and correctly goes stale/unhealthy rather than reading a
            # false "in sync". It also advances iff a real push happened, past every skip guard above.
            ${pkgs.coreutils}/bin/date +%s > "$replica"/.push-heartbeat
            rsync -a "$replica"/.push-heartbeat "rsync://$peer:${toString cfg.meshReplication.port}/vault-replica/"
          '';
          # Bound blast radius like the sibling units: it only reads the local replica and the mesh
          # identity dir (HOME) and pushes over the network. Keep the mesh stateDir writable in case
          # nvpn caches runtime state there; dataDir is read only in practice but kept in the writable
          # set for parity with the replicators.
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          ReadWritePaths = [
            dataDir
            config.keepNode.mesh.stateDir
          ];
          # The push runs as root to traverse the vaultwarden-owned 0700 replica dir and stamp
          # .push-heartbeat into it, so it keeps exactly CAP_DAC_OVERRIDE (DAC bypass across that tree)
          # and nothing else -- dropping the rest, notably CAP_SYS_RAWIO/CAP_MKNOD. PrivateDevices then
          # scrubs /dev so a bug handling `nvpn ip` output or rsync replies cannot open the raw
          # block-device nodes root would otherwise own. AF_INET/6 for the outbound push, AF_UNIX/
          # AF_NETLINK for libc/local lookups.
          CapabilityBoundingSet = [ "CAP_DAC_OVERRIDE" ];
          AmbientCapabilities = [ ];
          PrivateDevices = true;
          SystemCallFilter = [ "@system-service" ];
          SystemCallArchitectures = "native";
          RestrictAddressFamilies = [
            "AF_UNIX"
            "AF_NETLINK"
            "AF_INET"
            "AF_INET6"
          ];
          MemoryDenyWriteExecute = true;
          RestrictNamespaces = true;
          LockPersonality = true;
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
      systemd.timers.keep-node-vault-mesh-push = lib.mkIf (cfg.role == "active") {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "25s";
          OnUnitActiveSec = "15s";
          Unit = "keep-node-vault-mesh-push.service";
        };
      };
    })
  ];
}
