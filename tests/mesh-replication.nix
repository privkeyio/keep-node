# M1 mesh transport (PR-b): ship the Litestream vault-DB replica over the nvpn mesh. Two nodes form
# the mesh (as in tests/mesh.nix), the ACTIVE writes a probe into its live vault DB and Litestream
# captures it, then the active's replica is pushed to the STANDBY over the mesh (rsync to a receiver
# reachable only on the mesh interface) and the standby restores it -- proving the DB replica crosses
# a real encrypted transport, not the base64 copy the ha-failover test still uses.
#
# Run: nix build .#checks.x86_64-linux.mesh-replication
{
  nvpnPackage,
  vaultRsaKeyFixture,
  ...
}:
{
  name = "keep-node-mesh-replication";

  nodes.active =
    { pkgs, ... }:
    {
      imports = [ ../nixos/keep-node.nix ];
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
      };
      keepNode.vaultReplication = {
        rsaKeyFile = "${vaultRsaKeyFixture}/rsa_key.pem";
        litestream.enable = true;
        role = "active";
        meshReplication.enable = true;
      };
      environment.systemPackages = [
        pkgs.sqlite
        pkgs.litestream
      ];
    };
  nodes.standby =
    { pkgs, ... }:
    {
      imports = [ ../nixos/keep-node.nix ];
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
      };
      keepNode.vaultReplication = {
        rsaKeyFile = "${vaultRsaKeyFixture}/rsa_key.pem";
        role = "standby";
        meshReplication.enable = true;
      };
      environment.systemPackages = [
        pkgs.sqlite
        pkgs.litestream
      ];
    };

  testScript =
    { nodes, ... }:
    let
      ipActive = nodes.active.networking.primaryIPAddress;
      ipStandby = nodes.standby.networking.primaryIPAddress;
      port = toString nodes.active.keepNode.mesh.listenPort;
      meshHome = nodes.active.keepNode.mesh.stateDir;
    in
    ''
      start_all()
      for node in [active, standby]:
          node.wait_for_unit("vaultwarden.service")

      H = "HOME=${meshHome}"
      CONFIG = "${meshHome}/.config/nvpn/config.toml"

      # --- Bring up the mesh (static, relay-less; same sequence as tests/mesh.nix). ---
      active.succeed(f"{H} nvpn init --force")
      standby.succeed(f"{H} nvpn init --force")

      def npub(node):
          raw = node.succeed(
              "awk '/^\\[nostr\\]/{n=1;next} /^\\[/{n=0} "
              f"n&&/^public_key/{{print $3}}' {CONFIG}"
          )
          return raw.strip().strip('\"')

      npubActive = npub(active)
      npubStandby = npub(standby)
      for node in [active, standby]:
          node.succeed(f"{H} nvpn set --participant {npubActive} --participant {npubStandby}")
      active.succeed(
          f"{H} nvpn set --network-id keepnode --endpoint ${ipActive}:${port} "
          f"--listen-port ${port} --fips-advertise-endpoint true "
          f"--fips-peer-endpoint {npubStandby}=${ipStandby}:${port}"
      )
      standby.succeed(
          f"{H} nvpn set --network-id keepnode --endpoint ${ipStandby}:${port} "
          f"--listen-port ${port} --fips-advertise-endpoint true "
          f"--fips-peer-endpoint {npubActive}=${ipActive}:${port}"
      )
      active.systemctl("start keep-node-mesh.service")
      standby.systemctl("start keep-node-mesh.service")
      for node in [active, standby]:
          node.wait_until_succeeds(
              "journalctl -u keep-node-mesh.service | grep -q 'mesh: 1/1 peers connected'",
              timeout=90,
          )

      # --- Write a probe into the active's LIVE vault DB; Litestream captures it into the replica. ---
      active.wait_for_unit("keep-node-litestream.service")
      active.succeed(
          "sqlite3 /var/lib/vaultwarden/db.sqlite3 "
          "\"PRAGMA busy_timeout=10000; CREATE TABLE ha_probe(x TEXT); "
          "INSERT INTO ha_probe VALUES('m1-mesh-db-marker');\""
      )
      active.succeed("sleep 4")  # a couple of Litestream sync cycles
      active.succeed("test -n \"$(ls -A /var/lib/vaultwarden/replica 2>/dev/null)\"")

      # --- Drop a probe attachment; the local file-sync mirrors it into the SAME replica dir, so the
      # single push below carries the attachment/Send files over the mesh alongside the DB replica. ---
      active.succeed(
          "install -d -o vaultwarden -g vaultwarden -m 0700 /var/lib/vaultwarden/attachments/probe-cipher && "
          "echo 'mesh-attach-marker' > /tmp/pf && install -o vaultwarden -g vaultwarden -m 0600 "
          "/tmp/pf /var/lib/vaultwarden/attachments/probe-cipher/probe-file"
      )
      # ...and a Send probe, so sends/ (not just attachments/) is proven to cross the mesh too.
      active.succeed(
          "install -d -o vaultwarden -g vaultwarden -m 0700 /var/lib/vaultwarden/sends && "
          "echo 'mesh-send-marker' > /tmp/sf && install -o vaultwarden -g vaultwarden -m 0600 "
          "/tmp/sf /var/lib/vaultwarden/sends/probe-send"
      )
      active.systemctl("start keep-node-vault-files.service")
      active.succeed("test -f /var/lib/vaultwarden/replica/attachments/probe-cipher/probe-file")
      active.succeed("test -f /var/lib/vaultwarden/replica/sends/probe-send")

      # --- Push the replica to the standby OVER THE MESH (trigger the unit rather than wait the timer).
      # The standby's receiver is reachable only on the mesh interface. ---
      standby.wait_for_unit("keep-node-vault-receive.service")
      active.systemctl("start keep-node-vault-mesh-push.service")

      # --- The standby received the DB replica over the mesh; restoring it yields the probe row. ---
      standby.wait_until_succeeds(
          "test -e /var/lib/vaultwarden/replica/db.sqlite3 || test -n \"$(ls -A /var/lib/vaultwarden/replica 2>/dev/null)\"",
          timeout=30,
      )
      standby.succeed("litestream restore -o /tmp/restored.db file:///var/lib/vaultwarden/replica")
      got = standby.succeed("sqlite3 /tmp/restored.db 'SELECT x FROM ha_probe'").strip()
      assert got == "m1-mesh-db-marker", f"DB replica did not cross the mesh: {got!r}"

      # ...and the attachment file rode the same push over the mesh.
      standby.wait_until_succeeds(
          "test -f /var/lib/vaultwarden/replica/attachments/probe-cipher/probe-file", timeout=30
      )
      attach = standby.succeed(
          "cat /var/lib/vaultwarden/replica/attachments/probe-cipher/probe-file"
      ).strip()
      assert attach == "mesh-attach-marker", f"attachment did not cross the mesh: {attach!r}"

      # ...and the Send probe rode the same push over the mesh.
      standby.wait_until_succeeds(
          "test -f /var/lib/vaultwarden/replica/sends/probe-send", timeout=30
      )
      send = standby.succeed("cat /var/lib/vaultwarden/replica/sends/probe-send").strip()
      assert send == "mesh-send-marker", f"Send did not cross the mesh: {send!r}"

      # --- Deletion propagation: `rsync --delete` on the active push path must remove files the
      # standby holds once they leave the active. Delete the probe attachment on the active, re-run the
      # local file-sync (drops it from the active's replica) then the mesh push, and assert it vanishes
      # from the standby's replica -- proving --delete actually propagates deletions across the mesh. ---
      active.succeed("rm -f /var/lib/vaultwarden/attachments/probe-cipher/probe-file")
      active.systemctl("start keep-node-vault-files.service")
      active.succeed("test ! -e /var/lib/vaultwarden/replica/attachments/probe-cipher/probe-file")
      active.systemctl("start keep-node-vault-mesh-push.service")
      standby.wait_until_succeeds(
          "test ! -e /var/lib/vaultwarden/replica/attachments/probe-cipher/probe-file", timeout=30
      )

      # --- Role gate (keep-node-0z7): a standby must not wipe the files it received. The primary
      # protection is that the standby runs NO local file-sync (keep-node-vault-files is active-only,
      # under litestream.enable) -- assert the unit is not even instantiated here. The `--delete` in
      # that sync is additionally gated to role != "standby" (a Nix conditional) as belt-and-suspenders
      # for a misconfigured standby that enabled Litestream. ---
      standby.fail("systemctl cat keep-node-vault-files.service")
    '';
}
