# Multi-node HA (M1), increment 1: two KeepNodes share one Vaultwarden JWT signing key.
#
# Vaultwarden generates rsa_key.pem on first start if absent and signs session JWTs with it. If two
# nodes each generate their own, a token minted on the active is rejected by a promoted standby and
# every client must re-authenticate on failover. So the cluster must share ONE key. This proves the
# distribution: both nodes install the same operator-provided key BEFORE vaultwarden starts, so
# neither generates its own, and the key is byte-identical across nodes -- the precondition for a
# session to survive failover.
#
# Later increments (DB WAL streaming via Litestream, attachment replication, crash+promote) extend
# this harness; the full token-minted-on-A-accepted-by-B round-trip rides on the DB replication in
# a later increment (it needs a replicated user row + a registration client).
#
# The `gated` node adds the FROST-gate leg: with the data dir encrypted, the key installer must seed
# the shared key only onto the mounted volume and fail closed (never write to bare disk) when the
# gate cannot unlock. nodeA/nodeB run with the gate off and never reach that branch.
#
# Run: nix build .#checks.x86_64-linux.ha-failover
{ vaultRsaKeyFixture, ... }:
{
  name = "keep-node-ha-failover";

  # nodeA and nodeB are identical; share one module across both.
  #
  # Test-only: this deliberately does the anti-pattern the rsaKeyFile option warns against, feeding
  # a Nix-store path so the key sits world-readable in /nix/store. Safe here because the fixture is
  # an ephemeral per-build key, never a real secret. A real deploy must pass an out-of-band path.
  defaults =
    { pkgs, ... }:
    {
      imports = [ ../nixos/keep-node.nix ];
      keepNode.vaultReplication.rsaKeyFile = "${vaultRsaKeyFixture}/rsa_key.pem";
      keepNode.vaultReplication.rsaKeyPubFile = "${vaultRsaKeyFixture}/rsa_key.pub.pem";
      # sqlite: write/read the WAL probe; litestream: restore the replica on the peer.
      environment.systemPackages = [
        pkgs.sqlite
        pkgs.litestream
      ];
    };
  # nodeA is the active node: it runs Litestream, streaming its vault DB's WAL to the replica dir.
  nodes.nodeA = {
    keepNode.vaultReplication.litestream.enable = true;
  };
  nodes.nodeB = { };

  # Gate-enabled node (inherits `defaults`, so it carries the same shared-key wiring). The FROST gate
  # encrypts /var/lib/vaultwarden, which turns on the installer's gateEnabled branch: requires-on-gate
  # plus the mountpoint fail-closed guard. Swtpm + a blank disk let the gate self-provision the LUKS
  # volume, mirroring tests/frost-gate.nix.
  nodes.gated =
    { pkgs, ... }:
    {
      keepNode.frostGate = {
        enable = true;
        volumeDevice = "/dev/vdb";
      };
      environment.systemPackages = [ pkgs.cryptsetup ];
      virtualisation = {
        emptyDiskImages = [ 512 ]; # /dev/vdb: the encrypted vault volume
        tpm.enable = true; # swtpm, backing the TPM-sealed LUKS keyslot
      };
    };

  testScript = ''
    start_all()
    for node in [nodeA, nodeB]:
        node.wait_for_unit("keep-node-vault-rsa-key.service")
        node.wait_for_unit("vaultwarden.service")
        node.wait_for_open_port(8222)
        node.succeed("curl -fsS http://localhost:8222/alive")

    # The shared JWT signing key is byte-identical on both nodes: the installer landed it before
    # vaultwarden started, so neither node generated its own. A token signed on one therefore
    # validates on the other -- the precondition for sessions to survive a failover.
    def keyhash(node):
        return node.succeed("sha256sum /var/lib/vaultwarden/rsa_key.pem").split()[0]

    hash_a = keyhash(nodeA)
    hash_b = keyhash(nodeB)
    assert hash_a == hash_b, f"rsa_key.pem differs across nodes: {hash_a} vs {hash_b}"

    # ...and it is the SHARED key, not a per-node one vaultwarden generated for itself.
    fixture_hash = nodeA.succeed(
        "sha256sum ${vaultRsaKeyFixture}/rsa_key.pem"
    ).split()[0]
    assert hash_a == fixture_hash, (
        f"vaultwarden used a self-generated key ({hash_a}), not the shared fixture ({fixture_hash})"
    )

    # The key is private to the vaultwarden user, not world-readable.
    nodeA.succeed("test \"$(stat -c '%U %a' /var/lib/vaultwarden/rsa_key.pem)\" = 'vaultwarden 600'")

    # --- Litestream WAL streaming (M1 PR2): nodeA (active) ships its vault DB's WAL to a replica,
    # and the peer restores it intact. The cross-node hop is stubbed by a copy (like the shared key
    # in PR1); the real deploy ships the replica over the encrypted mesh transport, which is not
    # built yet. This proves Litestream captures Vaultwarden's live WAL and a replica round-trips. ---
    nodeA.wait_for_unit("keep-node-litestream.service")

    # Write a probe into the live vault DB. WAL mode (pinned by the module) lets this commit
    # concurrently with vaultwarden; busy_timeout rides out vaultwarden briefly holding the writer.
    nodeA.succeed(
        "sqlite3 /var/lib/vaultwarden/db.sqlite3 "
        "\"PRAGMA busy_timeout=10000; CREATE TABLE ha_probe(x TEXT); "
        "INSERT INTO ha_probe VALUES('m1-litestream-marker');\""
    )
    # Litestream syncs every ~1s; give it a couple cycles to ship the probe's WAL frames.
    nodeA.succeed("sleep 4")
    nodeA.succeed("test -n \"$(ls -A /var/lib/vault-replica 2>/dev/null)\"")

    # Transport stand-in: copy the replica to the peer (real deploy: over the mesh).
    replica_b64 = nodeA.succeed("tar -C /var/lib/vault-replica -cf - . | base64 -w0").strip()
    nodeB.succeed(
        f"mkdir -p /tmp/replica && printf %s '{replica_b64}' | base64 -d | tar -C /tmp/replica -xf -"
    )

    # The peer restores the vault DB from the received replica and finds the probe: the WAL streamed
    # end to end, so a promoted standby would carry the active's data.
    nodeB.succeed("litestream restore -o /tmp/restored.db file:///tmp/replica")
    restored = nodeB.succeed("sqlite3 /tmp/restored.db 'SELECT x FROM ha_probe'").strip()
    assert restored == "m1-litestream-marker", f"probe did not survive replication: {restored!r}"

    # --- Gate-enabled leg: the installer's gateEnabled branch, unreached by nodeA/nodeB. ---

    # Healthy unlock: the gate provisions + mounts the LUKS volume, THEN the installer's mountpoint
    # guard passes and it seeds the shared key onto the encrypted mapper before vaultwarden starts.
    gated.wait_for_unit("keep-node-frost-gate.service")
    gated.wait_for_unit("keep-node-vault-rsa-key.service")
    gated.wait_for_unit("vaultwarden.service")

    # The data dir IS the decrypted LUKS mapper (encrypted at rest), and the key on it is the shared
    # fixture -- proving the installer wrote through to the mounted volume, not that vaultwarden
    # self-generated one.
    gated.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")
    assert keyhash(gated) == fixture_hash, (
        "gate-enabled node did not seed the shared key onto the encrypted volume"
    )

    # Force the next unlock to fail closed: on the provisioned volume (completion marker present)
    # remove the TPM2 keyslot, leaving no usable key. The gate then refuses to reformat and stays
    # down -- exactly the scenario the requires-on-gate + mountpoint guard defend against.
    tokid = gated.succeed(
        "cryptsetup luksDump /dev/vdb | sed -n 's/^\\s*\\([0-9]\\+\\): systemd-tpm2/\\1/p' | head -n1"
    ).strip()
    gated.succeed(f"cryptsetup token remove --token-id {tokid} /dev/vdb")

    gated.shutdown()
    gated.start()

    # Gate fails closed: the volume never unlocks, so /var/lib/vaultwarden is the bare, UNENCRYPTED
    # root dir.
    gated.wait_until_succeeds("systemctl is-failed --quiet keep-node-frost-gate.service")
    gated.fail("test -e /dev/mapper/keep-vault")
    gated.fail("mountpoint -q /var/lib/vaultwarden")

    # The installer never wrote the shared private key: requires-on-gate aborts it when the gate
    # fails, so no rsa_key.pem lands on the unencrypted disk -- the security property of the fix.
    gated.fail("test -e /var/lib/vaultwarden/rsa_key.pem")
    gated.fail("systemctl is-active --quiet keep-node-vault-rsa-key.service")
    gated.fail("systemctl is-active --quiet vaultwarden.service")

    # Backstop: exercise the mountpoint guard directly. Run the installer's own script (bypassing the
    # requires dependency) while the volume is unmounted; it must refuse (non-zero) with the guard's
    # message and leave bare disk clean. Capture status+output so a regression reports what happened.
    key_script = gated.succeed(
        "systemctl show -p ExecStart --value keep-node-vault-rsa-key.service "
        "| grep -oE '/nix/store/[^ ;]*unit-script-keep-node-vault-rsa-key-start[^ ;]*' | head -n1"
    ).strip()
    status, out = gated.execute(f"{key_script} 2>&1")
    assert status != 0, f"installer did not fail closed while the volume was unmounted (rc={status}): {out}"
    assert "refusing to write key to unencrypted disk" in out, f"mountpoint guard did not fire: {out}"
    gated.fail("test -e /var/lib/vaultwarden/rsa_key.pem")
  '';
}
