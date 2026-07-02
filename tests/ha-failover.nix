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
    { ... }:
    {
      imports = [ ../nixos/keep-node.nix ];
      keepNode.vaultReplication.rsaKeyFile = "${vaultRsaKeyFixture}/rsa_key.pem";
      keepNode.vaultReplication.rsaKeyPubFile = "${vaultRsaKeyFixture}/rsa_key.pub.pem";
    };
  nodes.nodeA = { };
  nodes.nodeB = { };

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
  '';
}
