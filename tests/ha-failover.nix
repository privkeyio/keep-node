# STUB: two KeepNodes sync; kill one, the other keeps serving (multi-node HA).
#
# Fill in once the sync layer lands:
#   * transport: nostr-vpn mesh between nodeA and nodeB
#   * replication: active/standby of Vaultwarden's SQLite + attachments; Keep state via wisp
#     NIP-77 negentropy
#   * failover: promote standby on primary loss
#
# Target shape of the assertion:
#   start_all()
#   both nodes reach vaultwarden + join the mesh
#   write a vault item via nodeA
#   nodeA.crash()
#   nodeB still serves the item  <-- the proof
{ ... }:
{
  name = "keep-node-ha-failover";

  nodes.nodeA =
    { ... }:
    {
      imports = [ ../nixos/keep-node.nix ];
    };
  nodes.nodeB =
    { ... }:
    {
      imports = [ ../nixos/keep-node.nix ];
    };

  testScript = ''
    start_all()
    nodeA.wait_for_unit("vaultwarden.service")
    nodeB.wait_for_unit("vaultwarden.service")
    # TODO: mesh join, replication, then nodeA.crash() and assert nodeB still serves.
  '';
}
