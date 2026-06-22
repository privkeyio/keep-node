# M1 (STUB): two KeepNodes sync; kill one, the other keeps serving.
#
# Fill in once the sync layer lands:
#   * transport: nvpn mesh between nodeA and nodeB (see SPIKE-nostr-vpn.md)
#   * replication: active/standby of Vaultwarden's SQLite + attachments; Keep state via wisp
#     NIP-77 negentropy
#   * failover: promote standby on primary loss
#
# Target shape of the assertion:
#   start_all()
#   both nodes reach vaultwarden + join the mesh
#   write a vault item via nodeA
#   nodeA.crash()
#   nodeB still serves the item  <-- the M1 proof
{ ... }:
{
  name = "keep-node-m1-ha-failover";

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
    # TODO(M1): mesh join, replication, then nodeA.crash() and assert nodeB still serves.
  '';
}
