# keep-state replication over wisp. A relay + an active + a standby keep-web node, all
# sharing the cluster vault DATA KEY (KEEP_STORAGE_KEY), the vault password, and the state identity.
# Proves the DEPLOYMENT wires end to end: each keep-web creates its vault with the SHARED data key,
# unlocks it (shared password), and reaches keep-web's keep-state-replication-enabled state for its
# role (active publishes, standby subscribes). The replication LOGIC itself -- active write -> relay -> standby
# reconstruct + read-back -- is proven at the keep-web level by privkeyio/keep's e2e test; keep-web's
# HTTP API does not expose driving/reading the replicated tables (keys/descriptors/relay_configs)
# directly, so this validates the deployment integration rather than re-driving the record round-trip.
#
# Run: nix build .#checks.x86_64-linux.keep-state-replication
{
  keepWebPackage,
  wispModule,
  pkgs,
  ...
}:
let
  # Test-only shared cluster secrets. In production each is delivered out-of-band onto the encrypted
  # volume (like the shared JWT key). Keys::parse accepts a hex secret key; KEEP_STORAGE_KEY is 32-byte
  # hex; the password is any string. Distinct values so a mix-up can't accidentally pass.
  password = "clusterpassword123";
  identityHex = "0000000000000000000000000000000000000000000000000000000000000001";
  storageKeyHex = "1111111111111111111111111111111111111111111111111111111111111111";
  secrets = pkgs.runCommand "keep-cluster-secrets" { } ''
    mkdir -p "$out"
    printf '%s' "${password}" > "$out/password"
    printf '%s' "${identityHex}" > "$out/identity"
    printf '%s' "${storageKeyHex}" > "$out/storagekey"
  '';

  keepWebNode =
    { role }:
    { nodes, ... }:
    {
      imports = [ ../nixos/keep-web.nix ];
      # Deliver the shared secrets to a runtime path (the *File options reject Nix store paths). The
      # keep-web credentials are read by root before the DynamicUser drop, so 0700/root is fine.
      systemd.tmpfiles.rules = [ "C /run/keep-secrets 0700 root root - ${secrets}" ];
      keepNode.keepWeb = {
        enable = true;
        package = keepWebPackage;
        passwordFile = "/run/keep-secrets/password";
        stateRelay = "ws://${nodes.relay.networking.primaryIPAddress}:7777";
        stateIdentityFile = "/run/keep-secrets/identity";
        storageKeyFile = "/run/keep-secrets/storagekey";
        stateRole = role;
        allowInsecureWs = true; # the in-VM relay is plaintext ws://
      };
    };
in
{
  name = "keep-node-keep-state-replication";

  # The state relay both keep-web nodes publish to / subscribe from.
  nodes.relay =
    { ... }:
    {
      imports = [ wispModule ];
      services.wisp = {
        enable = true;
        host = "0.0.0.0";
        port = 7777;
        openFirewall = true;
      };
    };

  nodes.active = keepWebNode { role = "active"; };
  nodes.standby = keepWebNode { role = "standby"; };

  testScript = ''
    start_all()
    relay.wait_for_unit("wisp.service")
    relay.wait_for_open_port(7777)

    for node in [active, standby]:
        # keep-web comes up, which means: it created its vault with the SHARED data key and unlocked it
        # with the SHARED password (a wrong key or password would fail the create/unlock and crash the
        # unit), then bound its API port.
        node.wait_for_unit("keep-web.service")
        node.wait_for_open_port(8080)
        node.wait_until_succeeds(
            "journalctl -u keep-web.service | grep -q 'vault unlocked'", timeout=60
        )
        # keep-state replication reaches the enabled state for this node's role. This is keep-web's
        # own config-level readiness log, not an independent check that the relay connection is live;
        # the wire round-trip (active write -> relay -> standby reconstruct) is covered by keep's e2e test.
        node.wait_until_succeeds(
            "journalctl -u keep-web.service | grep -q 'keep-state replication enabled'", timeout=60
        )
  '';
}
