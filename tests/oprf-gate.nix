# End-to-end frost-gate OPRF mode with the REAL keep binary: the gate itself provisions the vault
# and then, at boot, unlocks it by running `keep oprf-unlock` inside its confined systemd-run scope.
# The oprf-unlock test drives keep directly; this drives it THROUGH the frost-gate module (its
# provision unit + boot gate + confined scope), which is what a real deployment runs and the only
# place the wlc confinement + the keep-node-5y0 non-root scope are actually exercised with real keep.
#
# The FROST group comes from a build-time fixture (frostGroupFixture): the module bakes the group
# npub into its unit at build time, but `keep frost generate` is random and runs at boot, so the
# group is pre-generated in a derivation and its npub read via IFD. The box copies the fixture
# dealer DB to keepDbPath; the holder copies the fixture holder DB.
#
# Run: nix build .#checks.x86_64-linux.oprf-gate
{
  keepCliPackage,
  frostGroupFixture,
  ...
}:
{
  name = "keep-node-oprf-gate-test";

  nodes.relay =
    { ... }:
    {
      services.nostr-rs-relay = {
        enable = true;
        port = 7777;
      };
      networking.firewall.allowedTCPPorts = [ 7777 ];
    };

  nodes.box =
    {
      pkgs,
      nodes,
      ...
    }:
    {
      imports = [ ../nixos/keep-node.nix ];

      keepNode.frostGate = {
        enable = true;
        mode = "oprf";
        volumeDevice = "/dev/vdb";
        keepPackage = keepCliPackage;
        keepDbPath = "/var/lib/keep-box";
        group = builtins.readFile "${frostGroupFixture}/npub"; # IFD: npub known at eval time
        relay = "ws://relay.kfp:7777";
        shareIndex = 1;
        volumeId = "vault0";
        quorum = {
          threshold = 2;
          total = 2;
        };
        keepPasswordCred = "/var/lib/keep-node/keep-password.cred";
        oprfShareCred = "/var/lib/keep-node/oprf-share.cred";
        # Test-only: the provision unit reads KEEP_PASSWORD from here. A real deploy uses a
        # 0400 secret, not a store path. Matches the fixture DB's password.
        keepPasswordEnvFile = "${pkgs.writeText "keep-pass-env" "KEEP_PASSWORD=fixturepass123"}";
        tpmTcti = "device:/dev/tpmrm0";
      };

      # A non-root gate scope (keep-node-5y0) needs the tss group + /dev/tpmrm0 at tss:0660.
      security.tpm2.enable = true;

      # Test-only: the VM relay is ws:// (no TLS), which keep's SSRF guard rejects unless
      # KEEP_ALLOW_WS is set. Real deploys use wss://. The provision unit runs keep directly (unit
      # env suffices); the boot gate runs keep in a systemd-run scope that forwards KEEP_ALLOW_WS
      # via -E, so it must be in the gate unit's env too.
      systemd.services.keep-node-frost-provision.environment.KEEP_ALLOW_WS = "1";
      systemd.services.keep-node-frost-gate.environment.KEEP_ALLOW_WS = "1";

      environment.systemPackages = [
        keepCliPackage
        pkgs.cryptsetup
      ];
      virtualisation = {
        emptyDiskImages = [ 512 ]; # /dev/vdb, the vault volume
        tpm.enable = true; # swtpm -> /dev/tpmrm0
      };
      networking.firewall.enable = false;
      networking.extraHosts = "${nodes.relay.networking.primaryIPAddress} relay.kfp";
    };

  nodes.holder =
    { nodes, ... }:
    {
      environment.systemPackages = [ keepCliPackage ];
      networking.firewall.enable = false;
      networking.extraHosts = "${nodes.relay.networking.primaryIPAddress} relay.kfp";
    };

  testScript = ''
    keep = "${keepCliPackage}/bin/keep"
    relay_url = "ws://relay.kfp:7777"
    npub = "${builtins.readFile "${frostGroupFixture}/npub"}"
    # fixturepass123 is the password the fixture DBs (and thus keepPasswordEnvFile) were built with.
    env = "KEEP_PASSWORD=fixturepass123 KEEP_YES=1 KEEP_ALLOW_WS=1 KEEP_PEER_ANNOUNCE_INTERVAL_SECS=3"

    def keep_bg(node, unit, args):
        node.succeed(
            f"systemd-run --unit={unit} "
            f"--setenv=KEEP_PASSWORD=fixturepass123 --setenv=KEEP_YES=1 --setenv=KEEP_ALLOW_WS=1 "
            f"--setenv=KEEP_PEER_ANNOUNCE_INTERVAL_SECS=3 "
            f"{keep} --no-mlock {args}"
        )
        node.wait_until_succeeds(
            f"journalctl -u {unit}.service --no-pager | grep -q 'Listening for FROST messages'",
            timeout=180,
        )

    start_all()
    relay.wait_for_unit("nostr-rs-relay.service")
    relay.wait_for_open_port(7777)
    holder.wait_for_unit("multi-user.target")
    box.wait_for_file("/dev/tpmrm0")
    # The gate is oprf-mode on a blank /dev/vdb: it fails closed on first boot (no marker), which is
    # expected. Provisioning below is what makes it unlockable. Wait for the unit to settle first.
    box.wait_until_fails("systemctl is-active --quiet keep-node-frost-gate.service")

    # Seed the box + holder keep DBs from the fixture (the dealer holds the group; the holder its
    # imported share). keepDbPath = /var/lib/keep-box.
    # cp from the read-only Nix store; make it writable (keep opens its DB read-write). The confined
    # gate scope drops all caps (no CAP_DAC_OVERRIDE), so even as root it obeys these perms, exactly
    # like the real writable keepDbPath a deployment provisions.
    box.succeed(
        "mkdir -p /var/lib/keep-box && cp -aT ${frostGroupFixture}/box /var/lib/keep-box && "
        "chmod -R u+w /var/lib/keep-box"
    )
    holder.succeed(
        "mkdir -p /root/holder && cp -aT ${frostGroupFixture}/holder /root/holder && "
        "chmod -R u+w /root/holder"
    )

    # --- Attestation bootstrap: box announces a TPM quote, holder pins it (TOFU). ---
    keep_bg(
        box,
        "box-announce",
        f"--path /var/lib/keep-box frost network serve --group {npub} --relay {relay_url} --share 1 "
        f"--tpm-tcti device:/dev/tpmrm0 --insecure-no-attestation",
    )
    holder.wait_until_succeeds(
        f"{env} {keep} --no-mlock --path /root/holder frost network attestation-provision "
        f"--group {npub} --relay {relay_url} --out /root/policy.toml --wait 40",
        timeout=180,
    )
    holder.succeed("test -s /root/policy.toml")
    box.succeed("systemctl stop box-announce.service")

    # --- Holder serves as an OPRF holder (receives its share during provision, then answers). ---
    keep_bg(
        holder,
        "holder-serve",
        f"--path /root/holder frost network serve --group {npub} --relay {relay_url} "
        f"--oprf-share-file /root/holder-oprf.share --oprf-dealer 1 --oprf-auto-approve "
        f"--attestation-config /root/policy.toml",
    )

    # --- The GATE provisions: distribute the OPRF key, LUKS-format /dev/vdb, seal creds to the TPM. ---
    box.wait_until_succeeds("systemctl start keep-node-frost-provision.service", timeout=180)
    box.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-oprf")  # provisioned marker
    box.succeed("test -s /var/lib/keep-node/oprf-share.cred")  # share sealed to TPM
    box.succeed("test -s /var/lib/keep-node/keep-password.cred")

    # The holder must restart to load its newly sealed OPRF share before it can answer evaluations.
    holder.wait_until_succeeds("test -s /root/holder-oprf.share", timeout=60)
    holder.succeed("systemctl stop holder-serve.service")
    keep_bg(
        holder,
        "holder-serve2",
        f"--path /root/holder frost network serve --group {npub} --relay {relay_url} "
        f"--oprf-share-file /root/holder-oprf.share --oprf-dealer 1 --oprf-auto-approve "
        f"--attestation-config /root/policy.toml",
    )

    # --- Reboot: the boot gate runs `keep oprf-unlock` in its confined scope, reconstructs the key
    # from the quorum, opens the LUKS volume, and mounts it; then Vaultwarden starts off it. ---
    box.shutdown()
    box.start()
    box.wait_for_file("/dev/tpmrm0")
    box.wait_for_unit("keep-node-frost-gate.service")
    box.succeed("test -e /dev/mapper/keep-vault")
    box.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")
    box.wait_for_unit("vaultwarden.service")

    # The unlock ran NON-ROOT (keep-node-5y0): the module chowns keepDbPath to keep-oprf-unlock and
    # the confined scope runs as that user with no caps, so the unlock -- which needs rw on that DB
    # and the TPM -- could only have succeeded as the unprivileged user, not root-with-DAC-override.
    box.succeed("stat -c %U /var/lib/keep-box | grep -qx keep-oprf-unlock")
  '';
}
