# End-to-end frost-gate OPRF mode with the REAL keep binary, and the M0 done-criterion: the gate
# itself provisions the vault and then, at boot, unlocks it by running `keep oprf-unlock` inside its
# confined systemd-run scope; then the vault is exercised (register + store + read a password over
# Vaultwarden's real protocol) and shown to survive a second quorum-unlock reboot.
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
  pkgs,
  ...
}:
let
  # Headless Bitwarden client for the M0 vault round-trip (crypto validated by the vw-client-check
  # test): register an account, store a login, read it back -- no browser, no bw/rbw agent.
  vwClient = import ./lib/vw-client.nix { inherit pkgs; };
in
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
        # Test-only: forward KEEP_ALLOW_WS into the confined boot scope so it can reach the in-VM
        # ws:// relay. Never set in production, where the boot OPRF exchange must stay over wss://.
        allowInsecureWs = true;
      };

      # A non-root gate scope (keep-node-5y0) needs the tss group + /dev/tpmrm0 at tss:0660.
      security.tpm2.enable = true;

      # M0: allow the vault round-trip's register call. Test-only; a real deploy keeps signups
      # default-deny (the operator onboards, not open self-registration).
      keepNode.vaultwarden.signupsAllowed = true;

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
    vw = "${vwClient}"
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

    # The unlock ran NON-ROOT (keep-node-5y0). The successful mount asserted just above is itself the
    # proof: the confined scope stages its OPRF share 0400-owned-by-keep-oprf-unlock and runs with an
    # empty CapabilityBoundingSet, so a scope that regressed to running as root would be capless root
    # -- it would hit EACCES reading that 0400 share, fail to reconstruct the key, and never open or
    # mount the volume. (We don't grep the journal for the scope's uid: keep logs to stderr, which
    # systemd-run --pipe routes to the root gate unit, so nothing is journaled under keep-oprf-unlock.)
    # Also assert the tmpfiles chown the scope depends on landed, so a regression that drops it -- and
    # would otherwise make the DB unreadable to the non-root scope -- fails here with a clear signal.
    box.succeed("stat -c %U /var/lib/keep-box | grep -qx keep-oprf-unlock")

    # --- M0 done-criterion: the vault is usable AND its data survives a quorum-unlock cycle. ---
    # Onboard (register, no seed) + store a password on the now-unlocked Vaultwarden, then reboot --
    # a SECOND quorum unlock -- and read it back. A read that matches proves the gated volume holds
    # real, usable Vaultwarden state that persists across the seal/unlock cycle, not just that the
    # service starts. The store/read run over Vaultwarden's actual Bitwarden protocol (vw-client.py).
    box.wait_for_open_port(8222)
    base = "http://localhost:8222"
    email = "m0@keep.test"
    pw = "MasterPass123"
    box.succeed(f"VW_PASSWORD={pw} {vw} register {base} {email} m0user")
    box.succeed(f"VW_PASSWORD={pw} VW_VALUE=SecretValue123 {vw} store {base} {email} mysecret")

    box.shutdown()
    box.start()
    box.wait_for_file("/dev/tpmrm0")
    box.wait_for_unit("keep-node-frost-gate.service")
    box.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")
    box.wait_for_unit("vaultwarden.service")
    box.wait_for_open_port(8222)

    got = box.succeed(f"VW_PASSWORD={pw} {vw} read {base} {email} mysecret").strip()
    assert got == "SecretValue123", f"vault read back {got!r} after quorum unlock, expected SecretValue123"
  '';
}
