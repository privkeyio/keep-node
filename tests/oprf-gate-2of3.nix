# Through-the-gate 2-of-3: the REAL boot gate (frost-gate oprf mode) unlocks the vault across reboots
# with the box + ANY ONE of two holders, and fails closed with neither. Where oprf-gate proves the boot
# path at 2-of-2 (both parties always required) and oprf-unlock-2of3 proves the 2-of-3 CRYPTO reboot-
# free, this proves the 2-of-3 BOOT path: the gate's bounded unlock retry converges on whichever single
# holder is online (the box rebuilds its peer set from live announces each boot), and refuses below
# threshold.
#
#   provision the 2-of-3 quorum (needs both holders online)
#   -> leg A: reboot, holder2 down   -> box + holder unlocks, Vaultwarden serves, store a secret
#   -> leg B: reboot, holder down    -> box + holder2 unlocks the SAME volume, reads the secret back
#   -> leg C: reboot, neither holder -> fails closed: gate failed, no mapper, Vaultwarden down
#
# Heavy: 4 VMs (relay + box[swtpm] + 2 holders) + 3 reboots + attestation bootstrap.
#
# Run: nix build .#checks.x86_64-linux.oprf-gate-2of3
{
  keepCliPackage,
  frostGroupFixture, # the 2-of-3 fixture (frostGroupFixture2of3), same arg name as oprf-gate
  wispModule,
  pkgs,
  ...
}:
let
  vwClient = import ./lib/vw-client.nix { inherit pkgs; };
in
{
  name = "keep-node-oprf-gate-2of3-test";

  # wisp is the production relay; use it (with NIP-42 auth) so the boot gate is
  # exercised against the real relay, not a permissive stand-in. Enforcement of
  # that auth (an unauthenticated REQ is refused) is asserted by the oprf-unlock
  # and duress-freeze tests against this same auth.required config; here the
  # passing boot proves the gate speaks NIP-42 to reach the quorum.
  nodes.relay =
    { ... }:
    {
      imports = [ wispModule ];
      services.wisp = {
        enable = true;
        host = "0.0.0.0";
        port = 7777;
        openFirewall = true;
        settings = {
          auth.required = true;
          rate_limits = {
            events_per_minute = 100000;
            queries_per_minute = 100000;
          };
        };
      };
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
        group = builtins.readFile "${frostGroupFixture}/npub";
        relay = "ws://relay.kfp:7777";
        shareIndex = 1;
        volumeId = "vault0";
        quorum = {
          threshold = 2;
          total = 3;
        };
        # Short so leg C fails closed quickly in-test (fast 3s announces make legs A/B converge on the
        # first attempt anyway); production keeps the 90s default. Each no-peer attempt costs ~24s of
        # keep's internal discovery, so this budget allows ~2 attempts before failing closed.
        bootUnlockTimeoutSec = 45;
        keepPasswordCred = "/var/lib/keep-node/keep-password.cred";
        oprfShareCred = "/var/lib/keep-node/oprf-share.cred";
        keepPasswordEnvFile = "${pkgs.writeText "keep-pass-env" "KEEP_PASSWORD=fixturepass123"}";
        tpmTcti = "device:/dev/tpmrm0";
        allowInsecureWs = true;
      };

      security.tpm2.enable = true;
      keepNode.vaultwarden.signupsAllowed = true;
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
  nodes.holder2 =
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

    def serve(node, path, unit):
        # Serve as an OPRF holder with the sealed share loaded (post-provision).
        keep_bg(
            node, unit,
            f"--path {path} frost network serve --group {npub} --relay {relay_url} "
            f"--oprf-share-file {path}-oprf.share --oprf-dealer 1 --oprf-auto-approve "
            f"--attestation-config /root/policy.toml",
        )

    def gate_unlocked_boot():
        # A reboot that must reach a mounted, serving vault.
        box.wait_for_file("/dev/tpmrm0")
        box.wait_for_unit("keep-node-frost-gate.service")
        box.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")
        box.wait_for_unit("vaultwarden.service")
        box.wait_for_open_port(8222)

    start_all()
    relay.wait_for_unit("wisp.service")
    relay.wait_for_open_port(7777)
    holder.wait_for_unit("multi-user.target")
    holder2.wait_for_unit("multi-user.target")
    box.wait_for_file("/dev/tpmrm0")
    # Blank /dev/vdb, no marker: the gate fails closed on first boot until we provision.
    box.wait_until_fails("systemctl is-active --quiet keep-node-frost-gate.service")

    # Seed DBs: box (dealer holds the group + all shares), holder (share 2), holder2 (share 3).
    box.succeed(
        "mkdir -p /var/lib/keep-box && cp -aT ${frostGroupFixture}/box /var/lib/keep-box && "
        "chmod -R u+w /var/lib/keep-box"
    )
    holder.succeed(
        "mkdir -p /root/holder && cp -aT ${frostGroupFixture}/holder /root/holder && chmod -R u+w /root/holder"
    )
    holder2.succeed(
        "mkdir -p /root/holder2 && cp -aT ${frostGroupFixture}/holder2 /root/holder2 && chmod -R u+w /root/holder2"
    )

    # --- Attestation bootstrap: box announces a TPM quote; BOTH holders pin it TOFU. ---
    keep_bg(
        box, "box-announce",
        f"--path /var/lib/keep-box frost network serve --group {npub} --relay {relay_url} --share 1 "
        f"--tpm-tcti device:/dev/tpmrm0 --insecure-no-attestation",
    )
    for (h, path) in [(holder, "/root/holder"), (holder2, "/root/holder2")]:
        h.wait_until_succeeds(
            f"{env} {keep} --no-mlock --path {path} frost network attestation-provision "
            f"--group {npub} --relay {relay_url} --out /root/policy.toml --wait 40",
            timeout=180,
        )
        h.succeed("test -s /root/policy.toml")
    box.succeed("systemctl stop box-announce.service")

    # --- Both holders serve; the gate provisions the 2-of-3 quorum (seals a share to every party, so
    # both holders must be online). ---
    serve(holder, "/root/holder", "holder-serve")
    serve(holder2, "/root/holder2", "holder2-serve")
    box.wait_until_succeeds("systemctl start keep-node-frost-provision.service", timeout=180)
    box.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-oprf")
    box.succeed("test -s /var/lib/keep-node/oprf-share.cred")

    # Holders reload their newly sealed OPRF shares.
    holder.wait_until_succeeds("test -s /root/holder-oprf.share", timeout=60)
    holder2.wait_until_succeeds("test -s /root/holder2-oprf.share", timeout=60)
    holder.succeed("systemctl stop holder-serve.service")
    holder2.succeed("systemctl stop holder2-serve.service")

    # === Leg A: box + holder (holder2 down) unlocks at boot and serves a real vault. ===
    serve(holder, "/root/holder", "holder-serveA")
    box.shutdown()
    box.start()
    gate_unlocked_boot()
    # The unlock ran NON-ROOT in the confined scope (keep-node-5y0): the DB is owned by keep-oprf-unlock,
    # and a scope that regressed to capless root could not read the 0400 share to reconstruct the key.
    box.succeed("stat -c %U /var/lib/keep-box | grep -qx keep-oprf-unlock")
    base = "http://localhost:8222"
    email = "m1@keep.test"
    pw = "MasterPass123"
    box.succeed(f"VW_PASSWORD={pw} {vw} register {base} {email} m1user")
    box.succeed(f"VW_PASSWORD={pw} VW_VALUE=SecretValue123 {vw} store {base} {email} mysecret")

    # === Leg B: box + holder2 (holder down) unlocks the SAME volume; the secret reads back. ===
    holder.succeed("systemctl stop holder-serveA.service")
    serve(holder2, "/root/holder2", "holder2-serveB")
    box.shutdown()
    box.start()
    gate_unlocked_boot()
    got = box.succeed(f"VW_PASSWORD={pw} {vw} read {base} {email} mysecret").strip()
    assert got == "SecretValue123", f"leg B read {got!r}, expected SecretValue123 (losing holder A is survivable)"

    # === Leg C: box + neither holder is below threshold -> fail closed. ===
    holder2.succeed("systemctl stop holder2-serveB.service")
    box.shutdown()
    box.start()
    box.wait_for_file("/dev/tpmrm0")
    # The gate retries within bootUnlockTimeoutSec, discovers no holders, then exits non-zero -> failed.
    box.wait_until_succeeds("systemctl is-failed --quiet keep-node-frost-gate.service", timeout=180)
    box.fail("test -e /dev/mapper/keep-vault")
    box.fail("systemctl is-active --quiet vaultwarden.service")
  '';
}
