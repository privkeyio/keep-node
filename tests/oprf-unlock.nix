# Real threshold-OPRF unlock over a live relay, no hardware: relay + box + one
# holder, each a NixOS VM, the box with swtpm. Proves the keep-cli OPRF quorum
# unlock end to end (the 2-node leg: a 2-of-2 box+holder quorum):
#
#   FROST group setup (box deals share 2 to the holder)
#   -> attestation bootstrap (box announces a quote, holder pins it TOFU)
#   -> holder serves as an OPRF holder (receives its share, then answers)
#   -> box provisions the OPRF quorum (box + holder online)
#   -> box requests a 2-of-2 unlock and reconstructs the SAME LUKS key.
#
# A 2-of-2 quorum (box share + holder share) is the minimal leg that proves "no single box
# can decrypt": the box alone holds one share and never reaches the threshold of 2. OPRF
# provisioning seals a share to every party, so it needs all `total` holders online; a third
# replica share (n>threshold redundancy, where unlock can proceed with the replica absent) is
# a later leg. Attestation is real (swtpm quotes), though the VM's PCRs are the boot reset
# values (no measured boot), so the policy the holder pins is whatever the box actually
# attests; this exercises the produce/verify/gate path, not a meaningful measured-boot policy
# (that is keep-27yn / Lanzaboote).
#
# Run: nix build .#checks.x86_64-linux.oprf-unlock
{ keepCliPackage, ... }:
{
  name = "keep-node-oprf-unlock-test";

  nodes.relay =
    { ... }:
    {
      # The relay binds 0.0.0.0 by default; the nixpkgs module hardcodes
      # network = { port = ...; } and discards any settings.network.address via a
      # shallow `//` merge, so setting it here is inert. The default is already what
      # the box/holder VMs need to reach it cross-node.
      services.nostr-rs-relay = {
        enable = true;
        port = 7777;
      };
      networking.firewall.allowedTCPPorts = [ 7777 ];
    };

  # keep-cli's relay-URL guard rejects single-label hosts as internal (SSRF protection) with no
  # runtime opt-out, so the box/holder reach the relay by a dotted name that passes validation.
  # ws:// skips cert-pinning's resolved-IP check, so the private VM address it resolves to is fine.
  nodes.box =
    { pkgs, nodes, ... }:
    {
      environment.systemPackages = [
        keepCliPackage
        pkgs.cryptsetup
      ];
      virtualisation.tpm.enable = true; # swtpm -> /dev/tpmrm0
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
    import re

    def must_match(pattern, text, what):
        m = re.search(pattern, text)
        assert m is not None, f"no {what} in output: {text!r}"
        return m.group(0)

    keep = "${keepCliPackage}/bin/keep"
    relay_url = "ws://relay.kfp:7777"
    # KEEP_YES skips confirmations; --no-mlock avoids RLIMIT_MEMLOCK failures in the
    # VM; KEEP_ALLOW_WS allows the plain-ws:// test relay (no TLS in the VM).
    # KEEP_PEER_ANNOUNCE_INTERVAL_SECS shrinks the 20s re-announce cadence so peer discovery
    # (which polls a bounded window) reliably overlaps an announce in the VM, making the
    # rendezvous deterministic instead of racing the default cadence.
    env = "KEEP_PASSWORD=testpassword123 KEEP_YES=1 KEEP_ALLOW_WS=1 KEEP_PEER_ANNOUNCE_INTERVAL_SECS=3"

    def keep_bg(node, unit, args):
        # Run a long-lived `keep` (serve/announce) as a transient unit in the background.
        node.succeed(
            f"systemd-run --unit={unit} "
            f"--setenv=KEEP_PASSWORD=testpassword123 --setenv=KEEP_YES=1 --setenv=KEEP_ALLOW_WS=1 "
            f"--setenv=KEEP_PEER_ANNOUNCE_INTERVAL_SECS=3 "
            f"{keep} --no-mlock {args}"
        )
        # Wait until the node is actually serving, not merely until the unit is active:
        # `keep` unlocks its vault (Argon2) BEFORE it starts the node, which can take tens of
        # seconds in a loaded VM. The unit goes active immediately, so is-active is a false
        # readiness signal; the "Listening" banner means the node has subscribed and is
        # announcing, so the box never provisions/unlocks before this peer can answer. This
        # also fails fast if the process crashed on startup (a bad flag, unreachable relay).
        node.wait_until_succeeds(
            f"journalctl -u {unit}.service --no-pager | grep -q 'Listening for FROST messages'",
            timeout=180,
        )

    start_all()
    relay.wait_for_unit("nostr-rs-relay.service")
    relay.wait_for_open_port(7777)
    box.wait_for_unit("multi-user.target")
    holder.wait_for_unit("multi-user.target")
    box.wait_for_file("/dev/tpmrm0")

    # --- 1. FROST group: box generates 2-of-2, exports share 2, holder imports it. ---
    box.succeed(f"{env} {keep} --no-mlock --path /root/box init")
    # `frost generate` prints the group npub to stderr; merge it so succeed() sees it.
    gen = box.succeed(f"{env} {keep} --no-mlock --path /root/box frost generate -t 2 -s 2 --name g 2>&1")
    npub = must_match(r"npub1[a-z0-9]{50,}", gen, "group npub")

    exported = box.succeed(
        f"printf 'sharepass1\\nsharepass1\\n' | "
        f"{env} {keep} --no-mlock --path /root/box frost export --share 2 --group {npub}"
    )
    kshare = must_match(r"kshare1[a-z0-9]+", exported, "exported share")

    holder.succeed(f"{env} {keep} --no-mlock --path /root/holder init")
    holder.succeed(
        f"printf '{kshare}\\n\\nsharepass1\\n' | "
        f"{env} {keep} --no-mlock --path /root/holder frost import"
    )

    # --- 2. Attestation bootstrap: box announces a TPM quote, holder pins it. ---
    # The box generated the group as trusted dealer, so it holds BOTH shares; pin --share 1 on
    # every box operation so it acts as share 1 deterministically. Without it, `keep` picks a
    # stored share non-deterministically and can act as share 2, colliding with the holder
    # (also share 2): the box then ignores the holder's announce as its own index and never
    # reaches quorum. Share 1 also matches the holder's --oprf-dealer 1.
    keep_bg(
        box,
        "box-announce",
        f"--path /root/box frost network serve --group {npub} --relay {relay_url} --share 1 "
        f"--tpm-tcti device:/dev/tpmrm0 --insecure-no-attestation",
    )
    # Announces are ephemeral, so attestation-provision holds a live subscription and listens for
    # the full --wait; the box re-announces every 20s, so a window over one interval deterministically
    # catches one. The outer retry only covers the box still warming up its first TPM quote.
    holder.wait_until_succeeds(
        f"{env} {keep} --no-mlock --path /root/holder frost network attestation-provision "
        f"--group {npub} --relay {relay_url} --out /root/policy.toml --wait 40",
        timeout=180,
    )
    holder.succeed("test -s /root/policy.toml")
    # Stop the bootstrap announcer so it does not share the box's identity with
    # the provisioning node below.
    box.succeed("systemctl stop box-announce.service")

    # --- 3. Holder serves as an OPRF holder: receives its share, verifies the box. ---
    # --oprf-auto-approve lets the holder answer evaluations unattended; it stays safe because the
    # oracle still requires the requester to be attestation-Verified and rate-limits each requester.
    keep_bg(
        holder,
        "holder-serve",
        f"--path /root/holder frost network serve --group {npub} --relay {relay_url} "
        f"--oprf-share-file /root/holder-oprf.share --oprf-dealer 1 --oprf-auto-approve "
        f"--attestation-config /root/policy.toml",
    )

    # --- 4. Box provisions the OPRF quorum (deals share 2 to the online holder). ---
    # The holder is listening (keep_bg waited for that); "No peers online" can still occur if a
    # discovery window just misses an announce, and it fails before any LUKS/key side effect, so
    # retry until the holder is discovered and shares are dealt.
    box.wait_until_succeeds(
        f"{env} {keep} --no-mlock --path /root/box frost network oprf-provision "
        f"--group {npub} --relay {relay_url} --share 1 --threshold 2 --total 2 --volume-id vault0 "
        f"--key-out /root/luks.key --share-out /root/box-oprf.share --tpm-tcti device:/dev/tpmrm0",
        timeout=120,
    )
    box.succeed("test -s /root/luks.key")
    holder.wait_until_succeeds("test -s /root/holder-oprf.share", timeout=60)

    # The holder must restart to LOAD its newly sealed share (it takes effect on
    # the next start); only then can it answer evaluations.
    holder.succeed("systemctl stop holder-serve.service")
    keep_bg(
        holder,
        "holder-serve2",
        f"--path /root/holder frost network serve --group {npub} --relay {relay_url} "
        f"--oprf-share-file /root/holder-oprf.share --oprf-dealer 1 --oprf-auto-approve "
        f"--attestation-config /root/policy.toml",
    )

    # --- 5. Box requests a 2-of-2 unlock; the reconstructed key must match. ---
    # The unlock is a read-only reconstruction, so retry until it yields the key, writing it to a
    # file we read back.
    box.wait_until_succeeds(
        f"{env} {keep} --no-mlock --path /root/box frost network oprf-unlock "
        f"--group {npub} --relay {relay_url} --share 1 --volume-id vault0 "
        f"--share-file /root/box-oprf.share --tpm-tcti device:/dev/tpmrm0 "
        f"> /root/unlocked.bin",
        timeout=120,
    )
    unlocked = box.succeed("od -An -v -tx1 /root/unlocked.bin | tr -d ' \\n'").strip()
    provisioned = box.succeed("od -An -v -tx1 /root/luks.key | tr -d ' \\n'").strip()
    assert len(provisioned) == 64, f"expected a 32-byte LUKS key, got {provisioned!r}"
    assert unlocked == provisioned, f"unlock key {unlocked!r} != provisioned {provisioned!r}"

    # --- 6. Below threshold: with the lone holder offline the box holds a single share
    # (< threshold 2), so the unlock must FAIL CLOSED and never reconstruct the key. ---
    holder.succeed("systemctl stop holder-serve2.service")
    # `timeout` bounds a hung quorum wait, so a never-answered request fails closed here
    # rather than stalling the test forever.
    box.fail(
        f"{env} timeout 30 {keep} --no-mlock --path /root/box frost network oprf-unlock "
        f"--group {npub} --relay {relay_url} --share 1 --volume-id vault0 "
        f"--share-file /root/box-oprf.share --tpm-tcti device:/dev/tpmrm0 "
        f"> /root/neg-unlock.out 2>/root/neg-unlock.err"
    )
    # ...and it emitted no usable key material: a failed unlock must not leak a 32-byte key.
    neg_size = box.succeed("stat -c %s /root/neg-unlock.out").strip()
    assert neg_size != "32", f"below-threshold unlock leaked a 32-byte key ({neg_size} bytes)"
  '';
}
