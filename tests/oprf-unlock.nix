# Real threshold-OPRF unlock over a live relay, no hardware: relay + box + one
# holder, each a NixOS VM, the box with swtpm. Proves the keep-cli OPRF quorum
# unlock end to end:
#
#   FROST group setup (box deals share 2 to the holder)
#   -> attestation bootstrap (box announces a quote, holder pins it TOFU)
#   -> holder serves as an OPRF holder (receives its share, then answers)
#   -> box provisions the OPRF quorum
#   -> box requests a 2-of-3 unlock and reconstructs the SAME LUKS key.
#
# The 3rd holder (replica) is absent: box + one holder = threshold 2, so a single
# share never reaches quorum. Attestation is real (swtpm quotes), though the VM's
# PCRs are the boot reset values (no measured boot), so the policy the holder pins
# is whatever the box actually attests; this exercises the produce/verify/gate
# path, not a meaningful measured-boot policy (that is keep-27yn / Lanzaboote).
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

  nodes.box =
    { pkgs, ... }:
    {
      environment.systemPackages = [
        keepCliPackage
        pkgs.cryptsetup
      ];
      virtualisation.tpm.enable = true; # swtpm -> /dev/tpmrm0
      networking.firewall.enable = false;
    };

  nodes.holder =
    { ... }:
    {
      environment.systemPackages = [ keepCliPackage ];
      networking.firewall.enable = false;
    };

  testScript = ''
    import re

    def must_match(pattern, text, what):
        m = re.search(pattern, text)
        assert m is not None, f"no {what} in output: {text!r}"
        return m.group(0)

    keep = "${keepCliPackage}/bin/keep"
    relay_url = "ws://relay:7777"
    # KEEP_YES skips confirmations; --no-mlock avoids RLIMIT_MEMLOCK failures in the
    # VM; KEEP_ALLOW_WS allows the plain-ws:// test relay (no TLS in the VM).
    env = "KEEP_PASSWORD=testpassword123 KEEP_YES=1 KEEP_ALLOW_WS=1"

    def keep_bg(node, unit, args):
        # Run a long-lived `keep` (serve/announce) as a transient unit in the background.
        node.succeed(
            f"systemd-run --unit={unit} "
            f"--setenv=KEEP_PASSWORD=testpassword123 --setenv=KEEP_YES=1 --setenv=KEEP_ALLOW_WS=1 "
            f"{keep} --no-mlock {args}"
        )
        # Fail fast (and name the unit) if the long-lived process crashed on startup,
        # e.g. a bad flag or an unreachable relay, instead of surfacing later as an
        # opaque downstream timeout. The subsequent sleeps remain as relay-propagation
        # margin (subscription/announce landing has no externally observable signal).
        node.wait_until_succeeds(f"systemctl is-active --quiet {unit}.service", timeout=15)

    start_all()
    relay.wait_for_unit("nostr-rs-relay.service")
    relay.wait_for_open_port(7777)
    box.wait_for_unit("multi-user.target")
    holder.wait_for_unit("multi-user.target")
    box.wait_for_file("/dev/tpmrm0")

    # --- 1. FROST group: box generates 2-of-3, exports share 2, holder imports it. ---
    box.succeed(f"{env} {keep} --no-mlock --path /root/box init")
    # `frost generate` prints the group npub to stderr; merge it so succeed() sees it.
    gen = box.succeed(f"{env} {keep} --no-mlock --path /root/box frost generate -t 2 -s 3 --name g 2>&1")
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
    keep_bg(
        box,
        "box-announce",
        f"--path /root/box frost network serve --group {npub} --relay {relay_url} "
        f"--tpm-tcti device:/dev/tpmrm0 --insecure-no-attestation",
    )
    holder.sleep(10)  # let the box's startup quote complete and its announce land
    holder.succeed(
        f"{env} {keep} --no-mlock --path /root/holder frost network attestation-provision "
        f"--group {npub} --relay {relay_url} --out /root/policy.toml --wait 20"
    )
    holder.succeed("test -s /root/policy.toml")
    # Stop the bootstrap announcer so it does not share the box's identity with
    # the provisioning node below.
    box.succeed("systemctl stop box-announce.service")

    # --- 3. Holder serves as an OPRF holder: receives its share, verifies the box. ---
    keep_bg(
        holder,
        "holder-serve",
        f"--path /root/holder frost network serve --group {npub} --relay {relay_url} "
        f"--oprf-share-file /root/holder-oprf.share --oprf-dealer 1 "
        f"--attestation-config /root/policy.toml",
    )
    holder.sleep(5)

    # --- 4. Box provisions the OPRF quorum (deals share 2 to the online holder). ---
    box.succeed(
        f"{env} {keep} --no-mlock --path /root/box frost network oprf-provision "
        f"--group {npub} --relay {relay_url} --threshold 2 --total 3 --volume-id vault0 "
        f"--key-out /root/luks.key --share-out /root/box-oprf.share --tpm-tcti device:/dev/tpmrm0"
    )
    box.succeed("test -s /root/luks.key")
    holder.wait_until_succeeds("test -s /root/holder-oprf.share", timeout=30)

    # The holder must restart to LOAD its newly sealed share (it takes effect on
    # the next start); only then can it answer evaluations.
    holder.succeed("systemctl stop holder-serve.service")
    keep_bg(
        holder,
        "holder-serve2",
        f"--path /root/holder frost network serve --group {npub} --relay {relay_url} "
        f"--oprf-share-file /root/holder-oprf.share --oprf-dealer 1 "
        f"--attestation-config /root/policy.toml",
    )
    holder.sleep(5)

    # --- 5. Box requests a 2-of-3 unlock; the reconstructed key must match. ---
    unlocked = box.succeed(
        f"{env} {keep} --no-mlock --path /root/box frost network oprf-unlock "
        f"--group {npub} --relay {relay_url} --volume-id vault0 "
        f"--share-file /root/box-oprf.share --tpm-tcti device:/dev/tpmrm0 "
        f"| xxd -p | tr -d '\\n'"
    ).strip()
    provisioned = box.succeed("xxd -p /root/luks.key | tr -d '\\n'").strip()
    assert len(provisioned) == 64, f"expected a 32-byte LUKS key, got {provisioned!r}"
    assert unlocked == provisioned, f"unlock key {unlocked!r} != provisioned {provisioned!r}"

    # --- 6. Below threshold: with the lone holder offline the box holds a single share
    # (< threshold 2), so the unlock must FAIL CLOSED and never reconstruct the key. ---
    holder.succeed("systemctl stop holder-serve2.service")
    # `timeout` bounds a hung quorum wait, so a never-answered request fails closed here
    # rather than stalling the test forever.
    box.fail(
        f"{env} timeout 30 {keep} --no-mlock --path /root/box frost network oprf-unlock "
        f"--group {npub} --relay {relay_url} --volume-id vault0 "
        f"--share-file /root/box-oprf.share --tpm-tcti device:/dev/tpmrm0 "
        f"> /root/neg-unlock.out 2>/root/neg-unlock.err"
    )
    # ...and it emitted no usable key material: a failed unlock must not leak a 32-byte key.
    neg_size = box.succeed("stat -c %s /root/neg-unlock.out").strip()
    assert neg_size != "32", f"below-threshold unlock leaked a 32-byte key ({neg_size} bytes)"
  '';
}
