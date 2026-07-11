# Measured-boot PCR 11 reference pinning (keep-node-61j): a holder that provisions its OPRF
# attestation policy with `--expected-pcr` REFUSES a box whose measured-boot PCR 11 differs from the
# known-good reference, instead of blind trust-on-first-use. This proves the OPRF quorum rejects a
# tampered-kernel peer at the attestation layer.
#
# The box is given a DETERMINISTIC, non-zero PCR 11 with `tpm2_pcrextend` (a stand-in for the real
# Lanzaboote UKI measurement), so the rejection mechanism runs in the light OPRF harness , no OVMF /
# measured boot needed. Deriving the reference PCR 11 from the actual UKI (systemd-measure) is the
# separate PR 2 half of 61j; this test proves the holder-side rejection the reference feeds.
#
#   box: fresh 2-of-3 group + share 1; extend PCR 11 to a known value; announce a signed TPM quote
#   -> holder + `--expected-pcr 11=<box's real PCR 11>`  => provisions (the reference matches)
#   -> holder + `--expected-pcr 11=<a different value>`  => REFUSES (no policy written): the rejection.
#
# Run: nix build .#checks.x86_64-linux.oprf-attestation-reject
{
  keepCliPackage,
  wispModule,
  pkgs,
  ...
}:
let
  common = import ./lib/oprf-common.nix { inherit keepCliPackage wispModule pkgs; };
in
{
  name = "keep-node-oprf-attestation-reject-test";

  nodes.relay = common.relayNode;
  nodes.box =
    { pkgs, ... }:
    {
      imports = [ common.boxNode ];
      # tpm2_pcrextend / tpm2_pcrread, to plant + read a deterministic PCR 11.
      environment.systemPackages = [ pkgs.tpm2-tools ];
    };
  nodes.holder = common.holderNode;

  testScript = common.preamble + ''
    start_all()
    relay.wait_for_unit("wisp.service")
    relay.wait_for_open_port(7777)
    assert_auth_enforced(relay)
    box.wait_for_file("/dev/tpmrm0")
    holder.wait_for_unit("multi-user.target")

    # A fresh 2-of-3 group; the box keeps share 1 and announces a proof-of-share + TPM quote. (The
    # holder needs no share/vault for attestation-provision , it only observes announces on the relay.)
    box.succeed(f"{env} {keep} --no-mlock --path /root/box init")
    gen = box.succeed(f"{env} {keep} --no-mlock --path /root/box frost generate -t 2 -s 3 --name g 2>&1")
    npub = must_match(r"npub1[a-z0-9]{50,}", gen, "group npub")

    # Give the box a deterministic, NON-ZERO PCR 11 (a stand-in for a measured-boot UKI value) BEFORE it
    # announces, then read it back as the known-good reference the holder will pin.
    box.succeed("tpm2_pcrextend -T device:/dev/tpmrm0 11:sha256=" + "ab" * 32)
    ref = box.succeed(
        "tpm2_pcrread -T device:/dev/tpmrm0 sha256:11 | grep -aoiE '0x[0-9a-f]{64}' | head -1 | sed 's/0[xX]//'"
    ).strip().lower()
    assert len(ref) == 64, f"expected a 32-byte (64 hex) PCR 11, got {ref!r}"

    # Box announces its quote (carrying the extended PCR 11) over the relay.
    keep_bg(
        box, "box-announce",
        f"--path /root/box frost network serve --group {npub} --relay {relay_url} --share 1 "
        f"--tpm-tcti device:/dev/tpmrm0 --insecure-no-attestation",
    )

    # POSITIVE: a holder pinning the box's ACTUAL PCR 11 provisions a policy (the reference matches, so
    # the box is admitted), and the pinned reference carries that PCR 11 value.
    holder.wait_until_succeeds(
        f"{env} {keep} --no-mlock frost network attestation-provision "
        f"--group {npub} --relay {relay_url} --expected-pcr 11={ref} --out /root/ok.toml --wait 20",
        timeout=90,
    )
    holder.succeed("test -s /root/ok.toml")
    holder.succeed(f"grep -qi {ref} /root/ok.toml")

    # NEGATIVE (the rejection this test exists for): a holder pinning a DIFFERENT PCR 11 refuses the box
    # , provisioning captures no peer and writes no policy. This is what stops a tampered-kernel peer
    # (whose PCR 11 diverges from the known-good reference) from ever being admitted to the quorum.
    wrong = "cd" * 32
    box.succeed("systemctl restart box-announce.service")  # keep announcing for the second provision
    holder.fail(
        f"{env} {keep} --no-mlock frost network attestation-provision "
        f"--group {npub} --relay {relay_url} --expected-pcr 11={wrong} --out /root/bad.toml --wait 20"
    )
    holder.fail("test -e /root/bad.toml")
  '';
}
