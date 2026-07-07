# Shared scaffolding for the real-OPRF-unlock nixosTests (oprf-unlock.nix = the 2-of-2 leg,
# oprf-unlock-2of3.nix = the 2-of-3 survivability leg). Both stand up the same relay + box(+swtpm) +
# holder topology and drive `keep` the same way; only the quorum and the unlock legs differ. This holds
# the parts that must stay in lockstep: the node module fragments and the Python testScript preamble
# (must_match / keep_bg / fail_closed / env). Each fixture imports this, wires the nodes, and appends its
# own body.
{
  keepCliPackage,
  wispModule,
}:
{
  # wisp (privkey's own Nostr relay) dogfooded as the OPRF coordination relay (GH #11), replacing the
  # nostr-rs-relay expedience stand-in. Binds 0.0.0.0 so the box/holder VMs reach it cross-node, opened
  # on 7777. This is the relay the appliance should actually ship, and the path to testing the
  # security-meaningful authenticated/rate-limited unlock relay the frost-gate requires.
  relayNode =
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

  # keep-cli's relay-URL guard rejects single-label hosts as internal (SSRF protection) with no runtime
  # opt-out, so the box/holder reach the relay by a dotted name (relay.kfp) that passes validation;
  # ws:// skips cert-pinning's resolved-IP check, so the private VM address it resolves to is fine.
  boxNode =
    { pkgs, nodes, ... }:
    {
      environment.systemPackages = [
        keepCliPackage
        pkgs.cryptsetup
      ];
      virtualisation.tpm.enable = true; # swtpm -> /dev/tpmrm0
      # Create the tss group and set /dev/tpmrm0 to tss:0660 (udev) so a non-root confined unlock can
      # reach the TPM via SupplementaryGroups=tss; root (the every-boot path) is unaffected.
      security.tpm2.enable = true;
      networking.firewall.enable = false;
      networking.extraHosts = "${nodes.relay.networking.primaryIPAddress} relay.kfp";
    };

  # A holder VM. Reused verbatim as holder2 in the 2-of-3 fixture; the per-holder DB path and FROST
  # share are set in the testScript, not here, so the module is identical for both.
  holderNode =
    { nodes, ... }:
    {
      environment.systemPackages = [ keepCliPackage ];
      networking.firewall.enable = false;
      networking.extraHosts = "${nodes.relay.networking.primaryIPAddress} relay.kfp";
    };

  # Python testScript preamble shared verbatim by both fixtures: imports, the regex matcher, the keep
  # binary + relay URL + env, the background-serve helper, and the fail-closed stdout-leak assertion.
  # Append each fixture's body after this.
  # KEEP_YES skips confirmations; --no-mlock avoids RLIMIT_MEMLOCK failures in the VM; KEEP_ALLOW_WS
  # allows the plain-ws:// test relay; KEEP_PEER_ANNOUNCE_INTERVAL_SECS shrinks the 20s re-announce
  # cadence so peer discovery reliably overlaps an announce, making the rendezvous deterministic.
  preamble = ''
    import re

    def must_match(pattern, text, what):
        m = re.search(pattern, text)
        assert m is not None, f"no {what} in output: {text!r}"
        return m.group(0)

    keep = "${keepCliPackage}/bin/keep"
    relay_url = "ws://relay.kfp:7777"
    env = "KEEP_PASSWORD=testpassword123 KEEP_YES=1 KEEP_ALLOW_WS=1 KEEP_PEER_ANNOUNCE_INTERVAL_SECS=3"

    def fail_closed(node, out_path):
        # Shared fail-closed assertion for the below-threshold (no-quorum) unlock legs. The security
        # property is "a failed unlock reconstructs no usable key," so the meaningful check is that stdout
        # carries no key bytes -- not that it is byte-empty. keep-cli's error-exit path writes a terminal
        # control escape (alt-screen-exit, `\e[?1049l`, the progress-spinner's cleanup) to stdout, so strip
        # ANSI escapes first, then require what remains to be empty. (On the SUCCESS path stdout is exactly
        # the 32-byte key -- verified in the 2-of-2 fixture -- so the frost-gate's key capture is
        # unaffected; the stray escape is a keep-cli stdout-hygiene nit tracked as keep-node-95y.) The
        # exact-32-byte guard is a second, independent backstop.
        clean_path = out_path + ".clean"
        node.succeed(rf"""sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' {out_path} > {clean_path}""")
        clean_size = node.succeed(f"stat -c %s {clean_path}").strip()
        assert clean_size == "0", f"fail-closed unlock leaked {clean_size} non-escape bytes to stdout ({out_path})"
        raw_size = node.succeed(f"stat -c %s {out_path}").strip()
        assert raw_size != "32", f"fail-closed unlock leaked a 32-byte key ({raw_size} bytes, {out_path})"

    def keep_bg(node, unit, args):
        # Run a long-lived `keep` (serve/announce) as a transient unit in the background.
        node.succeed(
            f"systemd-run --unit={unit} "
            f"--setenv=KEEP_PASSWORD=testpassword123 --setenv=KEEP_YES=1 --setenv=KEEP_ALLOW_WS=1 "
            f"--setenv=KEEP_PEER_ANNOUNCE_INTERVAL_SECS=3 "
            f"{keep} --no-mlock {args}"
        )
        # Wait until the node is actually serving, not merely until the unit is active: `keep` unlocks
        # its vault (Argon2) BEFORE it starts the node, which can take tens of seconds in a loaded VM.
        # The "Listening" banner means it has subscribed and is announcing, so the box never
        # provisions/unlocks before this peer can answer; this also fails fast on a startup crash.
        node.wait_until_succeeds(
            f"journalctl -u {unit}.service --no-pager | grep -q 'Listening for FROST messages'",
            timeout=180,
        )
  '';
}
