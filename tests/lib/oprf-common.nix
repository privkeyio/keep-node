# Shared scaffolding for the real-OPRF-unlock nixosTests (oprf-unlock.nix = the 2-of-2 leg,
# oprf-unlock-2of3.nix = the 2-of-3 survivability leg). Both stand up the same relay + box(+swtpm) +
# holder topology and drive `keep` the same way; only the quorum and the unlock legs differ. This holds
# the parts that must stay in lockstep: the node module fragments and the Python testScript preamble
# (must_match / keep_bg / env). Each fixture imports this, wires the nodes, and appends its own body.
{ keepCliPackage }:
{
  # The relay binds 0.0.0.0 by default; the nixpkgs module hardcodes network.port and discards
  # settings.network.address via a shallow `//` merge, so the default is already what the box/holder
  # VMs reach cross-node.
  relayNode =
    { ... }:
    {
      services.nostr-rs-relay = {
        enable = true;
        port = 7777;
      };
      networking.firewall.allowedTCPPorts = [ 7777 ];
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
  # binary + relay URL + env, and the background-serve helper. Append each fixture's body after this.
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
