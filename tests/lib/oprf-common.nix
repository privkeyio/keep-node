# Shared scaffolding for the real-OPRF-unlock nixosTests (oprf-unlock.nix = the 2-of-2 leg,
# oprf-unlock-2of3.nix = the 2-of-3 survivability leg). Both stand up the same relay + box(+swtpm) +
# holder topology and drive `keep` the same way; only the quorum and the unlock legs differ. This holds
# the parts that must stay in lockstep: the node module fragments and the Python testScript preamble
# (must_match / keep_bg / fail_closed / env). Each fixture imports this, wires the nodes, and appends its
# own body.
{
  keepCliPackage,
  wispModule,
  pkgs,
}:
let
  # Asserts the relay enforces NIP-42 auth: an unauthenticated REQ must be answered with a CLOSED
  # "auth-required" frame, never with events. Without this check a passing quorum could not distinguish an
  # authenticated client from auth being disabled on the relay.
  pyClient = pkgs.python3.withPackages (ps: [ ps.websockets ]);
  authProbe = pkgs.writeText "wisp-auth-probe.py" ''
    import asyncio, json, sys, websockets

    async def main():
        async with websockets.connect("ws://127.0.0.1:7777") as ws:
            await ws.send(json.dumps(["REQ", "unauth", {"kinds": [1], "limit": 1}]))
            for _ in range(6):
                try:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                except asyncio.TimeoutError:
                    sys.exit("relay never answered the unauthenticated REQ (auth withheld without a CLOSED frame?)")
                verb = msg[0]
                if verb == "CLOSED" and len(msg) > 2 and "auth-required" in msg[2]:
                    print("auth enforced:", msg[2])
                    return
                if verb == "EVENT":
                    sys.exit(f"LEAK: relay served an EVENT to an unauthenticated client: {msg}")
                if verb == "EOSE":
                    sys.exit(f"NOT ENFORCED: relay sent EOSE (served) without auth: {msg}")
                # AUTH challenge / NOTICE: keep reading
            sys.exit("no auth-required rejection observed")

    asyncio.run(main())
  '';
in
{
  # Wisp Nostr relay serving as the OPRF coordination relay. Binds 0.0.0.0 on 7777 so the box and holder
  # VMs reach it cross-node. auth.required enforces NIP-42, which keep satisfies automatically via
  # nostr-sdk. rate_limits are deliberately high so relay throttling never interferes with the OPRF
  # coordination (3s re-announce plus FROST rounds): the relay's per-minute limit is DoS hygiene, NOT the
  # key-leak throttle. The security-critical throttle -- capping OPRF evaluations per requester so a fixed
  # low-entropy input can't be replayed to reconstruct the key -- lives in keep's oracle
  # (--oprf-auto-approve) and is exercised by the holder legs. Exercising the relay's own per-minute
  # throttle is wisp-side coverage, tracked as keep-node-h3o; what this fixture proves at the relay is
  # auth enforcement (assert_auth_enforced).
  relayNode =
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

    def assert_auth_enforced(node):
        # Assert the relay rejects unauthenticated clients (NIP-42), so a passing quorum below confirms
        # keep authenticated rather than auth being disabled.
        node.succeed("${pyClient}/bin/python3 ${authProbe}")

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
