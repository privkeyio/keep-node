# Coercion resistance, end-to-end over a live (NIP-42) relay: a verified duress
# beacon freezes an OPRF holder, which drops the box below its 2-of-3 threshold so
# reconstruction fails closed; the freeze survives the holder restarting (sticky
# --duress-state-file); and a delayed operator clear (duress-clear initiate ->
# wait out the delay -> execute) lifts it so the box reconstructs the key again.
#
#   FROST 2-of-3 group + attestation bootstrap + OPRF provision (box + holder + holder2)
#   -> baseline: box + holder reconstructs the provisioned key
#   -> holder2 enters duress mode and PUBLISHES a beacon through wisp (NIP-42 auth);
#      holder (pinned to it) verifies and freezes
#   -> box + holder now fails closed (holder frozen -> below threshold), no key bytes
#   -> restart holder's serve: it RESTORES the persisted freeze -> still fails closed
#   -> duress-clear initiate + advance all clocks past the delay floor + execute
#   -> holder serves un-frozen again -> box + holder reconstructs the key.
#
# Using wisp (not a no-auth relay) is deliberate: it proves the dedicated beacon key
# authenticates to the relay via NIP-42 and its beacon actually reaches the holder,
# the real delivery path (keep-node-9cx).
#
# Heavy: 4 VMs (relay + box[swtpm] + 2 holders) + Argon2-HIGH duress derivations.
# Shared scaffolding: tests/lib/oprf-common.nix (as in oprf-unlock-2of3).
#
# Run: nix build .#checks.x86_64-linux.duress-freeze
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
  name = "keep-node-duress-freeze-test";

  nodes.relay = common.relayNode;
  nodes.box = common.boxNode;
  nodes.holder = common.holderNode;
  nodes.holder2 = common.holderNode;

  testScript = common.preamble + ''
    # A duress credential: >= 12 chars (the provisioning floor) and distinct from
    # the vault password the fixtures use.
    duress_cred = "duress-secret-phrase"

    start_all()
    relay.wait_for_unit("wisp.service")
    relay.wait_for_open_port(7777)
    assert_auth_enforced(relay)
    box.wait_for_unit("multi-user.target")
    holder.wait_for_unit("multi-user.target")
    holder2.wait_for_unit("multi-user.target")
    box.wait_for_file("/dev/tpmrm0")

    # --- 1. FROST group: box generates 2-of-3, exports share 2 / share 3. ---
    box.succeed(f"{env} {keep} --no-mlock --path /root/box init")
    gen = box.succeed(f"{env} {keep} --no-mlock --path /root/box frost generate -t 2 -s 3 --name g 2>&1")
    npub = must_match(r"npub1[a-z0-9]{50,}", gen, "group npub")

    def export_share(idx):
        out = box.succeed(
            f"printf 'sharepass1\\nsharepass1\\n' | "
            f"{env} {keep} --no-mlock --path /root/box frost export --share {idx} --group {npub}"
        )
        return must_match(r"kshare1[a-z0-9]+", out, f"exported share {idx}")

    kshare2 = export_share(2)
    kshare3 = export_share(3)
    holder.succeed(f"{env} {keep} --no-mlock --path /root/holder init")
    holder.succeed(
        f"printf '{kshare2}\\n\\nsharepass1\\n' | {env} {keep} --no-mlock --path /root/holder frost import"
    )
    holder2.succeed(f"{env} {keep} --no-mlock --path /root/holder2 init")
    holder2.succeed(
        f"printf '{kshare3}\\n\\nsharepass1\\n' | {env} {keep} --no-mlock --path /root/holder2 frost import"
    )

    # --- 2. Attestation bootstrap: box announces a TPM quote; BOTH holders pin it TOFU. ---
    keep_bg(
        box,
        "box-announce",
        f"--path /root/box frost network serve --group {npub} --relay {relay_url} --share 1 "
        f"--tpm-tcti device:/dev/tpmrm0 --insecure-no-attestation",
    )
    for h in [holder, holder2]:
        h.wait_until_succeeds(
            f"{env} {keep} --no-mlock --path /root/{h.name} frost network attestation-provision "
            f"--group {npub} --relay {relay_url} --out /root/policy.toml --wait 40",
            timeout=180,
        )
        h.succeed("test -s /root/policy.toml")
    box.succeed("systemctl stop box-announce.service")

    # --- 3. Both holders serve; box provisions the 2-of-3 quorum (needs both online). ---
    def serve(h, unit, extra=""):
        keep_bg(
            h,
            unit,
            f"--path /root/{h.name} frost network serve --group {npub} --relay {relay_url} "
            f"--oprf-share-file /root/{h.name}-oprf.share --oprf-dealer 1 --oprf-auto-approve "
            f"--attestation-config /root/policy.toml {extra}",
        )

    serve(holder, "holder-serve")
    serve(holder2, "holder2-serve")
    box.wait_until_succeeds(
        f"{env} {keep} --no-mlock --path /root/box frost network oprf-provision "
        f"--group {npub} --relay {relay_url} --share 1 --threshold 2 --total 3 --volume-id vault0 "
        f"--key-out /root/luks.key --share-out /root/box-oprf.share --tpm-tcti device:/dev/tpmrm0",
        timeout=120,
    )
    provisioned = box.succeed("od -An -v -tx1 /root/luks.key | tr -d ' \\n'").strip()
    assert len(provisioned) == 64, f"expected a 32-byte LUKS key, got {provisioned!r}"
    holder.wait_until_succeeds("test -s /root/holder-oprf.share", timeout=60)
    holder2.wait_until_succeeds("test -s /root/holder2-oprf.share", timeout=60)
    holder.succeed("systemctl stop holder-serve.service")
    holder2.succeed("systemctl stop holder2-serve.service")

    oprf_unlock_args = (
        f"frost network oprf-unlock --group {npub} --relay {relay_url} "
        f"--share 1 --volume-id vault0 --tpm-tcti device:/dev/tpmrm0 --share-file /root/box-oprf.share"
    )

    def unlock_key(dst):
        import time

        status = 1
        for attempt in range(12):
            status, _ = box.execute(f"{env} timeout 30 {keep} --no-mlock --path /root/box {oprf_unlock_args} > {dst}")
            if status == 0:
                return box.succeed(f"od -An -v -tx1 {dst} | tr -d ' \\n'").strip()
            if attempt < 11:
                time.sleep(10)
        raise Exception(f"oprf-unlock did not converge (last exit {status})")

    def unlock_fails_closed(tag):
        box.fail(
            f"{env} timeout 30 {keep} --no-mlock --path /root/box {oprf_unlock_args} "
            f"> /root/{tag}.out 2>/root/{tag}.err"
        )
        fail_closed(box, f"/root/{tag}.out")

    # === Baseline: box + holder (holder2 down) reconstructs the provisioned key. ===
    serve(holder, "holder-baseline")
    assert unlock_key("/root/base.bin") == provisioned, "baseline box+holder unlock must match provisioned key"
    holder.succeed("systemctl stop holder-baseline.service")

    # === Derive holder2's duress-beacon identity (pubkey npub + hex salt). ===
    prov = holder2.succeed(
        f"KEEP_DURESS_PASSWORD={duress_cred} {env} {keep} --no-mlock --path /root/holder2 "
        f"frost network duress-provision 2>&1"
    )
    # Anchor to the field labels (and take the captured group) so output ordering
    # can never bind holder2's own npub or some other hex token to the pin/salt.
    def match_group1(pattern, text, what):
        m = re.search(pattern, text)
        assert m is not None, f"no {what} in output: {text!r}"
        return m.group(1)

    # `.*?` stays on the label's line (`.` never crosses newlines) and tolerates the
    # colon inside the salt label, binding the value to its own field.
    beacon_npub = match_group1(r"Beacon pubkey.*?(npub1[0-9a-z]+)", prov, "beacon npub")
    beacon_salt = match_group1(r"Salt.*?([0-9a-f]{64})", prov, "beacon salt hex")

    # === Duress: holder serves pinned to holder2's beacon, with a sticky state file. ===
    def serve_duress_holder(unit):
        serve(
            holder, unit,
            extra=f"--duress-beacon-pin {beacon_npub} --duress-state-file /root/holder-duress.state",
        )

    serve_duress_holder("holder-duress")

    # holder2 enters duress mode (KEEP_PASSWORD = the duress credential + its own
    # pinned beacon config) and publishes a signed beacon through the NIP-42 relay.
    holder2.succeed(
        f"systemd-run --unit=holder2-duress "
        f"--setenv=KEEP_PASSWORD={duress_cred} --setenv=KEEP_YES=1 --setenv=KEEP_ALLOW_WS=1 "
        f"{keep} --no-mlock --path /root/holder2 frost network serve --group {npub} --relay {relay_url} "
        f"--duress-beacon-pubkey {beacon_npub} --duress-beacon-salt {beacon_salt} --insecure-no-attestation"
    )
    # Fail fast if the duress serve crashes at startup (e.g. the credential does
    # not derive the pinned beacon key) instead of surfacing only as the 180s
    # freeze-wait timeout below. run_duress_serve prints this once it has detected
    # duress and is about to publish.
    holder2.wait_until_succeeds(
        "journalctl -u holder2-duress.service --no-pager | grep -q 'Starting FROST coordination node'",
        timeout=120,
    )

    # holder verifies the beacon and freezes; the freeze is persisted.
    holder.wait_until_succeeds(
        "journalctl -u holder-duress.service --no-pager | grep -q 'DURESS BEACON verified'",
        timeout=180,
    )
    holder.wait_until_succeeds("test -s /root/holder-duress.state", timeout=30)

    # === box + holder now fails closed: holder frozen -> below threshold, no key. ===
    unlock_fails_closed("frozen")

    # === Sticky across restart: restart holder's serve -> it RESTORES the freeze. ===
    holder.succeed("systemctl stop holder-duress.service")
    serve_duress_holder("holder-duress2")
    holder.wait_until_succeeds(
        "journalctl -u holder-duress2.service --no-pager | grep -q 'Restored persisted DURESS freeze'",
        timeout=180,
    )
    unlock_fails_closed("sticky")

    # === Operator clear (the coercion has ended). Stop holder2's duress serve
    # FIRST so it stops re-broadcasting; then initiate (at the 1h floor), advance
    # ALL clocks past the delay (which also ages any lingering beacon out of the
    # freshness window so the resumed holder cannot re-freeze on it), and execute. ===
    holder2.succeed("systemctl stop holder2-duress.service")
    holder.succeed(
        f"{env} {keep} --no-mlock frost network duress-clear "
        f"--state-file /root/holder-duress.state initiate --delay-secs 3600"
    )
    # execute trusts the wall clock; advance every node together so OPRF replay
    # windows stay consistent across the quorum after the jump. The +2h jump must
    # exceed BOTH keep constants it straddles: the 1h clear delay above (so execute
    # is permitted) AND keep's 300s beacon freshness window (so the last relay-
    # persisted beacon is stale by the time holder-cleared resubscribes and cannot
    # re-freeze it). If keep ever raises either past 2h, bump this in step.
    for n in [relay, box, holder, holder2]:
        n.succeed("date -s '+2 hours'")
    holder.succeed(
        f"{env} {keep} --no-mlock frost network duress-clear "
        f"--state-file /root/holder-duress.state execute"
    )
    holder.fail("test -e /root/holder-duress.state")

    # === Cleared: holder serves un-frozen again -> box + holder reconstructs the key. ===
    holder.succeed("systemctl stop holder-duress2.service")
    serve_duress_holder("holder-cleared")
    assert unlock_key("/root/cleared.bin") == provisioned, "after clear, box+holder unlock must match again"
  '';
}
