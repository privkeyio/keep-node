# Real 2-of-3 threshold-OPRF unlock over a live relay, no hardware: relay + box + TWO holders, each a
# NixOS VM, the box with swtpm. Proves the survivability property that 2-of-3 exists for: the box plus
# ANY ONE of the two holders reconstructs the SAME LUKS key, while the box alone (one share, below the
# threshold of 2) fails closed. keep does t-of-n natively (in-exponent Lagrange; the box discovers and
# samples holders at runtime, taking no holder-identity args), so this needs no keep change.
#
#   FROST group setup (box deals shares 2 and 3 to holder and holder2)
#   -> attestation bootstrap (box announces a quote, BOTH holders pin it TOFU)
#   -> both holders serve; box provisions the 2-of-3 quorum (needs all `total` online)
#   -> leg A: box + holder      unlocks
#   -> leg B: box + holder2     unlocks to the SAME key (losing holder A is survivable)
#   -> leg C: box + neither     fails closed, no key material.
#
# This is the light, reboot-free crypto proof; the through-the-gate 2-of-3 (boot gate + confined
# non-root unlock across reboots) is a separate, heavier test. Attestation is real (swtpm quotes) but
# the PCRs are boot reset values (no measured boot), so this exercises produce/verify/gate, not a
# meaningful measured-boot policy.
#
# Run: nix build .#checks.x86_64-linux.oprf-unlock-2of3
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
  name = "keep-node-oprf-unlock-2of3-test";

  nodes.relay = common.relayNode;
  nodes.box = common.boxNode;
  # Two holders, identical but for their DB path and FROST share (2 vs 3), set in the testScript.
  nodes.holder = common.holderNode;
  nodes.holder2 = common.holderNode;

  testScript = common.preamble + ''
    start_all()
    relay.wait_for_unit("wisp.service")
    relay.wait_for_open_port(7777)
    # The relay requires NIP-42 auth; prove it refuses unauthenticated clients before the quorum runs.
    assert_auth_enforced(relay)
    box.wait_for_unit("multi-user.target")
    holder.wait_for_unit("multi-user.target")
    holder2.wait_for_unit("multi-user.target")
    box.wait_for_file("/dev/tpmrm0")

    # --- 1. FROST group: box generates 2-of-3, exports share 2 to holder and share 3 to holder2. ---
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
    # The "either holder is survivable" claim is only meaningful if the two holders hold DISTINCT
    # shares; if `frost export` regressed and dealt the same share twice, both legs would still pass
    # while proving nothing. Assert distinctness so that green means what it claims.
    assert kshare2 != kshare3, f"shares 2 and 3 are identical ({kshare2!r}); survivability proof is vacuous"
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

    # --- 3. Both holders serve as OPRF holders (share 2 / share 3), verifying the box. ---
    def serve(h, unit):
        keep_bg(
            h,
            unit,
            f"--path /root/{h.name} frost network serve --group {npub} --relay {relay_url} "
            f"--oprf-share-file /root/{h.name}-oprf.share --oprf-dealer 1 --oprf-auto-approve "
            f"--attestation-config /root/policy.toml",
        )

    serve(holder, "holder-serve")
    serve(holder2, "holder2-serve")

    # --- 4. Box provisions the 2-of-3 quorum. Provisioning seals a share to EVERY party, so it needs
    # both holders online (unlike unlock, which is fault-tolerant). ---
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

    # Each holder must restart to LOAD its newly sealed OPRF share (takes effect on next start).
    holder.succeed("systemctl stop holder-serve.service")
    holder2.succeed("systemctl stop holder2-serve.service")

    # The invariant oprf-unlock frost args, shared verbatim by the positive legs (unlock_key) and the
    # negative leg C, so the fail-closed leg can never drift from the legs it must mirror. Each call
    # site keeps its own prefix (keep binary + --path, any timeout wrapper) and redirect target.
    oprf_unlock_args = (
        f"frost network oprf-unlock --group {npub} --relay {relay_url} "
        f"--share 1 --volume-id vault0 --tpm-tcti device:/dev/tpmrm0 --share-file /root/box-oprf.share"
    )

    def unlock_key(dst):
        # Read-only reconstruction. Exactly one holder is online per leg, but the just-stopped holder's
        # announce can still be sampled, so an attempt may pick the absent one and fail; the retry
        # converges on the online holder that actually answers. keep's oracle rate-limits a requester to
        # 8 OPRF evals per 60s (MAX_OPRF_EVALS_PER_WINDOW), so a tight wait_until_succeeds loop can
        # exhaust that budget against the online holder before it converges, after which the unlock can
        # never succeed (flake). Space the retries >= 10s so the eval rate stays under 8/60s no matter
        # how many attempts miss, while still giving ~12 attempts to converge.
        import time

        status = 1
        attempts = 12
        for attempt in range(attempts):
            status, _ = box.execute(f"{env} timeout 30 {keep} --no-mlock --path /root/box {oprf_unlock_args} > {dst}")
            if status == 0:
                return box.succeed(f"od -An -v -tx1 {dst} | tr -d ' \\n'").strip()
            if attempt < attempts - 1:
                time.sleep(10)
        raise Exception(f"oprf-unlock did not converge within the retry budget (last exit {status})")

    # --- Leg A: box + holder (holder2 down) reconstructs the provisioned key. ---
    serve(holder, "holder-serve2")
    key_a = unlock_key("/root/unlock-a.bin")
    assert key_a == provisioned, f"box+holder key {key_a!r} != provisioned {provisioned!r}"

    # --- Leg B: box + holder2 (holder down) reconstructs the SAME key -- losing holder A is survivable. ---
    holder.succeed("systemctl stop holder-serve2.service")
    serve(holder2, "holder2-serve2")
    key_b = unlock_key("/root/unlock-b.bin")
    assert key_b == provisioned, f"box+holder2 key {key_b!r} != provisioned {provisioned!r}"

    # --- Leg C: box + neither holder is below threshold -> fail closed, no key material. ---
    holder2.succeed("systemctl stop holder2-serve2.service")
    box.fail(
        f"{env} timeout 30 {keep} --no-mlock --path /root/box {oprf_unlock_args} "
        f"> /root/neg.out 2>/root/neg.err"
    )
    # ...and it emitted no KEY MATERIAL: a failed unlock must leak no key bytes to stdout. The shared
    # helper strips keep-cli's error-path terminal escape before asserting the remainder is empty.
    fail_closed(box, "/root/neg.out")
  '';
}
