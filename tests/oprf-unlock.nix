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
let
  common = import ./lib/oprf-common.nix { inherit keepCliPackage; };
in
{
  name = "keep-node-oprf-unlock-test";

  nodes.relay = common.relayNode;
  nodes.box = common.boxNode;
  nodes.holder = common.holderNode;

  testScript = common.preamble + ''
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

    # The invariant oprf-unlock args shared verbatim by every unlock call site below (steps 5, 5b, 6),
    # defined once so the group/relay/share/volume/TPM binding stays in lockstep. Each site keeps its
    # own explicit prefix (keep binary + --path, any confinement/timeout wrapper), --share-file, and
    # redirect target -- the parts that legitimately differ per site.
    oprf_unlock_args = (
        f"frost network oprf-unlock --group {npub} --relay {relay_url} "
        f"--share 1 --volume-id vault0 --tpm-tcti device:/dev/tpmrm0"
    )

    # --- 5. Box requests a 2-of-2 unlock; the reconstructed key must match. ---
    # The unlock is a read-only reconstruction, so retry until it yields the key, writing it to a
    # file we read back.
    box.wait_until_succeeds(
        f"{env} {keep} --no-mlock --path /root/box {oprf_unlock_args} "
        f"--share-file /root/box-oprf.share "
        f"> /root/unlocked.bin",
        timeout=120,
    )
    unlocked = box.succeed("od -An -v -tx1 /root/unlocked.bin | tr -d ' \\n'").strip()
    provisioned = box.succeed("od -An -v -tx1 /root/luks.key | tr -d ' \\n'").strip()
    assert len(provisioned) == 64, f"expected a 32-byte LUKS key, got {provisioned!r}"
    assert unlocked == provisioned, f"unlock key {unlocked!r} != provisioned {provisioned!r}"

    # --- 5b. Non-root confined unlock (keep-node-5y0). The frost-gate runs `keep oprf-unlock` (the
    # relay-response parser) inside a transient systemd-run scope. wlc already drops all caps there,
    # but it still runs as uid 0, so a compromised parser can read any root-owned secret via DAC.
    # Prove the SAME real unlock succeeds as a dedicated UNPRIVILEGED user under that confinement, so
    # the frost-gate scope can drop to non-root. This surfaces exactly what a non-root uid needs:
    # (a) the keep DB on a path it can traverse -- /root is 0700, so relocate a copy to /var/lib;
    # (b) ownership of that DB (keep unlocks + writes its Argon2 vault there) and the OPRF share;
    # (c) the tss group for the TPM (/dev/tpmrm0) the box quotes with. The holder is still serving.
    box.succeed("useradd --system --user-group keepunlock")
    box.succeed(
        "install -d -o keepunlock -g keepunlock -m 0750 /var/lib/keepunlock && "
        "cp -a /root/box /var/lib/keepunlock/db && "
        "cp /root/box-oprf.share /var/lib/keepunlock/oprf.share && "
        "chown -R keepunlock:keepunlock /var/lib/keepunlock && "
        "chmod 0400 /var/lib/keepunlock/oprf.share"
    )
    # The `-p` set below MIRRORS the production frost-gate scope (nixos/frost-gate.nix:180-209)
    # so this test exercises the real confinement dropping to non-root, not a weaker copy. The one
    # deliberate deviation: NO RuntimeMaxSec=90. The unlock is wrapped in wait_until_succeeds(timeout=120)
    # and a per-invocation 90s hard kill under a loaded CI VM would cause spurious flakes unrelated to
    # confinement. User=keepunlock + SupplementaryGroups=tss are added on top of the production flags.
    # NOTE: this is a second real OPRF unlock from the same box FROST identity as step 5; it assumes
    # both fall within the holder's per-requester auto-approve rate-limit window (they have to date).
    box.wait_until_succeeds(
        f"{env} systemd-run --pipe --wait --collect --quiet "
        f"-p User=keepunlock -p SupplementaryGroups=tss "
        f"-p CapabilityBoundingSet= -p AmbientCapabilities= "
        f"-p NoNewPrivileges=yes -p SystemCallFilter=@system-service "
        f"-p SystemCallArchitectures=native "
        f"-p RestrictAddressFamilies='AF_UNIX AF_NETLINK AF_INET AF_INET6' "
        f"-p RestrictNamespaces=yes -p LockPersonality=yes -p MemoryDenyWriteExecute=yes "
        f"-p RestrictRealtime=yes -p RestrictSUIDSGID=yes "
        f"-p ProtectKernelTunables=yes -p ProtectKernelModules=yes -p ProtectKernelLogs=yes "
        f"-p ProtectControlGroups=yes -p ProtectHostname=yes "
        f"-p InaccessiblePaths='-/run/systemd/private -/run/dbus/system_bus_socket' "
        f"-p ProtectProc=invisible -p ProcSubset=pid "
        f"-E KEEP_PASSWORD -E KEEP_YES -E KEEP_ALLOW_WS -E KEEP_PEER_ANNOUNCE_INTERVAL_SECS "
        f"{keep} --no-mlock --path /var/lib/keepunlock/db {oprf_unlock_args} "
        f"--share-file /var/lib/keepunlock/oprf.share "
        f"> /root/nonroot-unlocked.bin",
        timeout=120,
    )
    nonroot = box.succeed("od -An -v -tx1 /root/nonroot-unlocked.bin | tr -d ' \\n'").strip()
    assert nonroot == provisioned, f"non-root unlock {nonroot!r} != provisioned {provisioned!r}"

    # Prove the DAC boundary that MOTIVATES step 5b: keepunlock is a distinct unprivileged uid, so it
    # must NOT be able to read the root-owned secrets a compromised uid-0 parser could. /root/luks.key
    # (the provisioned key) and /root/box (the keep DB) live under 0700 root:root /root; runuser (from
    # util-linux) drops to keepunlock and every read must be refused. Assert root ownership first so a
    # failing read is a real DAC denial, not a false pass on a missing/renamed path.
    box.succeed("test \"$(stat -c %U /root/luks.key)\" = root")
    box.succeed("test \"$(stat -c '%U %a' /root)\" = 'root 700'")
    box.fail("runuser -u keepunlock -- cat /root/luks.key")
    box.fail("runuser -u keepunlock -- ls /root/box")

    # --- 6. Below threshold: with the lone holder offline the box holds a single share
    # (< threshold 2), so the unlock must FAIL CLOSED and never reconstruct the key. ---
    holder.succeed("systemctl stop holder-serve2.service")
    # `timeout` bounds a hung quorum wait, so a never-answered request fails closed here
    # rather than stalling the test forever.
    box.fail(
        f"{env} timeout 30 {keep} --no-mlock --path /root/box {oprf_unlock_args} "
        f"--share-file /root/box-oprf.share "
        f"> /root/neg-unlock.out 2>/root/neg-unlock.err"
    )
    # ...and it emitted no usable key material: a failed unlock must leak no key bytes to stdout. The
    # shared helper strips keep-cli's error-path terminal escape before asserting the remainder is empty.
    fail_closed(box, "/root/neg-unlock.out")
  '';
}
