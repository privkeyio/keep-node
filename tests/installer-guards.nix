# Runtime coverage for install-keepnode's safety guards (keep-node-4ir). The checks that protect an
# operator from a bricked or unreachable install all run BEFORE the destructive wipe, so exercising
# them is cheap and needs no real install: each case must fail with the target disk left pristine.
# (The full install-mechanics path -- partition -> nixos-install the closure -> enroll the key -- is a
# heavier separate test; this covers the validation/safety logic, the part most likely to brick a box.)
#
# Run: nix build .#checks.x86_64-linux.installer-guards
{ adminKeyFixture, keepnodeToplevel, ... }:
{
  name = "keep-node-installer-guards";

  nodes.machine =
    { ... }:
    {
      imports = [ ../nixos/installer.nix ];
      # installer.nix needs the appliance closure it would install; the guard cases never reach the
      # install, so a minimal stand-in closure (passed from the flake check) keeps the test light.
      _module.args.keepnodeToplevel = keepnodeToplevel;
      # A scratch disk to point the installer at. Every case below aborts before the wipe, so it stays
      # blank -- asserted at the end.
      virtualisation.emptyDiskImages = [ 256 ];
    };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    pubkey = machine.succeed("cat ${adminKeyFixture}/id.pub").strip()

    # Each guard must fail (non-zero) and, crucially, before the destructive wipe. 'no\n' on stdin is
    # the confirmation answer for the one case that reaches the prompt; the earlier guards exit first.

    # 1. No --ssh-key: the hardened image is key-only (no password), so refuse rather than install a
    #    permanently-unreachable node.
    machine.fail("printf 'no\\n' | install-keepnode /dev/vdb")

    # 2. Malformed key (prefix ok, but ssh-keygen cannot parse it): refuse, so a typo can't enroll a key
    #    that locks the operator out.
    machine.fail("printf 'no\\n' | install-keepnode /dev/vdb --ssh-key 'ssh-ed25519 not-a-real-key'")

    # 3. A non-block-device target: usage error rather than wiping the wrong thing.
    machine.fail(f"printf 'no\\n' | install-keepnode /dev/does-not-exist --ssh-key '{pubkey}'")

    # 4. Valid key + real disk, but the confirmation is not exactly YES: abort before the wipe.
    machine.fail(f"printf 'no\\n' | install-keepnode /dev/vdb --ssh-key '{pubkey}'")

    # The destructive path is gated behind every check above: /dev/vdb must still be a blank disk with
    # no partition table (a regression that skipped a guard would have wiped + partitioned it).
    machine.succeed("test -b /dev/vdb")
    machine.fail("sgdisk -p /dev/vdb | grep -qiE 'ESP|nixos'")
  '';
}
