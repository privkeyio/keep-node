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
      # Two scratch disks to point the installer at. Every case below aborts before the wipe, so
      # /dev/vdb stays blank (asserted at the end); /dev/vdc gets a partition so we can prove the
      # installer refuses a partition target (the whole-disk guard).
      virtualisation.emptyDiskImages = [
        256
        256
      ];
    };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    pubkey = machine.succeed("cat ${adminKeyFixture}/id.pub").strip()

    # Give /dev/vdc a single partition so case 4 can exercise the whole-disk-vs-partition guard
    # (installer.nix refuses a target whose lsblk TYPE is not "disk").
    machine.succeed("sgdisk -n1:0:+16M -t1:8300 /dev/vdc")
    machine.succeed("partprobe /dev/vdc || true")
    machine.succeed("udevadm settle")
    machine.succeed("test -b /dev/vdc1")

    # Each guard must abort before the destructive wipe. We assert the guard's *specific* message so
    # that deleting a guard fails the test: without the assertion, a removed guard would just fall
    # through to the confirmation prompt, abort on the piped 'no', and still exit non-zero (green).
    # The piped 'no' is the confirmation answer for any case that reaches the prompt.

    # 1. No --ssh-key: the hardened image is key-only (no password), so refuse rather than install a
    #    permanently-unreachable node.
    out = machine.fail("printf 'no\\n' | install-keepnode /dev/vdb 2>&1")
    assert "requires --ssh-key" in out, out

    # 2. Malformed key (prefix ok, but ssh-keygen cannot parse it): refuse, so a typo can't enroll a key
    #    that locks the operator out.
    out = machine.fail("printf 'no\\n' | install-keepnode /dev/vdb --ssh-key 'ssh-ed25519 not-a-real-key' 2>&1")
    assert "failed to parse" in out, out

    # 3. A non-block-device target: usage error rather than wiping the wrong thing.
    out = machine.fail(f"printf 'no\\n' | install-keepnode /dev/does-not-exist --ssh-key '{pubkey}' 2>&1")
    assert "usage:" in out, out

    # 4. A partition, not a whole disk: refuse so a mistyped target can't wipe a single partition.
    out = machine.fail(f"printf 'no\\n' | install-keepnode /dev/vdc1 --ssh-key '{pubkey}' 2>&1")
    assert "usage:" in out, out

    # 5. Unknown option: reject rather than silently ignore an operator typo.
    out = machine.fail(f"printf 'no\\n' | install-keepnode /dev/vdb --bogus --ssh-key '{pubkey}' 2>&1")
    assert "unknown option" in out, out

    # 6. Valid key from a FILE + real disk, but the confirmation is not exactly YES: abort before the
    #    wipe. Doubles as coverage of the --ssh-key <file> read path.
    out = machine.fail("printf 'no\\n' | install-keepnode /dev/vdb --ssh-key ${adminKeyFixture}/id.pub 2>&1")
    assert "Aborted" in out, out

    # 7. Valid inline key + real disk, but the confirmation is not exactly YES: abort before the wipe.
    out = machine.fail(f"printf 'no\\n' | install-keepnode /dev/vdb --ssh-key '{pubkey}' 2>&1")
    assert "Aborted" in out, out

    # The destructive path is gated behind every check above: /dev/vdb must still be a blank whole disk
    # with no partition table at all (a regression that skipped a guard would have wiped + partitioned
    # it), and the partition pre-made on /dev/vdc must be untouched.
    machine.succeed("test -b /dev/vdb")
    machine.fail("sgdisk -p /dev/vdb | grep -qE '^ +[0-9]+ '")
    machine.succeed("test -b /dev/vdc1")
  '';
}
