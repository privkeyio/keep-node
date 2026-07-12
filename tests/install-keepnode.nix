# tests/install-keepnode.nix -- run install-keepnode end-to-end on a blank disk and prove the install
# MECHANICS succeed: partitioning, nixos-install of the REAL bring-up appliance closure, systemd-boot
# written to the ESP, and the operator key enrolled into the runtime authorizedKeysFile.
#
# installer-guards.nix covers only the abort paths (with a stubbed closure); this runs a SUCCESSFUL
# install of the real keepnodeBringupSystem. It asserts against the freshly-installed /mnt rather than
# booting the installed disk: the actual boot is firmware/TPM-specific (validated on real hardware),
# while the environment-independent install mechanics -- which were never success-tested before -- are
# proven here deterministically in a single VM (no second-boot/OVMF handoff to flake on).
#
# The installed closure (keepnodeToplevel arg) is the real bring-up appliance with ONE test-only
# accommodation, canTouchEfiVariables=false, so nixos-install's `bootctl install` needs no efivarfs in
# the BIOS installer VM (the appliance ships it true for the real UEFI box). Nothing else differs, so
# the install path and the installed closure are otherwise exactly what ships.
#
# Run: nix build .#checks.x86_64-linux.install-keepnode
{
  adminKeyFixture,
  keepnodeToplevel,
  ...
}:
{
  name = "keep-node-install-keepnode";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ../nixos/installer.nix ];
      _module.args.keepnodeToplevel = keepnodeToplevel;
      # install-keepnode is written for the installation-CD environment, which provides `nixos-install`
      # on PATH (installer.nix intentionally leaves it unpinned) and an existing /mnt mount point. This
      # bare test node has neither, so provide the same two things the CD would (mirroring reality
      # rather than special-casing the installer).
      environment.systemPackages = [ pkgs.nixos-install-tools ];
      systemd.tmpfiles.rules = [ "d /mnt 0755 root root - -" ];
      # A blank second disk (/dev/vdb) is the install TARGET. The installer itself boots off the
      # default test root (host store), so no rootDevice/bootloader wiring is needed to run the
      # install -- the target only has to be a blank whole disk install-keepnode can partition.
      virtualisation.emptyDiskImages = [ (12 * 1024) ]; # must hold the copied appliance closure
      virtualisation.memorySize = 4096;
      virtualisation.cores = 4;
    };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("udevadm settle")

    # Non-interactive YES; install onto the blank target /dev/vdb, reading the operator pubkey from a
    # FILE (exercises install-keepnode's --ssh-key <file> read path).
    machine.succeed(
        "printf 'YES\n' | install-keepnode /dev/vdb --ssh-key ${adminKeyFixture}/id.pub >&2"
    )

    # Partitioning: the GPT ESP + nixos partitions exist with the labels install-keepnode assigns.
    machine.succeed("blkid -L ESP")
    machine.succeed("blkid -L nixos")

    # nixos-install installed EXACTLY the closure install-keepnode was handed (the real bring-up
    # appliance): the target's system profile resolves to that store path.
    installed = machine.succeed("readlink -f /mnt/nix/var/nix/profiles/system").strip()
    assert installed == "${keepnodeToplevel}", (
        f"installed system profile {installed!r} != the shipped bring-up closure ${keepnodeToplevel}"
    )

    # systemd-boot landed on the ESP with generated boot entries -> the target is bootable.
    machine.succeed("test -e /mnt/boot/EFI/systemd/systemd-bootx64.efi")
    machine.succeed("test -n \"$(ls -A /mnt/boot/loader/entries 2>/dev/null)\"")

    # The operator key was enrolled into the runtime authorizedKeysFile that keepNode.adminAccess
    # reads at boot: the exact pubkey bytes, world-readable (0644) as the module expects.
    machine.succeed(
        "grep -qF \"$(cat ${adminKeyFixture}/id.pub)\" /mnt/etc/keepnode/admin_authorized_keys"
    )
    machine.succeed(
        "test \"$(stat -c %a /mnt/etc/keepnode/admin_authorized_keys)\" = 644"
    )
  '';
}
