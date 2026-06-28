# Customizations layered on top of nixpkgs' installation-cd-minimal to make a one-command,
# offline keepnode installer. The full appliance closure (keepnodeToplevel) is embedded in the
# ISO store via system.extraDependencies, so `install-keepnode` installs with no network and no
# rebuild on the target machine.
{
  pkgs,
  keepnodeToplevel,
  ...
}:
let
  install-keepnode = pkgs.writeShellScriptBin "install-keepnode" ''
    set -euo pipefail
    # Partitioning needs root; the installer logs in as an unprivileged user, so re-exec via sudo.
    if [ "$(id -u)" -ne 0 ]; then exec sudo -- "$0" "$@"; fi

    disk="''${1:-}"
    # Resolve symlinks (by-id/by-path) to the kernel name so the partition-suffix logic below
    # and the wipe act on the canonical whole-disk node.
    if [ -n "$disk" ] && [ -b "$disk" ]; then disk="$(${pkgs.coreutils}/bin/realpath "$disk")"; fi
    if [ -z "$disk" ] || [ ! -b "$disk" ] \
       || [ "$(${pkgs.util-linux}/bin/lsblk -dno TYPE "$disk" 2>/dev/null)" != disk ]; then
      echo "usage: install-keepnode /dev/DISK   (a whole disk, not a partition)"
      echo
      ${pkgs.util-linux}/bin/lsblk -do NAME,SIZE,TYPE,MODEL,SERIAL
      exit 1
    fi

    echo "This will ERASE everything on $disk:"
    ${pkgs.util-linux}/bin/lsblk -o NAME,SIZE,TYPE,MODEL,SERIAL "$disk"
    read -rp "Type YES to wipe it and install keepnode: " confirm
    [ "$confirm" = "YES" ] || { echo "Aborted."; exit 1; }

    # Make re-runs in the same boot safe: release anything left mounted by a prior failed run.
    umount -R /mnt 2>/dev/null || true
    swapoff -a 2>/dev/null || true

    ${pkgs.util-linux}/bin/wipefs -a "$disk"
    ${pkgs.gptfdisk}/bin/sgdisk --zap-all "$disk"
    ${pkgs.gptfdisk}/bin/sgdisk -n1:0:+512M -t1:EF00 -c1:ESP "$disk"
    ${pkgs.gptfdisk}/bin/sgdisk -n2:0:0 -t2:8300 -c2:nixos "$disk"

    case "$disk" in
      *nvme*|*mmcblk*) p1="''${disk}p1"; p2="''${disk}p2" ;;
      *) p1="''${disk}1"; p2="''${disk}2" ;;
    esac

    # Force the kernel to adopt the new table before formatting, then clear any stale
    # filesystem signatures left on the new partitions (avoids a wrong-fs-type mount race).
    ${pkgs.parted}/bin/partprobe "$disk" || true
    ${pkgs.systemd}/bin/udevadm settle
    ${pkgs.util-linux}/bin/wipefs -a "$p1" "$p2" || true

    ${pkgs.dosfstools}/bin/mkfs.fat -F32 -n ESP "$p1"
    ${pkgs.e2fsprogs}/bin/mkfs.ext4 -F -L nixos "$p2"
    ${pkgs.systemd}/bin/udevadm settle

    # Mount the partitions we just created by their device node. The udevadm settle above makes
    # this safe from the re-read race; mounting by label could resolve to another disk that
    # happens to share the "nixos"/"ESP" label.
    mount "$p2" /mnt
    mkdir -p /mnt/boot
    mount "$p1" /mnt/boot

    # --system installs the pre-built, embedded closure: no eval, no network, no rebuild.
    nixos-install --system ${keepnodeToplevel} --no-root-password --no-channel-copy

    echo
    echo "keepnode installed. Remove the USB stick and reboot."
    echo "First login: root / keepnode  (change it immediately)."
  '';
in
{
  environment.systemPackages = [
    install-keepnode
    pkgs.gptfdisk
    pkgs.dosfstools
    pkgs.e2fsprogs
    pkgs.parted
  ];

  # Bake the appliance into the ISO so the install is fully offline.
  system.extraDependencies = [ keepnodeToplevel ];

  users.motd = ''

    keep-node installer
    ===================
    1) See your disks:        lsblk
    2) Install (ERASES disk): install-keepnode /dev/nvme0n1
    Then remove the USB and reboot.

  '';
}
