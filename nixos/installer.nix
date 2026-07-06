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

    disk=""
    sshkey=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --ssh-key) sshkey="''${2:-}"; shift 2 2>/dev/null || shift ;;
        --ssh-key=*) sshkey="''${1#--ssh-key=}"; shift ;;
        -*) echo "unknown option: $1" >&2; exit 1 ;;
        *) disk="$1"; shift ;;
      esac
    done
    # Resolve symlinks (by-id/by-path) to the kernel name so the partition-suffix logic below
    # and the wipe act on the canonical whole-disk node.
    if [ -n "$disk" ] && [ -b "$disk" ]; then disk="$(${pkgs.coreutils}/bin/realpath "$disk")"; fi
    if [ -z "$disk" ] || [ ! -b "$disk" ] \
       || [ "$(${pkgs.util-linux}/bin/lsblk -dno TYPE "$disk" 2>/dev/null)" != disk ]; then
      echo "usage: install-keepnode /dev/DISK --ssh-key <pubkey|file>   (a whole disk, not a partition)"
      echo
      ${pkgs.util-linux}/bin/lsblk -do NAME,SIZE,TYPE,MODEL,SERIAL
      exit 1
    fi

    # The hardened image has NO known password: the operator's SSH public key is enrolled so the node
    # is reachable (key-only) after first boot. Require it rather than install an unreachable box.
    if [ -n "$sshkey" ] && [ -f "$sshkey" ]; then sshkey="$(${pkgs.coreutils}/bin/cat "$sshkey")"; fi
    # The prefix check rejects a private key or obvious junk; ssh-keygen then actually parses the key
    # body, so a typo like "ssh-ed25519 garbage" can't enroll a permanently-unreachable node.
    case "$sshkey" in
      "ssh-ed25519 "* | "ssh-rsa "* | "ecdsa-"* | "sk-ssh-"* | "sk-ecdsa-"*) : ;;
      *)
        echo "install-keepnode requires --ssh-key <pubkey|file> (an OpenSSH public key)." >&2
        echo "The hardened image has no password; your key is how you reach the node (key-only SSH)." >&2
        exit 1
        ;;
    esac
    if ! printf '%s\n' "$sshkey" | ${pkgs.openssh}/bin/ssh-keygen -lf /dev/stdin >/dev/null 2>&1; then
      echo "install-keepnode: --ssh-key is not a valid OpenSSH public key (failed to parse)." >&2
      exit 1
    fi

    echo "This will ERASE everything on $disk:"
    ${pkgs.util-linux}/bin/lsblk -o NAME,SIZE,TYPE,MODEL,SERIAL "$disk"
    read -rp "Type YES to wipe it and install keepnode: " confirm
    [ "$confirm" = "YES" ] || { echo "Aborted."; exit 1; }

    # Make re-runs in the same boot safe: release anything left mounted by a prior failed run.
    ${pkgs.util-linux}/bin/umount -R /mnt 2>/dev/null || true
    ${pkgs.util-linux}/bin/swapoff -a 2>/dev/null || true

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
    ${pkgs.util-linux}/bin/mount "$p2" /mnt
    ${pkgs.coreutils}/bin/mkdir -p /mnt/boot
    ${pkgs.util-linux}/bin/mount "$p1" /mnt/boot

    # --system installs the pre-built, embedded closure: no eval, no network, no rebuild.
    # nixos-install is intentionally unpinned: it comes from the installation-cd environment's
    # system PATH, not a pkgs attr.
    nixos-install --system ${keepnodeToplevel} --no-root-password --no-channel-copy

    # Enroll the operator key into the runtime authorized_keys the hardened profile reads
    # (keepNode.adminAccess.authorizedKeysFile). The closure is fixed at ISO-build time, so the
    # per-deployment key is provisioned here rather than baked into config.
    ${pkgs.coreutils}/bin/install -d -m 0755 /mnt/etc/keepnode
    printf '%s\n' "$sshkey" > /mnt/etc/keepnode/admin_authorized_keys
    ${pkgs.coreutils}/bin/chmod 0644 /mnt/etc/keepnode/admin_authorized_keys

    echo
    echo "keepnode installed (hardened, no known password). Remove the USB stick and reboot."
    echo "Reach it over key-only SSH from your machine on the LAN:  ssh keepadmin@<node-ip>"
    echo "Then onboard it onto the mesh and redeploy with keepNode.adminAccess.lanBringup = false."
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
    2) Install (ERASES disk): install-keepnode /dev/nvme0n1 --ssh-key ~/.ssh/id_ed25519.pub
    Then remove the USB and reboot; reach the node over key-only SSH (ssh keepadmin@<node-ip>).

  '';
}
