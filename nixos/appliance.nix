# Hardware/host layer for the keepnode appliance (what the installer writes to disk).
#
# Disk-agnostic on purpose: filesystems are matched by label (the installer creates an ESP
# labelled ESP and a root labelled nixos), so the same image installs to /dev/sda, /dev/nvme0n1,
# etc. without rebuilding. frost-gate is off, so Vaultwarden's state is on the plain root disk.
{ ... }:
{
  networking.hostName = "keepnode";

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # No hardware-configuration.nix on a generic image; cover the common UEFI boot paths so the
  # root disk and USB are visible in the initrd on most x86_64 machines.
  boot.initrd.availableKernelModules = [
    "nvme"
    "ahci"
    "sd_mod"
    "xhci_pci"
    "ehci_pci"
    "usb_storage"
    "usbhid"
  ];

  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
  };
  fileSystems."/boot" = {
    device = "/dev/disk/by-label/ESP";
    fsType = "vfat";
  };
}
