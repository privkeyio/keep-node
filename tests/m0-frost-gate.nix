# M0 frost-gate v1: Vaultwarden's data dir is a TPM-sealed LUKS volume, auto-unlocked at boot.
# Grounded in nixpkgs nixos/tests/systemd-cryptenroll.nix (emptyDiskImages + tpm.enable +
# systemd-cryptenroll --tpm2-device=auto), unlocked by the keep-node-frost-gate service.
# Run: nix build .#checks.x86_64-linux.m0-frost-gate
{ ... }:
{
  name = "keep-node-m0-frost-gate";

  nodes.node =
    { pkgs, ... }:
    {
      imports = [ ../nixos/keep-node.nix ];

      keepNode.frostGate = {
        enable = true;
        volumeDevice = "/dev/vdb";
      };

      # For the test-script assertions (cryptsetup isLuks / enroll listing).
      environment.systemPackages = [ pkgs.cryptsetup ];

      virtualisation = {
        emptyDiskImages = [ 512 ]; # /dev/vdb, the vault volume
        tpm.enable = true; # swtpm
      };
    };

  testScript = ''
    node.start()

    # First boot: blank disk -> the gate self-provisions (LUKS format + TPM2 enroll + mkfs).
    node.wait_for_unit("keep-node-frost-gate.service")
    node.succeed("cryptsetup isLuks /dev/vdb")
    node.succeed("systemd-cryptenroll /dev/vdb | grep -q tpm2")

    # Reboot: the gate TPM2-unlocks the volume, it mounts, then Vaultwarden starts off it.
    node.shutdown()
    node.start()
    node.wait_for_unit("keep-node-frost-gate.service")
    node.succeed("test -e /dev/mapper/keep-vault")
    node.wait_for_unit("vaultwarden.service")

    # The vault data dir IS the decrypted LUKS mapper, and Vaultwarden serves off it.
    node.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")
    node.wait_for_open_port(8222)
    node.succeed("curl -fsS http://localhost:8222/alive")
  '';
}
