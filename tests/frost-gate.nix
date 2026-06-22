# frost-gate v1: Vaultwarden's data dir is a TPM-sealed LUKS volume, auto-unlocked at boot.
# Grounded in nixpkgs nixos/tests/systemd-cryptenroll.nix (emptyDiskImages + tpm.enable +
# systemd-cryptenroll --tpm2-device=auto), unlocked by the keep-node-frost-gate service.
# Run: nix build .#checks.x86_64-linux.frost-gate
{ ... }:
{
  name = "keep-node-frost-gate-test";

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

    # Drop a canary into the decrypted volume so the reboot can prove the SAME data came
    # back (i.e. the volume was unlocked, not silently reformatted).
    node.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")
    node.succeed("echo keep-node-canary > /var/lib/vaultwarden/canary")

    # Reboot: the gate TPM2-unlocks the volume, it mounts, then Vaultwarden starts off it.
    node.shutdown()
    node.start()
    node.wait_for_unit("keep-node-frost-gate.service")
    node.succeed("test -e /dev/mapper/keep-vault")
    node.wait_for_unit("vaultwarden.service")

    # The vault data dir IS the decrypted LUKS mapper, and Vaultwarden serves off it.
    node.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")

    # The canary survived: the gate unlocked the existing volume rather than reformatting.
    node.succeed("grep -qx keep-node-canary /var/lib/vaultwarden/canary")
    node.wait_for_open_port(8222)
    node.succeed("curl -fsS http://localhost:8222/alive")

    # Losing the TPM2 token on a PROVISIONED volume must FAIL CLOSED, never auto-wipe. Removing
    # the systemd-tpm2 token leaves the volume with no usable keyslot, so its data (the canary
    # above) is unrecoverable on-box. Per the fail-closed design (header: recover from a replica,
    # never destroy local data) the gate must refuse to reformat and leave the node down, NOT come
    # back up on a freshly wiped empty volume. The completion marker (LUKS2 subsystem) is what lets
    # the gate tell this apart from an interrupted first provision (which has no marker and IS
    # reclaimed). Note: a real PCR change / TPM clear leaves the token present and the unseal simply
    # fails closed at attach; deleting the token here reproduces the same "no usable keyslot" end
    # state via a path the test can drive deterministically.
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-provisioned")  # marker is set
    tokid = node.succeed("cryptsetup luksDump /dev/vdb | sed -n 's/^\\s*\\([0-9]\\+\\): systemd-tpm2/\\1/p' | head -n1").strip()
    node.succeed(f"cryptsetup token remove --token-id {tokid} /dev/vdb")
    node.succeed("! systemd-cryptenroll /dev/vdb | grep -q tpm2")  # tpm2 token really gone

    node.shutdown()
    node.start()
    # The gate refuses to destroy the provisioned-but-unrecoverable volume: its unit fails closed,
    # and for THIS reason (the refuse-to-reformat path), not some unrelated abort.
    node.wait_until_succeeds("systemctl is-failed --quiet keep-node-frost-gate.service")
    node.succeed("journalctl -u keep-node-frost-gate.service | grep -q 'refusing to reformat'")
    node.fail("test -e /dev/mapper/keep-vault")  # not unlocked
    node.fail("systemctl is-active --quiet vaultwarden.service")  # vault stays down (hard dep)
    # The volume was NOT reformatted: our LUKS container, label, and completion marker all survive.
    node.succeed("cryptsetup isLuks /dev/vdb")
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-frost-gate")
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-provisioned")
  '';
}
