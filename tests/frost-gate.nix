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

    # Anti-brick: if the TPM token is lost (a PCR change, TPM clear, or an enroll interrupted
    # by power loss all leave our LUKS volume with no usable TPM2 token), the gate must
    # reclaim and re-provision its OWN volume on the next boot rather than getting stuck.
    # Simulate token loss, then reboot and assert the node recovers to a working state.
    tokid = node.succeed("cryptsetup luksDump /dev/vdb | sed -n 's/^\\s*\\([0-9]\\+\\): systemd-tpm2/\\1/p' | head -n1").strip()
    node.succeed(f"cryptsetup token remove --token-id {tokid} /dev/vdb")
    node.succeed("systemd-cryptenroll /dev/vdb | grep -vq tpm2")  # token really gone

    node.shutdown()
    node.start()
    node.wait_for_unit("keep-node-frost-gate.service")
    node.succeed("test -e /dev/mapper/keep-vault")  # reclaimed + re-provisioned, not bricked
    node.wait_for_unit("vaultwarden.service")
    node.wait_for_open_port(8222)
    node.succeed("curl -fsS http://localhost:8222/alive")
    # The canary is gone here, by design: an unrecoverable volume is re-provisioned, not unlocked.
    node.fail("test -e /var/lib/vaultwarden/canary")
  '';
}
