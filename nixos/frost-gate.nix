# FROST threshold volume gate (Approach B core). STUB.
#
# Design (see SPIKE-vaultwarden-unlock.md / KEEP-NODE.md):
#   1. Vaultwarden's data dir lives on the LUKS volume `volumeDevice`.
#   2. On unlock, the on-box FROST share (held in the secure element, released only after
#      measured boot + user PIN) plus the phone share reconstruct the t-of-n threshold; the
#      reconstructed key unseals the volume.
#   3. vaultwarden.service is ordered After= keep-node-frost-gate.service, so the password
#      manager starts only once the quorum has unsealed its storage.
#   4. Re-lock on idle/reboot. The gate protects startup/unlock (the FDE model), and the
#      node's measured boot + secure element protect the on-box share at rest.
#
# For the M0 VM there is no hardware/LUKS; this unit is a no-op placeholder so the wiring and
# ordering exist before the real unseal logic lands (M1/M2).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.keepNode.frostGate;
in
{
  options.keepNode.frostGate = {
    enable = lib.mkEnableOption "FROST-quorum gate for the Vaultwarden data volume (Approach B)";

    volumeDevice = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Block device of the LUKS volume holding Vaultwarden's data dir.";
    };

    quorum = lib.mkOption {
      default = { };
      description = "FROST t-of-n threshold. MVP: 2-of-3 (node + phone + replica/relay).";
      type = lib.types.submodule {
        options = {
          threshold = lib.mkOption {
            type = lib.types.int;
            default = 2;
          };
          total = lib.mkOption {
            type = lib.types.int;
            default = 3;
          };
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.quorum.threshold <= cfg.quorum.total && cfg.quorum.threshold >= 1;
        message = "keepNode.frostGate.quorum: need 1 <= threshold <= total.";
      }
      {
        assertion = cfg.volumeDevice != null;
        message = "keepNode.frostGate.enable requires keepNode.frostGate.volumeDevice (the LUKS volume to unseal).";
      }
    ];

    systemd.services.keep-node-frost-gate = {
      description = "KeepNode FROST volume gate (stub)";
      wantedBy = [ "multi-user.target" ];
      before = [ "vaultwarden.service" ];
      # Hard dependency, not just ordering: if the unseal gate fails, Vaultwarden must NOT
      # start (its storage is still sealed). `before` alone would let it start anyway.
      requiredBy = [ "vaultwarden.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # STUB: replace with the unseal helper that reconstructs the FROST quorum and
        # `cryptsetup open`s cfg.volumeDevice onto Vaultwarden's data dir.
        ExecStart = "${pkgs.coreutils}/bin/true";
      };
    };
  };
}
