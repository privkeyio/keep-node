# Hardened SSH admin access, reachable ONLY over the encrypted nvpn mesh. The perimeter is the mesh,
# not the daemon: sshd's port is opened only on the mesh interface, so a hostile LAN (and the WireGuard
# underlay) can never send a packet to it -- only cryptographically-authenticated mesh peers. Key-only,
# a dedicated `keepadmin` (wheel + passwordless sudo, since a key-only account has no password to
# type), and root is not a network-reachable username at all. This retires the debug profile's known
# password + password-SSH for a DECLARATIVE deploy: the operator bakes their pubkey + the mesh roster
# into the config, deploys, and reaches the node over the mesh. Design is research-backed (Start9 gates
# SSH behind Tor/web-console, Umbrel steers remote access to a WireGuard mesh; OpenSSH modern defaults;
# fail2ban is pointless for key-only auth so it is omitted in favour of sshd's PerSourcePenalties).
{ config, lib, ... }:
let
  cfg = config.keepNode.adminAccess;
in
{
  options.keepNode.adminAccess = {
    enable = lib.mkEnableOption "hardened key-only SSH admin access over the mesh (the keepadmin account)";

    authorizedKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "ssh-ed25519 AAAA... you@host" ];
      description = ''
        Operator SSH public keys authorized for the `keepadmin` account. Public keys are public, so
        listing them inline in the config (and git) is correct , no secret manager needed. Password
        auth is disabled, so shipping zero keys is a permanent remote lockout; an assertion refuses it.
      '';
    };

    meshInterface = lib.mkOption {
      type = lib.types.str;
      default = "utun100";
      description = ''
        The nvpn mesh interface. SSH's port is opened ONLY here, so only rostered, WireGuard-
        authenticated mesh peers can reach sshd , not the LAN, not the underlay. Matches nvpn's device.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # Anti-lockout: password auth is off below, so zero keys = no way in over the network, ever.
        # Fail the build rather than brick a remote box (the one lockout foot-gun the research flags).
        assertion = cfg.authorizedKeys != [ ];
        message = "keepNode.adminAccess.enable is true but keepNode.adminAccess.authorizedKeys is empty: SSH password auth is disabled, so this would permanently lock out remote access. Add at least one operator public key (or leave adminAccess off).";
      }
    ];

    users.users.keepadmin = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      openssh.authorizedKeys.keys = cfg.authorizedKeys;
    };

    # A key-only account has no password to type, so wheel gets passwordless sudo , the SSH key is the
    # authentication. Still auditable (you log in as keepadmin; sudo is logged) and not root-by-default:
    # a compromised session is not root until an explicit `sudo`.
    security.sudo.wheelNeedsPassword = false;

    services.openssh = {
      enable = true;
      # CRITICAL: openFirewall defaults to true, which opens port 22 on ALL interfaces and would defeat
      # the mesh-only perimeter below. Disable it; the interface-scoped rule is the only opening.
      openFirewall = false;
      # ed25519 host key only (the modern default; no RSA host key to attack or keep current).
      hostKeys = [
        {
          type = "ed25519";
          path = "/etc/ssh/ssh_host_ed25519_key";
        }
      ];
      settings = {
        PasswordAuthentication = false;
        # Also kill the PAM keyboard-interactive password path; disabling only PasswordAuthentication
        # can leave a keyboard-interactive password prompt alive.
        KbdInteractiveAuthentication = false;
        # Strongest: root is not a network-reachable username at all (even a leaked root key can't log
        # in over the network). Admin is keepadmin + sudo.
        PermitRootLogin = "no";
        AllowUsers = [ "keepadmin" ];
        MaxAuthTries = 3;
        X11Forwarding = false;
        AllowTcpForwarding = false;
        AllowAgentForwarding = false;
        # Deliberately DO NOT set Ciphers/KexAlgorithms/MACs/HostKeyAlgorithms: pinning them freezes the
        # crypto policy at authoring time, keeps older/weaker algorithms alive, and breaks the OpenSSH
        # post-quantum-KEX upgrade path. The modern OpenSSH defaults are the curated strong set.
      };
    };

    # The perimeter is the mesh: open SSH ONLY on the mesh interface, so the hostile LAN and the
    # WireGuard underlay never reach sshd. Same pattern as the vault-replication rsync receiver. No
    # entry in the global allowedTCPPorts. (No fail2ban: it does nothing for key-only auth; sshd's
    # built-in PerSourcePenalties covers misbehaving sources.)
    networking.firewall.interfaces.${cfg.meshInterface}.allowedTCPPorts = [ 22 ];
  };
}
