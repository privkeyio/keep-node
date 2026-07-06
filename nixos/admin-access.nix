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

    authorizedKeysFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/etc/keepnode/admin_authorized_keys";
      description = ''
        Absolute path to a MUTABLE runtime authorized_keys file sshd also honours for `keepadmin`, for
        a key provisioned AFTER install. The generic installer ISO embeds a fixed closure (the key
        cannot be baked into config at install time), so it writes the operator's key here instead.
        Complements `authorizedKeys`. The file may be absent/empty at build time, so on its own it does
        NOT satisfy the anti-lockout check; the installer is responsible for populating it and refusing
        to proceed with no key.
      '';
    };

    lanBringup = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Bring-up escape hatch: ALSO expose the key-only SSH on all interfaces (the LAN), not just the
        mesh, and widen the `@10.44/16` source restriction to the private RFC1918 ranges (so LAN
        onboarding works while a public/WAN source is still refused at auth time). A freshly-installed
        generic node is not on a mesh yet, so this is the only way to reach it for onboarding. Still
        key-only (no password), unlike the debug profile. Leave false for a declarative deploy
        (mesh-only); flip back to false once the node has joined the mesh.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # Anti-lockout: password auth is off below, so zero (or only blank) keys = no way in over the
        # network, ever. Fail the build rather than brick a remote box (the one lockout foot-gun the
        # research flags). Empty/whitespace-only entries don't count as a usable key. A runtime
        # authorizedKeysFile also satisfies this: its key is provisioned post-install (by the installer,
        # which refuses to proceed with no key), so it can't be checked at build time.
        assertion =
          (lib.any (k: k != "") (map lib.strings.trim cfg.authorizedKeys)) || cfg.authorizedKeysFile != null;
        message = "keepNode.adminAccess.enable is true but neither keepNode.adminAccess.authorizedKeys (a usable inline key) nor authorizedKeysFile is set: SSH password auth is disabled, so this would permanently lock out remote access. Add an operator public key (or leave adminAccess off).";
      }
      {
        # The mesh-only perimeter is enforced by an interface-scoped firewall rule below; if the firewall
        # is off, that rule does nothing and sshd is reachable from the LAN/underlay. firewall.enable is
        # only mkDefault true, so a host can silently turn it off.
        assertion = config.networking.firewall.enable;
        message = "keepNode.adminAccess.enable is true but networking.firewall.enable is false: the mesh-only SSH perimeter depends on the interface-scoped firewall rule. Enable the firewall (or leave adminAccess off).";
      }
      {
        # admin-access and debug-access define conflicting sshd settings, and debug-access re-exposes SSH
        # on ALL interfaces with password auth + a known password, defeating the mesh-only perimeter.
        assertion = !(config.keepNode.debugAccess.enable or false);
        message = "keepNode.adminAccess.enable and keepNode.debugAccess.enable are both true: they define conflicting sshd settings, and debug-access re-exposes SSH on all interfaces with password auth. Enable only one.";
      }
    ];

    users.users.keepadmin = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      openssh.authorizedKeys.keys = cfg.authorizedKeys;
    };

    # A key-only account has no password to type, so keepadmin gets passwordless sudo , the SSH key is
    # the authentication. Scoped to keepadmin only (not global wheelNeedsPassword) so other wheel
    # accounts don't silently inherit passwordless root. Still auditable (you log in as keepadmin; sudo
    # is logged) and not root-by-default: a compromised session is not root until an explicit `sudo`.
    security.sudo.extraRules = [
      {
        users = [ "keepadmin" ];
        commands = [
          {
            command = "ALL";
            options = [ "NOPASSWD" ];
          }
        ];
      }
    ];

    services.openssh = {
      enable = true;
      # CRITICAL: openFirewall defaults to true, which opens port 22 on ALL interfaces and would defeat
      # the mesh-only perimeter below. Disable it; the interface-scoped rule is the only opening.
      openFirewall = false;
      # A runtime authorized_keys file (provisioned post-install) sshd also honours, in ADDITION to the
      # Nix-managed keys under /etc/ssh/authorized_keys.d/%u. NixOS appends this to the default
      # AuthorizedKeysFile list, so the inline `authorizedKeys` still work.
      authorizedKeysFiles = lib.optional (cfg.authorizedKeysFile != null) cfg.authorizedKeysFile;
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
        # Daemon-level backstop matching vault-replication's rsyncd `hosts allow = 10.44/16`: sshd
        # listens on 0.0.0.0, and the firewall interface rule below is the primary perimeter, but if that
        # rule is absent (firewall off) or meshInterface drifts, this denies any source outside nvpn's
        # mesh subnet (10.44.0.0/16) at auth time. sshd matches the numeric CIDR against the connecting
        # address, so a LAN/underlay source is refused even with no firewall guard. Bring-up widens the
        # restriction to the private (RFC1918) ranges rather than dropping it: a fresh node has no mesh
        # yet and is reached over the LAN, but a public/WAN source is still refused at auth time even
        # though the bring-up firewall opening is global. Mesh (10.44/16) stays reachable within 10/8.
        AllowUsers =
          if cfg.lanBringup then
            [
              "keepadmin@10.0.0.0/8"
              "keepadmin@172.16.0.0/12"
              "keepadmin@192.168.0.0/16"
            ]
          else
            [ "keepadmin@10.44.0.0/16" ];
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
    #
    # COUPLING: meshInterface must match nvpn's actual runtime tun device (same coupling vault-
    # replication carries). If it drifts, this rule opens the wrong interface (or none); in the default
    # mesh-only deploy the AllowUsers=keepadmin@10.44.0.0/16 CIDR backstop above covers a mismatch by
    # denying any non-mesh source at auth time. (Under lanBringup the backstop is intentionally widened
    # to RFC1918, which still denies public/WAN sources but allows the LAN for onboarding.)
    networking.firewall.interfaces.${cfg.meshInterface}.allowedTCPPorts = [ 22 ];

    # Bring-up only: ALSO open SSH globally (the LAN), because a fresh node has no mesh to reach it
    # over yet. Still key-only. Off by default, so a declarative deploy stays mesh-only.
    networking.firewall.allowedTCPPorts = lib.optional cfg.lanBringup 22;
  };
}
