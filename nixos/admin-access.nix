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
  imports = [ ./mesh-interface.nix ];

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
      default = config.keepNode.mesh.interface;
      defaultText = lib.literalExpression "config.keepNode.mesh.interface";
      description = ''
        The nvpn mesh interface. SSH's port is opened ONLY here, so only rostered, WireGuard-
        authenticated mesh peers can reach sshd , not the LAN, not the underlay. Defaults to the shared
        `keepNode.mesh.interface` so it can't drift from nvpn's device.
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

    lanBringupInterface = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "eth0";
      description = ''
        Only meaningful with `lanBringup = true`. Names the LAN interface the bring-up SSH opening is
        scoped to, so port 22 is NOT opened on a public/WAN NIC. Leave null (the default) for the
        generic installer image, which cannot know the NIC name and so opens all interfaces; the
        `@RFC1918` `AllowUsers` backstop still refuses public/WAN sources at auth time either way.
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
        # sshd honours only an ABSOLUTE AuthorizedKeysFile path; a relative or empty string is silently
        # ignored, so a typo'd authorizedKeysFile satisfies the anti-lockout check above (it is non-null)
        # yet provisions no key at all , the exact silent remote lockout the guard exists to prevent.
        # Catch the path-typo class at build time; the runtime keep-node-admin-key-check unit below then
        # covers the "absolute but absent/empty at boot" class the build cannot see.
        assertion =
          cfg.authorizedKeysFile == null || lib.hasPrefix "/" (lib.strings.trim cfg.authorizedKeysFile);
        message = "keepNode.adminAccess.authorizedKeysFile (${toString cfg.authorizedKeysFile}) must be an ABSOLUTE path (starting with /): sshd silently ignores a relative or empty AuthorizedKeysFile, which would provision no admin key and permanently lock out remote access. Use an absolute path like /etc/keepnode/admin_authorized_keys.";
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
      {
        # An empty/whitespace-only lanBringupInterface passes the `!= null` check below and emits
        # networking.firewall.interfaces."".allowedTCPPorts = [22] (an invalid empty interface name)
        # while suppressing the global all-interface fallback: the firewall apply can fail and leave
        # sshd reachable on 0.0.0.0 with nothing scoping it. Require a usable NIC name when set.
        assertion = cfg.lanBringupInterface == null || lib.strings.trim cfg.lanBringupInterface != "";
        message = "keepNode.adminAccess.lanBringupInterface is set to an empty or whitespace-only string: it must name a LAN interface (e.g. \"eth0\") or be null. An empty name produces an invalid firewall rule and suppresses the global bring-up opening. Set a real interface name (or leave it null).";
      }
      {
        # lanBringupInterface only scopes the bring-up opening; it does nothing unless lanBringup is on.
        # Naming an interface without enabling bring-up opens no LAN port at all, so an operator who set
        # it may wrongly believe scoped bring-up is active. Fail rather than silently open nothing.
        assertion = cfg.lanBringupInterface == null || cfg.lanBringup;
        message = "keepNode.adminAccess.lanBringupInterface is set but keepNode.adminAccess.lanBringup is false: the interface only scopes the bring-up SSH opening, which is off, so no LAN port is opened. Set lanBringup = true to activate scoped bring-up (or leave lanBringupInterface null).";
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

    # Runtime anti-lockout backstop for what the build cannot see: an authorizedKeysFile that is a valid
    # absolute path (so the assertions pass) but is ABSENT or EMPTY at boot , a failed installer
    # enrollment, an un-provisioned runtime file, or a deleted key , leaves keepadmin with zero usable
    # keys and, with password auth off, NO way in over the network. That would otherwise be a silent
    # brick. This oneshot checks the effective key sources at boot and, if none holds a usable key, fails
    # loudly: a console message an operator sees on the physical box, and a `systemctl --failed` entry.
    # Nothing requires this unit, so its failure surfaces the lockout WITHOUT blocking boot or sshd.
    systemd.services.keep-node-admin-key-check = {
      description = "Anti-lockout: fail loudly if keepadmin has no authorized SSH key";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        present=0
        # The inline `authorizedKeys` land in the Nix-managed per-user file; the runtime
        # authorizedKeysFile (when configured) is the installer/operator-provisioned path.
        for f in /etc/ssh/authorized_keys.d/keepadmin ${
          lib.optionalString (cfg.authorizedKeysFile != null) (lib.escapeShellArg cfg.authorizedKeysFile)
        }; do
          # A usable key is any non-blank, non-comment line.
          if [ -f "$f" ] && grep -qE '^[[:space:]]*[^#[:space:]]' "$f" 2>/dev/null; then
            present=1
          fi
        done
        if [ "$present" -eq 0 ]; then
          msg="KEEP NODE ANTI-LOCKOUT: keepadmin has NO authorized SSH key (inline keys empty${
            lib.optionalString (cfg.authorizedKeysFile != null) " and ${cfg.authorizedKeysFile} is absent/empty"
          }). Key-only SSH means remote access is IMPOSSIBLE. Provision an admin public key (keepNode.adminAccess.authorizedKeys${
            lib.optionalString (cfg.authorizedKeysFile != null) " or ${cfg.authorizedKeysFile}"
          }), then: systemctl restart keep-node-admin-key-check.service"
          echo "$msg" > /dev/console 2>/dev/null || true
          echo "$msg" >&2
          exit 1
        fi
        echo "keepadmin has at least one authorized SSH key"
      '';
    };

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
    # SSH's port is opened on the mesh interface always, plus during bring-up on the LAN. When
    # lanBringupInterface names the LAN NIC the bring-up opening is scoped to it, so a public/WAN NIC
    # is never opened; otherwise (the generic installer image, which can't know the NIC name) it falls
    # back to opening all interfaces via the global list below. Either way the @RFC1918 AllowUsers
    # backstop refuses public/WAN sources at auth time.
    networking.firewall.interfaces = lib.mkMerge [
      { ${cfg.meshInterface}.allowedTCPPorts = [ 22 ]; }
      (lib.mkIf (cfg.lanBringup && cfg.lanBringupInterface != null) {
        ${cfg.lanBringupInterface}.allowedTCPPorts = [ 22 ];
      })
    ];

    # Global (all-interface) bring-up opening only when no LAN interface is named. Off by default, so a
    # declarative deploy stays mesh-only; a scoped bring-up (lanBringupInterface set) stays off WAN.
    networking.firewall.allowedTCPPorts = lib.optional (
      cfg.lanBringup && cfg.lanBringupInterface == null
    ) 22;
  };
}
