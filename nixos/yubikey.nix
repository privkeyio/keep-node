# YubiKey / FIDO2 hardware-backed admin authentication, layered on top of keepNode.adminAccess.
#
# adminAccess already gives key-only SSH over the mesh, but the operator's private key is a FILE on a
# laptop: steal the laptop (or land malware on it) and you inherit full node admin, silently and
# replayably. A FIDO2 key (`ed25519-sk` / `ecdsa-sk`) moves the private key into the token's secure
# element, where it cannot be copied, and `verify-required` puts a PIN + a physical touch on EVERY
# authentication. Laptop theft alone stops being enough, and remote malware cannot log in without the
# operator physically present.
#
# This is NODE ACCESS ONLY. It does not touch, replace, or weaken the FROST threshold model: vault
# recovery is still the device quorum, and losing every YubiKey costs SSH access (physical console is
# the permanent break-glass), never the vault.
#
# Backward compatible by construction: the module is off by default, and with `requireHardwareKey`
# false (the default) sshd's accepted-algorithm set is untouched, so existing software keys keep
# working. Nothing here introduces a password path, a listening port, or a daemon.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.keepNode.security.yubikey;
  admin = config.keepNode.adminAccess;
  keys = import ./lib/authorized-keys.nix { inherit lib; };
  keyCheck = import ./lib/key-check.nix { inherit lib; };

  # The wire algorithm names each FIDO2 key type presents at authentication. Certificate variants are
  # included so an sk-only PubkeyAcceptedAlgorithms set does not silently refuse a signed sk key.
  algorithmsFor = {
    "ed25519-sk" = [
      "sk-ssh-ed25519@openssh.com"
      "sk-ssh-ed25519-cert-v01@openssh.com"
    ];
    "ecdsa-sk" = [
      "sk-ecdsa-sha2-nistp256@openssh.com"
      "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
    ];
  };
  acceptedAlgorithms = lib.concatMap (t: algorithmsFor.${t}) cfg.keyTypes;

  # An authorized_keys line may carry an options field before the algorithm and may be tab-separated,
  # and this classifier is applied to `admin.authorizedKeys` too, where both are legal and unguarded.
  # See nixos/lib/authorized-keys.nix for why field-wise parsing (not "everything up to the first
  # space") is what keeps a misread line from becoming a false lockout or a false all-clear.
  inherit (keys) algorithmOf isHardwareKey;

  # Keys sshd would actually ACCEPT under an sk-only policy: hardware-backed AND of an allowed type. A
  # hardware key whose algorithm is excluded by `keyTypes` is refused at auth time, so it does not count
  # towards the anti-lockout guard.
  hardwareKeys = keys.trimKeys cfg.authorizedKeys;
  inlineKeys = hardwareKeys ++ keys.trimKeys admin.authorizedKeys;
  usableHardwareKeys = lib.filter (
    k: isHardwareKey k && lib.elem (algorithmOf k) acceptedAlgorithms
  ) inlineKeys;

  badHardwareKeys = lib.filter (k: !(isHardwareKey k)) hardwareKeys;

  # Runtime matchers for the SAME allow-list `usableHardwareKeys` applies at eval. Both are derived from
  # acceptedAlgorithms rather than matching `sk-` generically: a hardware key of a type excluded by
  # keyTypes is refused by sshd at authentication, so treating it as usable (in the boot check) or
  # enrolling it (in the helper) would manufacture the exact silent lockout those paths exist to prevent.
  # Certificate algorithms are included because a cert line's algorithm field is the cert algorithm.
  #
  # The boot check matches FIELD-WISE (field 1, or field 2 behind an options prefix such as
  # `verify-required sk-ssh-ed25519@...`), never as a substring of the line: an algorithm name is
  # perfectly legal inside a software key's free-form COMMENT, and matching it there would report a
  # hardware key present on a node whose only key sshd refuses , failing in the unsafe direction, which
  # is the one thing this backstop may never do. awk's default field splitting also handles tabs.
  acceptedKeyProgram = ''
    BEGIN { split("${lib.concatStringsSep " " acceptedAlgorithms}", want, " "); for (i in want) accepted[want[i]] = 1 }
    /^[[:space:]]*#/ { next }
    (accepted[$1] || accepted[$2]) { found = 1; exit }
    END { exit found ? 0 : 1 }
  '';
  enrollCasePattern = lib.concatStringsSep " | " (map (a: ''"${a} "*'') acceptedAlgorithms);

  # verify-required as a per-key authorized_keys option (not only the global PubkeyAuthOptions) so PIN +
  # touch is enforced on the hardware keys even in a MIXED deployment, where software keys are still
  # accepted and a global verify-required would lock them out.
  keyLine = k: if cfg.requireVerification then keys.withOption "verify-required" k else k;

  enroll = pkgs.writeShellScriptBin "keepnode-enroll-yubikey" ''
    set -euo pipefail
    # The runtime keys file is root-owned; the operator logs in as keepadmin.
    if [ "$(id -u)" -ne 0 ]; then exec sudo -- "$0" "$@"; fi

    target=${lib.escapeShellArg (toString admin.authorizedKeysFile)}
    key="''${1:-}"
    if [ -z "$key" ]; then
      echo "usage: keepnode-enroll-yubikey <sk-pubkey|file>" >&2
      echo "Generate one on your LAPTOP (the private key never leaves the token):" >&2
      echo "  ssh-keygen -t ${lib.head cfg.keyTypes} -O resident -O verify-required -C yubikey-backup" >&2
      exit 1
    fi
    if [ -f "$key" ]; then key="$(${pkgs.coreutils}/bin/cat "$key")"; fi

    # Exactly ONE key per invocation. Every check below is line-agnostic while the WRITE is not: the
    # `case` glob spans newlines, ssh-keygen -lf exits 0 if ANY line parses, and the verify-required
    # prefix is applied to the payload as a whole. So a two-line paste whose first line is a genuine
    # FIDO2 key would carry a second, un-prefixed SOFTWARE key straight into the keys file , voiding
    # the one guarantee this helper makes. Refuse the shape outright rather than validate per line.
    if [ "$(printf '%s' "$key" | ${pkgs.coreutils}/bin/wc -l)" -ne 0 ]; then
      echo "keepnode-enroll-yubikey: input holds more than one line; enroll exactly one public key per invocation." >&2
      exit 1
    fi

    # Hardware-backed types the CONFIGURED keyTypes allow, nothing else: a software key here would hand
    # back the exact laptop-theft exposure the module removes, and an sk- key of an excluded type would
    # be enrolled only for sshd to refuse it at authentication.
    case "$key" in
      ${enrollCasePattern}) : ;;
      *)
        echo "keepnode-enroll-yubikey: not an accepted FIDO2 public key (keepNode.security.yubikey.keyTypes allows ${lib.concatStringsSep ", " acceptedAlgorithms})." >&2
        echo "Use keepNode.adminAccess.authorizedKeys for software keys." >&2
        exit 1
        ;;
    esac
    # The prefix check above rejects obvious junk; ssh-keygen parses the key BODY, so a truncated or
    # corrupted paste cannot be enrolled as an unusable "key".
    if ! printf '%s\n' "$key" | ${pkgs.openssh}/bin/ssh-keygen -lf /dev/stdin >/dev/null 2>&1; then
      echo "keepnode-enroll-yubikey: public key failed to parse." >&2
      exit 1
    fi

    # Create only what is missing, and never write THROUGH a symlink. This runs as root: on a keys path
    # placed under a directory some other service can write, blindly chmod'ing and appending to whatever
    # sits at $target would turn an enrollment into an arbitrary root-owned write. Not reachable with the
    # shipped root-owned /etc/keepnode, which is exactly why it should stay unreachable by construction.
    dir="$(${pkgs.coreutils}/bin/dirname "$target")"
    [ -d "$dir" ] || ${pkgs.coreutils}/bin/install -d -m 0755 "$dir"
    if [ -L "$target" ]; then
      echo "keepnode-enroll-yubikey: $target is a symlink; refusing to enroll through it." >&2
      exit 1
    fi
    if [ ! -e "$target" ]; then
      ${pkgs.coreutils}/bin/install -m 0644 /dev/null "$target"
    elif [ ! -f "$target" ]; then
      echo "keepnode-enroll-yubikey: $target is not a regular file." >&2
      exit 1
    fi
    # Repair the mode every run, not just on create: sshd's StrictModes ignores a group- or
    # world-writable keys file outright, while the boot check reads content only and would report the
    # node healthy. Left unrepaired that pair is a silent lockout.
    ${pkgs.coreutils}/bin/chmod 0644 "$target"

    # De-duplicate on algorithm + body, ignoring the trailing comment, so re-running with a renamed
    # comment does not append a second copy of the same credential.
    body="$(printf '%s\n' "$key" | ${pkgs.gawk}/bin/awk '{print $1" "$2}')"
    if ${pkgs.gnugrep}/bin/grep -qF "$body" "$target"; then
      echo "already enrolled: $body"
    else
      printf '%s\n' ${lib.escapeShellArg (lib.optionalString cfg.requireVerification "verify-required ")}"$key" >> "$target"
      echo "enrolled into $target"
    fi

    systemctl restart keep-node-admin-key-check.service 2>/dev/null || true
    systemctl restart keep-node-hardware-key-check.service 2>/dev/null || true
  '';
in
{
  options.keepNode.security.yubikey = {
    enable = lib.mkEnableOption "YubiKey / FIDO2 hardware-backed SSH authentication for the keepadmin account";

    authorizedKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "sk-ssh-ed25519@openssh.com AAAA... yubikey-primary" ];
      description = ''
        FIDO2 SSH public keys (`ed25519-sk` / `ecdsa-sk`) authorized for `keepadmin`, merged with
        `keepNode.adminAccess.authorizedKeys`. Every entry must be an `sk-` type , a software key here
        is refused at build time, so the hardware namespace cannot silently hold a file-based key.
        Enroll TWO tokens (primary + off-site backup): one hardware key is a single point of failure
        for node access.

        Only the ALGORITHM is checked at build time; the key body cannot be. A well-formed line with a
        corrupt or truncated body (`sk-ssh-ed25519@openssh.com garbage`) passes every assertion, counts
        towards the anti-lockout guard, and is then silently ignored by sshd. Paste the `.pub` file
        whole, and confirm an actual login before you rely on a token.
      '';
    };

    keyTypes = lib.mkOption {
      type = lib.types.nonEmptyListOf (
        lib.types.enum [
          "ed25519-sk"
          "ecdsa-sk"
        ]
      );
      default = [
        "ed25519-sk"
        "ecdsa-sk"
      ];
      description = ''
        Declarative allow-list of FIDO2 credential types accepted for admin SSH. Under
        `requireHardwareKey` this becomes sshd's `PubkeyAcceptedAlgorithms` (plus the matching
        certificate algorithms), so narrowing it to `[ "ed25519-sk" ]` genuinely refuses an ecdsa-sk
        credential at authentication time rather than merely omitting it from a file.
      '';
    };

    requireHardwareKey = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Refuse every non-hardware-backed SSH key: sshd's `PubkeyAcceptedAlgorithms` is narrowed to the
        `sk-` algorithms implied by `keyTypes`, so an enrolled software key is rejected by the daemon,
        not merely absent. Off by default so existing software-key deployments (and initial bring-up,
        where the operator may not have a token yet) are unaffected. Password auth stays disabled in
        both cases , this never adds an authentication path, it only removes one.

        Anti-lockout: turning this on with no usable hardware key is a permanent remote lockout, so it
        is refused at build time unless `keepNode.adminAccess.authorizedKeysFile` is configured (whose
        contents cannot be known at eval); the `keep-node-hardware-key-check` unit then covers that
        case loudly at boot.
      '';
    };

    enableEnrollmentHelper = lib.mkOption {
      type = lib.types.bool;
      default = admin.authorizedKeysFile != null;
      defaultText = lib.literalExpression "config.keepNode.adminAccess.authorizedKeysFile != null";
      description = ''
        Install `keepnode-enroll-yubikey <sk-pubkey|file>`, which validates a FIDO2 public key, appends
        it (de-duplicated) to `keepNode.adminAccess.authorizedKeysFile`, and re-runs the anti-lockout
        checks , the post-install path for adding a token, or a second one, to a node whose closure was
        fixed at build time. Defaults on exactly when that runtime file exists to write to. A node
        deployed declaratively lists its keys in `authorizedKeys` instead and needs no helper.
      '';
    };

    requireVerification = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Require user verification (PIN) in addition to the touch on every authentication, matching a
        credential created with `ssh-keygen -O verify-required`. Applied as a per-key `verify-required`
        option on `authorizedKeys`, so it binds the hardware keys without locking out software keys in a
        mixed deployment; under `requireHardwareKey` it is ALSO set globally (`PubkeyAuthOptions`), which
        additionally covers keys provisioned into the runtime `authorizedKeysFile`. Turning this off
        leaves touch-only credentials, which a laptop-resident attacker can drive whenever the token is
        plugged in.

        LOCKOUT CAVEAT: whether a credential was created with `-O verify-required` is a property of the
        credential ON THE TOKEN, invisible to both the build-time assertion and the
        `keep-node-hardware-key-check` unit , they can only see algorithms in a file. A token enrolled
        WITHOUT that flag therefore satisfies both anti-lockout guards and is still refused by sshd at
        authentication, so both report healthy on a node you cannot reach. Generate credentials with
        `-O verify-required` (as the docs show) and confirm a real login from your laptop before
        flipping `requireHardwareKey` on or discarding your software key.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # The module only shapes adminAccess's sshd and keepadmin's keys; with adminAccess off there is
        # no keepadmin account and no sshd config to harden, so the options would silently do nothing.
        assertion = admin.enable;
        message = "keepNode.security.yubikey.enable is true but keepNode.adminAccess.enable is false: the YubiKey module hardens the keepadmin SSH account that adminAccess defines, so on its own it configures nothing. Enable keepNode.adminAccess (or leave the yubikey module off).";
      }
      {
        # A software key listed under the hardware namespace would be presented to the operator as
        # YubiKey-protected while actually being a copyable file , the precise misconception this module
        # exists to remove. Refuse it rather than quietly enroll it.
        assertion = badHardwareKeys == [ ];
        message = "keepNode.security.yubikey.authorizedKeys contains a non-FIDO2 key (${lib.concatStringsSep ", " (map algorithmOf badHardwareKeys)}): only hardware-backed sk- types (sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com) belong here, otherwise a copyable software key would masquerade as YubiKey-protected. Put software keys in keepNode.adminAccess.authorizedKeys.";
      }
      {
        # Anti-lockout, mirroring adminAccess's guard: with sk-only algorithms enforced, a config whose
        # only keys are software keys (or hardware keys of a type excluded by keyTypes) has NO key sshd
        # will accept, and password auth is off. That is a permanent remote lockout; fail the build. The
        # runtime authorizedKeysFile escape satisfies it because its contents are provisioned after the
        # build (the installer / keepnode-enroll-yubikey), so eval cannot see them.
        assertion =
          !cfg.requireHardwareKey || usableHardwareKeys != [ ] || admin.authorizedKeysFile != null;
        message = "keepNode.security.yubikey.requireHardwareKey is true but no usable hardware key is configured: sshd would accept only ${lib.concatStringsSep ", " acceptedAlgorithms}, no inline key matches, password auth is disabled, and no keepNode.adminAccess.authorizedKeysFile is set , a permanent remote lockout. Add an sk- key of an allowed type to keepNode.security.yubikey.authorizedKeys (or set authorizedKeysFile and enroll one with keepnode-enroll-yubikey).";
      }
      {
        # The helper writes into adminAccess's runtime keys file; with no such file configured there is
        # nowhere to enroll to, and the command would fail at the point the operator needs it most.
        assertion = !cfg.enableEnrollmentHelper || admin.authorizedKeysFile != null;
        message = "keepNode.security.yubikey.enableEnrollmentHelper is true but keepNode.adminAccess.authorizedKeysFile is null: keepnode-enroll-yubikey writes the new key into that runtime file, so there is nowhere to enroll. Set keepNode.adminAccess.authorizedKeysFile (or disable the helper and enroll declaratively via keepNode.security.yubikey.authorizedKeys).";
      }
    ];

    # Feed the hardware keys through adminAccess rather than straight into users.users: that is the one
    # place keepadmin's key set is assembled, so these keys are also seen by adminAccess's own
    # anti-lockout assertion and its boot-time check. A YubiKey-only deployment (no software key listed
    # at all) therefore builds, instead of tripping a guard that cannot see the hardware keys.
    keepNode.adminAccess.authorizedKeys = map keyLine hardwareKeys;

    services.openssh.settings = lib.mkIf cfg.requireHardwareKey {
      # sshd-level enforcement: a software key is refused during authentication even if it is present in
      # an authorized_keys file. Comma-separated, as sshd_config expects.
      PubkeyAcceptedAlgorithms = lib.concatStringsSep "," acceptedAlgorithms;
      # Global backstop for keys the Nix-managed per-key `verify-required` option cannot reach (the
      # runtime authorizedKeysFile). Safe here precisely because only sk- keys are accepted at all.
      PubkeyAuthOptions = lib.mkIf cfg.requireVerification "verify-required";
    };

    # ssh-keygen needs FIDO support (nixpkgs builds openssh with withFIDO) and libfido2's tooling to talk
    # to a token, so an operator can generate or inspect a credential from the node itself if needed.
    environment.systemPackages = [ pkgs.libfido2 ] ++ lib.optional cfg.enableEnrollmentHelper enroll;

    # Runtime anti-lockout backstop for what the build cannot see: with sk-only algorithms enforced and
    # the key material living in a runtime file, an un-enrolled, failed, or deleted credential leaves
    # keepadmin with nothing sshd will accept , a silent brick. This oneshot inspects the effective key
    # sources at boot and fails LOUDLY (console message + a systemctl --failed entry) when none holds a
    # hardware key. Nothing requires the unit, so surfacing the lockout never blocks boot or sshd.
    systemd.services.keep-node-hardware-key-check = lib.mkIf cfg.requireHardwareKey (
      keyCheck.mkKeyCheck {
        description = "Anti-lockout: fail loudly if keepadmin has no hardware-backed (FIDO2) SSH key";
        authorizedKeysFile = admin.authorizedKeysFile;
        # A usable hardware key is a non-comment line whose ALGORITHM FIELD is one of the accepted
        # algorithms (not merely any sk- type, which sshd would refuse if keyTypes excludes it), whether
        # or not it sits behind an options field (e.g. `verify-required sk-ssh-ed25519@...`).
        matcher = "${pkgs.gawk}/bin/awk ${lib.escapeShellArg acceptedKeyProgram} \"$f\" 2>/dev/null";
        # The passing case is deliberately narrower than "you can log in": this sees ALGORITHMS in a
        # file, never whether the credential behind one was created with -O verify-required, so under
        # requireVerification a token missing it clears this check and is still refused at auth. Say so
        # here, because an operator reading this message is mid-lockout and needs the real next step.
        message =
          "KEEP NODE ANTI-LOCKOUT: keepadmin has NO hardware-backed (sk-) SSH key, but keepNode.security.yubikey.requireHardwareKey restricts sshd to ${lib.concatStringsSep "," acceptedAlgorithms}. Password auth is off, so remote access is IMPOSSIBLE. Enroll a FIDO2 key (keepnode-enroll-yubikey <sk-pubkey>), then: systemctl restart keep-node-hardware-key-check.service"
          + lib.optionalString cfg.requireVerification " NOTE: this check reads key algorithms only. requireVerification is on, so a credential created WITHOUT -O verify-required will satisfy this check and still be refused by sshd; confirm an actual login from your laptop before relying on it.";
        okMessage = "keepadmin has at least one hardware-backed SSH key";
      }
    );
  };
}
