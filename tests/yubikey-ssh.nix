# YubiKey / FIDO2 admin SSH posture (issue #99). Two nodes, differing only in
# `keepNode.security.yubikey.requireHardwareKey`, prove the security-relevant behaviour of the module:
#
#   strict: requireHardwareKey = true  -> sshd accepts ONLY sk- algorithms, so the enrolled SOFTWARE key
#           is refused at authentication time (not merely absent from a file), verify-required is
#           enforced globally, and the runtime anti-lockout unit fails loudly while no hardware key
#           exists , then passes once one is enrolled.
#   mixed:  requireHardwareKey = false -> the accepted-algorithm set is untouched and the same software
#           key logs in normally. This is the backward-compatibility guarantee for existing deployments.
#
# A real FIDO2 authentication cannot be exercised here (it needs physical hardware; there is no virtual
# authenticator in the test VM), so the test asserts the sshd policy that gates it plus the refusal of
# everything that is not hardware-backed , which is the part a refactor can silently break.
#
# Run: nix build .#checks.x86_64-linux.yubikey-ssh
{
  adminKeyFixture,
  ...
}:
let
  keysFile = "/etc/keepnode/admin_authorized_keys";
  base =
    {
      requireHardwareKey,
      keyTypes ? [
        "ed25519-sk"
        "ecdsa-sk"
      ],
    }:
    {
      imports = [
        ../nixos/admin-access.nix
        ../nixos/yubikey.nix
      ];
      keepNode.adminAccess = {
        enable = true;
        # The operator's SOFTWARE key is provisioned into the runtime file by the test script, mirroring
        # how install-keepnode enrolls it post-install.
        authorizedKeysFile = keysFile;
        lanBringup = true;
      };
      keepNode.security.yubikey = {
        enable = true;
        inherit requireHardwareKey keyTypes;
      };
    };
in
{
  name = "keep-node-yubikey-ssh";

  nodes.strict = { ... }: base { requireHardwareKey = true; };
  nodes.mixed = { ... }: base { requireHardwareKey = false; };
  # keyTypes narrowed to one credential type: an ecdsa-sk key is hardware-backed but sshd is configured
  # to refuse it, so neither the anti-lockout check nor the enrollment helper may treat it as usable.
  nodes.narrow =
    { ... }:
    base {
      requireHardwareKey = true;
      keyTypes = [ "ed25519-sk" ];
    };

  testScript =
    { nodes, ... }:
    let
      strictLan = nodes.strict.networking.primaryIPAddress;
      mixedLan = nodes.mixed.networking.primaryIPAddress;
      # A syntactically well-formed sk- authorized_keys line. It is never authenticated with (no
      # authenticator exists in the VM); it only has to be the kind of line the anti-lockout check must
      # recognise as a hardware key.
      skKey = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fAAAABHNzaDo= yubikey-fixture";
      # A REAL, parseable ecdsa-sk credential (valid P-256 point), so the narrow node's refusals are
      # attributable to the keyTypes allow-list and not to a malformed key body.
      skEcdsaKey = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBOKRXwzBjTsl22Z1ZTrbbYm69yDI7inkAVNomlkgMUZSoRbudm0h2HRnmlkOfeltknXGkZ5an2nI9bzuhTeg41IAAAAEc3NoOg== yubikey-ecdsa-fixture";
    in
    ''
      start_all()
      strict.wait_for_unit("sshd.service")
      mixed.wait_for_unit("sshd.service")
      narrow.wait_for_unit("sshd.service")

      ssh = (
          "ssh -i /root/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
          "-o BatchMode=yes -o ConnectTimeout=10"
      )
      for m in (strict, mixed, narrow):
          m.succeed("install -m 0600 ${adminKeyFixture}/id /root/id")
          m.succeed("install -d -m 0755 /etc/keepnode")
          m.succeed("install -m 0644 ${adminKeyFixture}/id.pub ${keysFile}")
          # The hardened posture is untouched by this module: no password path, no root over the network.
          m.succeed("sshd -T | grep -qx 'passwordauthentication no'")
          m.succeed("sshd -T | grep -qx 'kbdinteractiveauthentication no'")
          m.succeed("sshd -T | grep -qx 'permitrootlogin no'")

      # requireHardwareKey narrows sshd to the sk- algorithms (both key types are allowed by default,
      # certificate variants included) and requires user verification (PIN + touch) on every auth.
      strict.succeed("sshd -T | grep -q '^pubkeyacceptedalgorithms .*sk-ssh-ed25519@openssh.com'")
      strict.succeed("sshd -T | grep -q '^pubkeyacceptedalgorithms .*sk-ecdsa-sha2-nistp256@openssh.com'")
      strict.succeed("sshd -T | grep -qx 'pubkeyauthoptions verify-required'")
      # ...and NOTHING software-backed survives in that set.
      strict.fail("sshd -T | grep -E '^pubkeyacceptedalgorithms ' | grep -qE '(^| |,)(ssh-ed25519|rsa-sha2-[0-9]+|ecdsa-sha2-nistp256)(,| |$)'")

      # The mixed node keeps stock algorithm negotiation (software keys still negotiable) and does not
      # impose a global verify-required, which would lock those software keys out.
      # Anchored on the FIELD: bare 'ssh-ed25519' is a substring of 'sk-ssh-ed25519@openssh.com', which
      # is present in the strict set too, so an unanchored match would pass even if this node had
      # regressed into the sk-only posture , proving nothing about backward compatibility.
      mixed.succeed("sshd -T | grep -E '^pubkeyacceptedalgorithms ' | grep -qE '(^| |,)ssh-ed25519(,| |$)'")
      mixed.fail("sshd -T | grep -qx 'pubkeyauthoptions verify-required'")

      # Anti-lockout: the strict node enforces sk-only but no hardware key is enrolled, so the runtime
      # check must FAIL LOUDLY , while boot and sshd carry on regardless.
      strict.wait_until_succeeds("systemctl is-failed --quiet keep-node-hardware-key-check.service")
      strict.succeed("journalctl -u keep-node-hardware-key-check.service --no-pager | grep -q 'ANTI-LOCKOUT'")
      # The unit is not part of any dependency chain, so the failure did not take sshd down.
      strict.succeed("systemctl is-active --quiet sshd.service")
      # A SOFTWARE key present in the same file does not clear it: the check counts hardware keys, not
      # keys, which is exactly the lockout it exists to catch.
      strict.fail("systemctl restart keep-node-hardware-key-check.service")
      # Nor does a software key whose free-form COMMENT merely names an sk- algorithm: the check must
      # match the algorithm FIELD, since a substring match here reports a hardware key on a node whose
      # only key sshd will refuse , the silent brick this unit exists to catch, in the unsafe direction.
      strict.succeed("cp ${keysFile} /tmp/keys.bak")
      strict.succeed("printf '%s\\n' \"$(cat ${adminKeyFixture}/id.pub) my sk-ssh-ed25519@openssh.com backup key\" >> ${keysFile}")
      strict.fail("systemctl restart keep-node-hardware-key-check.service")
      strict.succeed("cp /tmp/keys.bak ${keysFile}")

      # The software key is enrolled and would authenticate on any ordinary key-only node; the strict
      # node refuses it at the DAEMON, purely because it is not hardware-backed. This is the property.
      strict.fail(f"{ssh} keepadmin@${strictLan} true")
      # Same key, same account, requireHardwareKey off -> logs in with passwordless sudo (backward
      # compatibility for every existing software-key deployment).
      mixed.wait_until_succeeds(f"{ssh} keepadmin@${mixedLan} true", timeout=30)
      mixed.succeed(f"{ssh} keepadmin@${mixedLan} sudo -n true")

      # Enrolling a hardware key into the runtime file clears the anti-lockout alarm , no false alarm on
      # a correctly-provisioned node.
      strict.succeed("printf '%s\\n' 'verify-required ${skKey}' >> ${keysFile}")
      strict.succeed("systemctl restart keep-node-hardware-key-check.service")
      strict.succeed("systemctl is-active --quiet keep-node-hardware-key-check.service")

      # The enrollment helper is the post-install path for a second (backup) token: it accepts a FIDO2
      # key, de-duplicates, and refuses a software key outright, so the hardware guarantee cannot be
      # eroded by enrolling a copyable key through it.
      strict.succeed("keepnode-enroll-yubikey '${skKey}' | grep -q 'already enrolled'")
      strict.fail("keepnode-enroll-yubikey \"$(cat ${adminKeyFixture}/id.pub)\"")
      # A MULTI-LINE payload whose first line is a genuine FIDO2 key must be refused whole. Validating
      # only line 1 (which every check here does, being line-agnostic) would append line 2 , a software
      # key, without the verify-required prefix , through a helper whose entire point is refusing one.
      strict.fail("keepnode-enroll-yubikey \"$(printf '%s\\n%s' '${skKey}' \"$(cat ${adminKeyFixture}/id.pub)\")\"")
      strict.succeed("test \"$(grep -c '^ssh-ed25519 ' ${keysFile})\" = 1")

      # keyTypes is a real allow-list, not documentation: with it narrowed to ed25519-sk, sshd carries no
      # ecdsa-sk algorithm at all...
      narrow.succeed("sshd -T | grep -q '^pubkeyacceptedalgorithms .*sk-ssh-ed25519@openssh.com'")
      narrow.fail("sshd -T | grep -E '^pubkeyacceptedalgorithms ' | grep -q 'sk-ecdsa'")
      # ...the helper refuses to enroll a credential sshd would then reject (citing keyTypes)...
      narrow.fail("keepnode-enroll-yubikey '${skEcdsaKey}'")
      # Captured to a file rather than piped: the driver runs commands under `pipefail`, so a pipeline
      # whose left-hand side exits non-zero can never pass regardless of what the message says.
      narrow.succeed("keepnode-enroll-yubikey '${skEcdsaKey}' 2>/tmp/enroll.err || true")
      narrow.succeed("grep -q 'keyTypes' /tmp/enroll.err")
      narrow.fail("grep -q 'sk-ecdsa' ${keysFile}")
      # ...and an excluded-type key sitting in the keys file does NOT satisfy the anti-lockout check,
      # which is the silent lockout a generic sk- match would have waved through.
      narrow.succeed("printf '%s\\n' 'verify-required ${skEcdsaKey}' >> ${keysFile}")
      narrow.fail("systemctl restart keep-node-hardware-key-check.service")
      # An ALLOWED type clears it, so the check is not simply always-failing.
      narrow.succeed("keepnode-enroll-yubikey '${skKey}'")
      narrow.succeed("systemctl restart keep-node-hardware-key-check.service")
      narrow.succeed("systemctl is-active --quiet keep-node-hardware-key-check.service")
    '';
}
