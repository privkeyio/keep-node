# The shared shape of the anti-lockout boot checks (admin-access and yubikey).
#
# Both units answer the same question , does keepadmin still have a key sshd will accept? , over the
# same key sources, and differ only in what counts as a usable key. Keeping the SOURCE LIST in one
# place is the point: a third key source added to one check and not the other leaves the other
# reporting a lockout that is not there, or worse, missing one that is , which is precisely the
# failure both units exist to catch. Nothing requires either unit, so a failure surfaces the lockout
# (console message + a `systemctl --failed` entry) WITHOUT blocking boot or sshd.
{ lib }:
{
  # `matcher` is a shell command evaluated with "$f" bound to each key source in turn; exit 0 means
  # that source holds a usable key. `message` is interpolated into a double-quoted shell string, so it
  # may reference "$akf" (the runtime keys file) and must not contain a double quote or a backtick.
  mkKeyCheck =
    {
      description,
      authorizedKeysFile,
      matcher,
      message,
      okMessage,
    }:
    let
      hasRuntimeFile = authorizedKeysFile != null;
    in
    {
      inherit description;
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        present=0
        # Bind the operator-supplied path to a shell VARIABLE via escapeShellArg, then reference it only
        # as "$akf". The path is operator config, but embedding it raw in a double-quoted string would
        # let a value containing $(...) or a backtick run as root at boot; a shell variable's contents
        # are never re-scanned for command substitution, so this stays safe on any path.
        ${lib.optionalString hasRuntimeFile "akf=${lib.escapeShellArg (toString authorizedKeysFile)}"}
        # The inline `authorizedKeys` land in the Nix-managed per-user file; the runtime
        # authorizedKeysFile (when configured) is the installer/operator-provisioned path.
        for f in /etc/ssh/authorized_keys.d/keepadmin ${lib.optionalString hasRuntimeFile ''"$akf"''}; do
          if [ -f "$f" ] && ${matcher}; then
            present=1
          fi
        done
        if [ "$present" -eq 0 ]; then
          msg="${message}"
          echo "$msg" > /dev/console 2>/dev/null || true
          echo "$msg" >&2
          exit 1
        fi
        echo ${lib.escapeShellArg okMessage}
      '';
    };
}
