# Shared authorized_keys line classifier for the admin SSH modules.
#
# A line is `[options] algorithm base64-body [comment]`: the options field may be absent, the field
# separator may be a TAB (sshd accepts it), and the comment is free-form text. So the algorithm is not
# simply everything up to the first space, and getting it wrong fails in BOTH directions, a
# tab-separated or options-prefixed hardware key read as software is a false anti-lockout build
# failure, while an algorithm name occurring in a software key's COMMENT read as the key type reports
# a hardware key present on a node whose only key sshd will refuse. Only the first two fields are ever
# considered, so a comment can never be mistaken for an algorithm.
{ lib }:
let
  # Every SSH public key algorithm name starts with one of these; no authorized_keys OPTION does
  # (`from=`, `command=`, `verify-required`, `restrict`, `cert-authority`, ...), which is what makes
  # an options field distinguishable from the algorithm without parsing the options grammar.
  algorithmPrefixes = [
    "ssh-"
    "sk-"
    "ecdsa-"
    "rsa-"
    "webauthn-"
  ];
  isAlgorithmField = t: lib.any (p: lib.hasPrefix p t) algorithmPrefixes;
in
rec {
  # An empty or whitespace-only entry is not a usable key.
  trimKeys = ks: lib.filter (k: k != "") (map lib.strings.trim ks);

  # Split on any whitespace RUN rather than a literal space, so tab-separated fields are fields.
  tokensOf = k: lib.filter (t: builtins.isString t && t != "") (builtins.split "[[:space:]]+" k);

  # Field 1, or field 2 when field 1 is an options field. Falls back to field 1 so an unparseable
  # line still yields something nameable for an assertion message.
  algorithmOf =
    k:
    let
      fields = lib.take 2 (tokensOf k);
      fallback = if fields == [ ] then "" else lib.head fields;
    in
    lib.findFirst isAlgorithmField fallback fields;

  isHardwareKey = k: lib.hasPrefix "sk-" (algorithmOf k);

  # Add `option` to a line's options field. Options are ONE comma-separated field before the algorithm,
  # so a line that already carries options must be extended in place: prepending a second
  # space-separated field yields `verify-required from="..." sk-... body`, which sshd cannot parse, and
  # the key is then silently ignored, an enrolled-but-dead key that still satisfies the anti-lockout
  # guards. Idempotent, so a line that already states the option is returned unchanged.
  withOption =
    option: k:
    let
      fields = tokensOf k;
      first = if fields == [ ] then "" else lib.head fields;
    in
    if fields == [ ] then
      k
    else if isAlgorithmField first then
      "${option} ${k}"
    else if lib.elem option (lib.splitString "," first) then
      k
    else
      "${option},${k}";
}
