# Fast validation of the headless Bitwarden client helper (tests/lib/vw-client.py) against a plain
# Vaultwarden: register -> store a login -> read it back. No OPRF/TPM/reboot -- this exists only to
# get the client-side crypto right cheaply before wiring the helper into the heavy M0 gated test.
#
# Run: nix build .#checks.x86_64-linux.vw-client-check
{ pkgs, ... }:
{
  name = "keep-node-vw-client-check";

  nodes.vw =
    { ... }:
    {
      services.vaultwarden = {
        enable = true;
        config = {
          DOMAIN = "http://localhost:8222";
          ROCKET_ADDRESS = "127.0.0.1";
          ROCKET_PORT = 8222;
          SIGNUPS_ALLOWED = true;
        };
      };
    };

  testScript =
    let
      client = import ./lib/vw-client.nix { inherit pkgs; };
    in
    ''
      start_all()
      vw.wait_for_unit("vaultwarden.service")
      vw.wait_for_open_port(8222)

      base = "http://localhost:8222"
      email = "m0@keep.test"
      pw = "MasterPass123"

      vw.succeed(f"VW_PASSWORD={pw} ${client} register {base} {email} m0user")
      vw.succeed(f"VW_PASSWORD={pw} VW_VALUE=SecretValue123 ${client} store {base} {email} mysecret")
      got = vw.succeed(f"VW_PASSWORD={pw} ${client} read {base} {email} mysecret").strip()
      assert got == "SecretValue123", f"read back {got!r}, expected SecretValue123"
    '';
}
