# Deployment

Two ways to stand up a keep-node box:

- **Bring-up (debug) profile** , the installer ISO (`keepnode-debug`). Insecure by design (known root
  password, password SSH, open signups) so a fresh box is reachable over the LAN before the encrypted
  transport exists. For evaluation only. See the README's "Install on hardware".
- **Hardened (declarative) profile** , `nixosConfigurations.keepnode`, deployed from a config you
  author. This is the real deployment: the encrypted mesh forms at boot from your config, admin access
  is key-only over that mesh, `debugAccess` is off, and signups default-deny. The rest of this page
  covers it.

The model is a **co-owned cluster**: you (the operator) hold every node's config and every peer's
identity, so the whole mesh , nodes *and* your admin laptop , is provisioned declaratively. The mesh
is the perimeter; nothing admin-facing is exposed to the LAN.

## 1. Generate a mesh identity per participant

Every mesh participant , each node **and** your admin laptop , needs an nvpn identity: a `config.toml`
and its `secret` file, produced by `nvpn init`. The identity's **npub** is how peers refer to it, and
it must be known at deploy time so the roster can be authored ahead of boot.

```bash
# For each participant, in an isolated dir:
XDG_CONFIG_HOME=$PWD/node-a nvpn init      # prints: nostr_pubkey=npub1...
# -> node-a/nvpn/config.toml + node-a/nvpn/.config.toml.nostr-secret-key.secret
```

Record each npub. `keepNode.mesh.identityDir` points at an on-target directory holding exactly two
files: `config.toml` and `secret` , the latter being nvpn's `.config.toml.nostr-secret-key.secret`,
**renamed to `secret`**:

```bash
mkdir node-a-identity
cp node-a/nvpn/config.toml node-a-identity/config.toml
cp node-a/nvpn/.config.toml.nostr-secret-key.secret node-a-identity/secret
```

Deliver that directory to the node **out-of-band** (e.g. agenix/sops onto the encrypted volume) at a
runtime path , **never** as a Nix-path literal, or the secret key lands in the world-readable
`/nix/store`; the module refuses a store path.

## 2. Author each node's mesh roster

This how-to uses **static endpoints**: each node lists its own advertised endpoint and every peer's
npub + endpoint. Set the same `networkId` on all of them. (An opt-in `keepNode.mesh.discovery` mode
instead learns peer endpoints over a wisp relay , the `mesh-discovery` test proves it , for nodes with
dynamic addresses; static endpoints are the simplest to start with.)

```nix
# node A's configuration.nix (node B is symmetric, with A in its peers)
keepNode.mesh = {
  enable = true;
  package = nvpn;                       # the nvpn package
  networkId = "keepnode";               # shared across the cluster
  identityDir = "/run/secrets/mesh-id"; # node A's identity, delivered out-of-band
  selfEndpoint = "203.0.113.10:51820";  # this node's advertised ip:port
  peers = [
    { npub = "npub1...b"; endpoint = "203.0.113.11:51820"; }  # node B
    { npub = "npub1...laptop"; endpoint = "203.0.113.50:51820"; }  # your admin laptop
  ];
};
```

At boot, `keep-node-mesh-prepare` installs the identity and applies the roster, and
`keep-node-mesh.service` forms the mesh , no manual `nvpn init`/`nvpn set`. On a FROST-gated node the
identity is placed on the encrypted volume, fail-closed. Each node gets a deterministic `10.44.x.y`
mesh IP.

## 3. Enable admin SSH over the mesh

`keepNode.adminAccess` gives a hardened, key-only `keepadmin` account reachable **only over the mesh
interface** , the LAN and the WireGuard underlay never reach sshd. To administer the cluster, your
laptop joins the mesh (step 1-2 above, as a peer) and you SSH to a node's `10.44.x.y` address.

```nix
keepNode.adminAccess = {
  enable = true;
  authorizedKeys = [ "ssh-ed25519 AAAA... you@laptop" ];  # your SSH public key(s)
};
```

- Key-only (`PasswordAuthentication` off); `root` is not a network username (`PermitRootLogin no`);
  `keepadmin` is in `wheel` with passwordless sudo (the SSH key is the authentication).
- Public keys are public , list them inline; no secret manager needed.
- **Anti-lockout:** with keys empty the build is refused (password auth is off, so zero keys would
  permanently lock out remote access). `adminAccess` also requires the firewall enabled and refuses to
  coexist with `debugAccess`.

Then, from your (mesh-joined) laptop:

```bash
ssh keepadmin@10.44.x.y     # the node's mesh IP; not reachable from the LAN
```

## 4. Harden admin access with a YubiKey (FIDO2)

An SSH key is a *file on your laptop*: steal the laptop and you inherit node admin, silently. A FIDO2
credential (`ed25519-sk` / `ecdsa-sk`) keeps the private key inside the token's secure element, where it
cannot be copied, and `verify-required` demands a PIN **and** a physical touch on every login.

**This is node access only. It is not FROST.** Losing every YubiKey costs you SSH to the box (physical
console remains the permanent break-glass); it never costs you the vault. Vault recovery is the FROST
threshold quorum, unchanged by anything on this page.

### Generate the credential (on your laptop)

Do this **twice**: a primary token and a backup you store off-site. One hardware key is a single point
of failure for node access.

```bash
ssh-keygen -t ed25519-sk -O resident -O verify-required -C yubikey-primary
```

- `-O resident` stores the credential *on the token*, so you can recover it onto a new laptop with
  `ssh-keygen -K` (run in `~/.ssh`). Non-resident keys work too, but then the key handle file is
  something you must back up yourself.
- `-O verify-required` is what forces the PIN in addition to the touch.
- `ecdsa-sk` instead of `ed25519-sk` if your token's firmware predates FIDO2 ed25519 support.

The `.pub` file it writes is what you enroll; the private half never leaves the YubiKey.

### Enroll it

```nix
keepNode.security.yubikey = {
  enable = true;
  authorizedKeys = [
    "sk-ssh-ed25519@openssh.com AAAA... yubikey-primary"
    "sk-ssh-ed25519@openssh.com AAAA... yubikey-backup"
  ];
  requireHardwareKey = true;   # refuse every non-hardware-backed key at sshd
};
```

- `requireHardwareKey` narrows sshd's `PubkeyAcceptedAlgorithms` to the `sk-` algorithms, so a software
  key is **rejected by the daemon**, not merely left out of a file. Leave it `false` (the default) while
  you still need software-key access; the module is fully backward compatible in that mode, and the
  hardware keys still carry a per-key `verify-required`.
- `keyTypes` (default `[ "ed25519-sk" "ecdsa-sk" ]`) is the declarative allow-list of credential types.
  Narrow it to `[ "ed25519-sk" ]` to refuse ecdsa-sk outright.
- **Anti-lockout:** `requireHardwareKey = true` with no usable hardware key fails the build; if the key
  lives in the runtime `authorizedKeysFile` (which the build cannot inspect), the
  `keep-node-hardware-key-check` unit fails loudly at boot instead, without blocking boot or sshd.
- Password authentication stays disabled throughout. This module only ever *removes* an authentication
  path.

> **What the anti-lockout guards cannot see.** Both of them , the build assertion and the boot check ,
> read *key algorithms in a file*. They cannot see whether the credential on your token was created
> with `-O verify-required`, and they cannot see whether the key body is intact. So with
> `requireVerification = true` (the default), a token enrolled **without** that flag satisfies both
> guards and is still refused by sshd at login: both report healthy on a node you cannot reach.
> **Actually log in over the mesh with the YubiKey , from a second terminal, keeping your current
> session open , before you flip `requireHardwareKey` on or remove your software key.** That login is
> the only real proof; everything else is a file check.

### Enroll after install

On a node installed from the generic ISO the closure is fixed, so add a token at runtime:

```bash
ssh keepadmin@<node>
keepnode-enroll-yubikey "sk-ssh-ed25519@openssh.com AAAA... yubikey-backup"
```

It validates the key, refuses anything that is not `sk-`, de-duplicates, appends `verify-required`, and
re-runs the anti-lockout checks. Enroll the backup token **before** flipping `requireHardwareKey` on.

Pass **one** key per invocation: a multi-line paste is refused outright, because only the first line
would be validated while every line got written.

### Vaultwarden: YubiKey as 2FA / passkey

Vaultwarden supports WebAuthn, but it binds every credential to the origin in its `DOMAIN` setting: if
that does not match the URL you actually browse, registration appears to work and then fails on the next
login. Declare it:

```nix
keepNode.vaultwarden.domain = "http://localhost:8222";   # the SSH-tunnelled default
```

`http://localhost` is a secure context, so WebAuthn works over the tunnel without TLS. Do **not** put a
mesh IP or LAN name behind plain `http://`: browsers treat that as a non-secure context and refuse
WebAuthn entirely (and Vaultwarden drops secure cookies), so registration cannot even start. Off
localhost, use HTTPS. If you enable
`keepNode.ingress`, it sets `DOMAIN` to its public HTTPS hostname and takes precedence , register your
token against whichever origin you actually use, and re-register if you change it.

Then in the web vault: **Settings -> Security -> Two-step login -> FIDO2 WebAuthn**, add both tokens, and
save the recovery code somewhere offline. Vaultwarden's own passkey/2FA state lives in the vault DB on
the FROST-gated volume, so it is covered by the same threshold guarantee as everything else.

## Installer bring-up (generic ISO)

Mesh-only admin assumes your laptop is already a rostered mesh peer. For a co-owned cluster you author
that in from the start (step 2). For a box installed from the generic ISO, where the operator key
isn't known at build time, `install-keepnode --ssh-key <pubkey|file>` enrolls your key at install time
into a runtime file (`keepNode.adminAccess.authorizedKeysFile`) that the fixed closure reads. The
installed image is the **hardened** profile (no known password, key-only SSH, `debugAccess` off), with
`keepNode.adminAccess.lanBringup = true` so the key-only SSH is reachable on the LAN for first contact:

```bash
install-keepnode /dev/sda --ssh-key ~/.ssh/id_ed25519.pub
# reboot, then: ssh keepadmin@<node-ip>
```

Once the node has joined the mesh, redeploy with `lanBringup = false` for the mesh-only posture above.
Physical console access is the permanent break-glass.

See [Multi-node sync (design)](./multi-node-sync.md) for what replicates over the mesh once it's up.
