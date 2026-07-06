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

The mesh uses **static endpoints** (no relay discovery): each node lists its own advertised endpoint
and every peer's npub + endpoint. Set the same `networkId` on all of them.

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
