# Multi-node sync (design)

> **Status: in progress.** Keep Node runs a single node today; the M1 active/standby HA build is
> underway, one increment at a time, each covered by the `ha-failover` nixosTest. Landed so far:
> the **shared JWT signing key** (`keepNode.vaultReplication.rsaKeyFile` , installed on every node
> before Vaultwarden starts so a session token minted on the active is accepted by a promoted
> standby, and, when the FROST gate is on, written only onto the mounted encrypted volume) and
> **Litestream WAL streaming** of `db.sqlite3` (`keepNode.vaultReplication.litestream.enable` , the
> active continuously ships the vault DB's write-ahead log to a replica a peer can restore); and
> **attachment/Send file replication** (a periodic sync mirrors the `attachments/`+`sends/` files
> Litestream does not carry into the same replica dir , bounded eventual consistency, since two
> async replicators cannot give atomic file-before-row); and **crash + promote failover**
> (`keep-node-vault-promote` , an operator-triggered unit that restores the vault DB + files from
> the delivered replica and starts Vaultwarden, so a standby takes over the failed active's data with
> sessions intact because the JWT key is shared). The `ha-failover` test crashes the active and
> asserts the promoted node serves the replicated row + attachment. Promotion does NOT fence the
> failed active, and because the JWT signing key is shared cluster-wide, an old active that comes
> back can mint tokens the promoted node accepts and resume writing (split-brain), so the operator
> runbook must ensure the old active stays down before promoting.
> The cross-node **transport is now real**, end to end. The `nvpn` encrypted mesh (nostr-vpn,
> boringtun userspace WireGuard, Nostr-authenticated peers) is packaged and run headless by
> `keepNode.mesh`, validated forming + carrying traffic over its `10.44.x.y` tunnel with no relay (the
> `mesh` test). With `keepNode.vaultReplication.role` and `meshReplication`, the active pushes its
> whole replica dir , DB replica plus the mirrored `attachments/`+`sends/` files , to a standby
> receiver reachable ONLY on the mesh interface; the standby restores it. And the **full failover runs
> over that mesh**: the `mesh-replication` test replicates a DB row, an attachment, and a Send across
> the tunnel, propagates a deletion, then crashes the active and asserts the promoted standby serves
> the mesh-delivered data with the shared JWT key intact , the M1 Done criterion over a genuine
> transport, so no stand-in copy remains. The standby also carries a **replication-lag health signal**
> (`meshReplication.maxLagSeconds`): the active heartbeats the replica on every push, and a periodic
> `keep-node-vault-lag-check` on the standby fails once the received heartbeat is older than the
> threshold, so an idle-but-in-sync standby reads healthy while a stalled/partitioned one is surfaced.
> **Keep-state-over-`wisp` replication** now lands too, alongside the Vaultwarden HA above: keep-web
> (the Keep daemon, a subsystem separate from Vaultwarden) replicates its OWN encrypted vault records
> , keys, descriptors, relay configs , to a standby over the on-box `wisp` relay under a shared cluster
> identity, so a promoted node serves the same Keep secrets. See *Keep-state replication* below. (The
> 2-of-3 quorum is covered by the `oprf-unlock-2of3` test.) Relay-based peer discovery over `wisp` is
> implemented as the opt-in `keepNode.mesh.discovery` mode and tested (`mesh-discovery`); full
> symmetric-NAT traversal for internet deployment is the remaining piece beyond the VM.
> This chapter inventories Vaultwarden's state and the constraints that design has to respect.

Vaultwarden (1.36.x here) keeps its state under one data directory, the FROST-gated LUKS
volume mounted at `/var/lib/vaultwarden`. Keep Node configures the **SQLite** backend, which is
single-writer; that is what makes **active/standby** (one node serves and writes, others tail and
can take over) the natural HA shape rather than active/active.

## What is in the data directory

| Item | Kind | Server can read it? | Replicate? |
|------|------|---------------------|------------|
| `db.sqlite3` | SQLite database (see tables below) | Mixed, see below | Yes (authoritative state) |
| `attachments/<cipher>/<id>` | Per-attachment **files** | No (E2E ciphertext) | Yes, and consistently with the DB row that references them |
| `sends/<id>` | Bitwarden **Send** files | No (E2E ciphertext) | Yes, same consistency caveat |
| `rsa_key.pem` / `.pub.pem` | RSA keypair that **signs JWT access tokens** | Yes (it is the signing secret) | Yes, **must be identical on every node** |
| `config.json` | Admin-panel runtime config | Yes | Keep Node sets config declaratively via Nix, so this is normally absent/empty; sync only if the admin panel is used |
| `icon_cache/` | Cached favicons | n/a | **No**, regenerable |
| `tmp/`, `*.tmp` | Scratch | n/a | **No**, ephemeral |

## Database tables: encrypted blobs vs metadata vs server-side secrets

Three categories matter for replication and for how much a replica is trusted:

- **End-to-end ciphertext the server cannot read.** Cipher contents, folder names, Send payloads,
  and attachment keys/filenames are client-encrypted; the server stores opaque blobs. Tables:
  `ciphers`, `folders`, `sends`, and the encrypted columns of `attachments` (`akey`, `file_name`).
  Replicating these leaks nothing.
- **Server-readable metadata.** Emails, names, IDs, timestamps/revision dates, KDF parameters,
  org/collection membership, policies, device identifiers and types, attachment `file_size`. Tables:
  `users` (non-secret columns), `organizations`, `collections`, `devices`, `org_policies`, `events`,
  etc. Useful to an attacker, but not the vault contents.
- **Server-side secrets, a replica that can read these is as trusted as the primary.** This is the
  key finding for the "ciphertext-only replica" claim in the threat model:
  - `users.password_hash` + `salt`, the server-side hash of the client master-password hash.
  - `users.private_key`, the user's encrypted private key (E2E ciphertext, but still sensitive).
  - `users.totp_secret` / `totp_recover`, **TOTP 2FA secrets stored server-side in the clear.**
  - `users.security_stamp`, rotating it invalidates all of a user's sessions.
  - `devices.refresh_token` / `push_token`, live session refresh tokens and mobile push tokens.
  - the `rsa_key` files, the JWT signing key.

  A replica that can *serve* Vaultwarden necessarily decrypts the LUKS volume and can read all of
  the above. A genuinely "ciphertext-only" replica is therefore a **cold standby**: it stores the
  replicated bytes but cannot read or serve them until it is keyed by the quorum. A **warm** standby
  that can fail over instantly is, by construction, a fully trusted holder. M1 must pick a point on
  that spectrum deliberately, per node.

## Replication gotchas (active/standby)

1. **SQLite needs WAL streaming.** Use Litestream or LiteFS to stream the WAL from the active node;
   both require `journal_mode=WAL`. The active node is the sole writer; standbys are read-only until
   promoted. Failover = promote a standby that has the replicated DB.
2. **`rsa_key` must be identical on every node.** A JWT signed by node A is rejected by node B if
   their signing keys differ, so an instant failover would force every client to re-authenticate (or
   break). Generate the keypair once and distribute it as a synced secret (over the encrypted mesh,
   onto each node's LUKS volume) rather than letting each node generate its own on first boot.
3. **Attachment/Send files must replicate consistently with the DB.** The DB row references a file
   on disk by id; if the row replicates before the file, that attachment is briefly broken on the
   standby. Replicate files **before** the referencing DB transaction, or accept (and bound) an
   eventual-consistency window.
4. **Session continuity depends on `devices` freshness.** Replication lag on `devices.refresh_token`
   means a client's refresh token may be missing on the just-promoted standby, the client re-logs
   in. `push_token` lag means missed mobile push until the next sync. Bound the lag accordingly.
5. **Client sync correctness rides on revision dates + `security_stamp`.** Bitwarden clients decide
   whether to pull using the account revision date; a standby behind on replication can serve a stale
   revision after failover until the next write bumps it. `security_stamp` likewise must be current,
   or a stale standby could honor sessions the primary had already revoked.
6. **The LUKS layer is below replication.** Replicate the *application* state over the encrypted
   transport (mesh); each node re-encrypts it under its own FROST-gated LUKS volume. Never ship the
   plaintext volume or an at-or-above-threshold set of shares between nodes.

## Implications for M1

- Active/standby with WAL streaming (Litestream/LiteFS) for `db.sqlite3`, plus file replication for
  `attachments/` and `sends/`, ordered file-before-row.
- A shared, securely distributed `rsa_key` so failover does not invalidate sessions.
- An explicit decision on cold vs warm standby, recorded per node, because a serving replica reads
  `totp_secret`/`password_hash`/refresh tokens and is therefore fully trusted, the threat model's
  "ciphertext-only replica" only holds for a cold standby.
- Bounded replication lag, surfaced as an availability/consistency metric, since failover correctness
  (sessions, revisions, 2FA) depends on it.

## Keep-state replication (keep-web)

Everything above concerns **Vaultwarden**. Keep also runs **keep-web**, its own headless daemon with an
encrypted vault (keys, wallet descriptors, relay configs, and per-node FROST shares). For a promoted
standby to serve the same Keep secrets, that vault state replicates too, over the same mesh, using the
on-box `wisp` relay as the transport instead of file streaming.

How it works (implemented in `privkeyio/keep`, wired here by `keepNode.keepWeb`):

- **Shared cluster identity.** One Keep Nostr keypair for the cluster, distributed out-of-band to every
  node (like the shared Vaultwarden JWT key). The active publishes under it; the standby subscribes to
  that one author. Single-writer: `stateRole = "active"` publishes local writes, `"standby"` subscribes
  and reconstructs. A promoted standby is redeployed as `active`.
- **Per-record addressable events.** Each replicated redb record is one NIP-78 addressable event
  (kind 30078), `d`-tag `keep:<table>:<record-id>`, so a newer write supersedes the old and the relay
  keeps only the latest. The content is the record's already-vault-encrypted bytes, NIP-44-encrypted to
  the shared identity, so the relay only ever holds ciphertext.
- **Shares are never replicated.** Only `keys`, `descriptors`, and `relay_configs` propagate. Each node
  keeps its OWN FROST share; the consumer rejects any other table.
- **Shared vault data key.** The double-wrapped bytes only decrypt on the standby if both nodes share
  the vault's record-encryption key. Each node seeds the SAME key at first-run via `KEEP_STORAGE_KEY`
  (`storageKeyFile`), delivered onto the encrypted volume like the other cluster secrets; each node
  still wraps it under its own password.

Configuration (`keepNode.keepWeb`): `stateRelay` (the mesh `wisp`, e.g. `ws://<mesh-ip>:7777`),
`stateIdentityFile` (the shared cluster nsec), `storageKeyFile` (the shared data key), and `stateRole`.
The `keep-state-replication` nixosTest brings up a relay plus an active and a standby node sharing the
data key, and asserts both create their shared-key vault and connect keep-web to the relay; the wire
round-trip (active write → relay → standby reconstruct + read-back) is covered by keep's own e2e test.
