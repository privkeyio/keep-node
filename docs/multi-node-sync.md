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
> asserts the promoted node serves the replicated row + attachment.
> Still to come: the cross-node **transport** (everything lands the replica locally today; the test
> stubs the hop with a copy , the real deploy ships it over the encrypted mesh, which does not exist
> yet), and a **replication-lag** signal.
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
