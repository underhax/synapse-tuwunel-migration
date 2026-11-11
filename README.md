# synapse-tuwunel-migration

Partial Synapse-to-Tuwunel Matrix migration CLI built on [mautrix-go](https://github.com/mautrix/go). Transfers selected accounts over the Matrix Client-Server API, paired with an offline Synapse Ed25519 signing-key drop-in for Tuwunel maintenance import.

## Migration Scope and Limitations

- Client-Server API model and manual manifest: Synapse (PostgreSQL) and Tuwunel (RocksDB) use non-interchangeable storage backends, so migration operates over the Client-Server API without direct database reads or server-wide enumeration. Administrators must manually author `migration.json` for allowlisted accounts and supply Synapse credentials (`synapse_access_token` or `synapse_password`), SSSS recovery keys (`recovery_key`), Tuwunel account passwords (`tuwunel_password`), `tuwunel_shared_secret` for account provisioning, and the Synapse `.signing.key` file.
- Cryptographic identity and backups transferred: Cross-signing keys, SSSS containers, user-signing trust signatures for verified local and external contacts, and `m.megolm_backup.v1` room key backups are migrated.
- Local rooms recreated on Room v12: Non-federated local rooms are recreated from scratch on Tuwunel (default Room v12) with new room IDs and without message history, while preserving Synapse room state and configuration: allowlisted members, room name, topic, avatar, encryption settings, retention policy (`m.room.retention`), history visibility, join rules, guest access, power levels (mapping co-admins to `additional_creators`), room tags, and `m.direct` mappings.
- Federated rooms rejoined with original IDs: Rooms with currently joined external participants retain their original Matrix room IDs and are rejoined via ranked remote `via` servers during `federate-sync`, with their room tags restored; failed joins are logged and skipped.
- Spaces rebuilt and pruned: Local Spaces are recreated after child rooms (default Room v12) with preserved room settings and remapped `m.space.child` links (new IDs for local rooms, original IDs for federated rooms, plus `order`, `via`, and `suggested` attributes). References to excluded or unmigrated rooms are stripped, and Spaces left with zero migrated child rooms are iteratively pruned; federated Spaces retain their original IDs and are rejoined via `federate-sync`.
- Local history, aliases, and device sessions omitted: Local room message timelines, canonical room aliases (`m.room.canonical_alias`), and legacy Synapse device IDs are not migrated; users establish fresh device sessions on Tuwunel and restore keys and verification via SSSS.
- Single-user notes replay caveats: When `replay_single_user_notes` is enabled, pure single-participant rooms are replayed via the Client-Server API (`m.room.message` events, replies, final edited bodies, media attachments, and reactions). Replayed events receive new event IDs and current migration timestamps rather than original Synapse timestamps. Undecryptable Megolm events; non-message, unsupported, or unparseable mautrix-go events; and attachments whose media returns `404`/`M_NOT_FOUND`, fails decryption, or has an invalid `mxc://` URI (along with their referencing note messages) are skipped.
- Bridged rooms excluded: Rooms carrying bridge state markers (`m.bridge`, `uk.half-shot.bridge`, `fi.mau.*`) or non-allowlisted `io.element.functional_members` service bots are dropped together with their bridge contacts, room keys, and `m.direct` entries. Configure bridges independently on Tuwunel so bridge rooms and contacts resync from the bridge side.
- Orphaned single-member rooms skipped: A non-Space room with only one currently joined allowlisted user is excluded if its membership state includes any other local or external participant (non-allowlisted, invited, left, kicked, or banned). Only rooms whose sole historical and current participant is one allowlisted user qualify as `single_user_notes`; rooms with zero joined allowlisted users are also skipped. Local rooms retaining two or more joined allowlisted users are migrated without non-allowlisted or departed members.

---

<details>
<summary><strong>Workspace Preparation</strong></summary>

## Workspace Preparation

> **Note:** The commands below assume execution as `root`. Always `cd /root/matrix-migration` and run `./migrator` from inside the workspace directory. `/home/matrix/tuwunel/data` is an example Tuwunel data directory; replace it with your target database path if it differs.

Workspace layout (`/root/matrix-migration`, mode `0700`):

```text
├── migrator                                # Migration CLI binary (0500)
├── synapse.signing.key                     # Copy of Synapse <domain>.signing.key, renamed to synapse.signing.key (0400)
├── migration.json                          # Migration manifest and credentials (0400 or 0600)
├── tuwunel.toml                            # Staging Tuwunel configuration (0600)
├── element-config.json                     # Temporary Element Web staging config (0644)
└── dump/                                   # Migration state and exported artifacts created by migrator; do not create files manually (0700)
    ├── accounts/                           # Per-account keys, profiles, trust graphs, sessions (0700)
    ├── media/                              # SHA-256 content-addressed media blobs (0700)
    ├── rooms/                              # Classified local and federated room manifests (0700)
    ├── manifest_state.json                 # Generated migration progress and room ID map (0600)
    └── tuwunel-import-key.toml             # Generated Tuwunel key import drop-in (0400)
```

Initialize the workspace directory tree:

```bash
mkdir -p /root/matrix-migration/dump/{rooms,media,accounts}
find /root/matrix-migration -type d -exec chmod 0700 {} +
cd /root/matrix-migration
```

Download the `migrator` release archive and extract the binary into `/root/matrix-migration` (set `ARCH` to `amd64` or `arm64`):

```bash
ARCH="amd64"
curl -fsSL "https://github.com/underhax/synapse-tuwunel-migration/releases/latest/download/migrator-linux-${ARCH}.tar.gz" \
  | tar -xz -C /root/matrix-migration migrator
```

Copy your Synapse server signing key (`<domain>.signing.key`) to `/root/matrix-migration/synapse.signing.key`; then set ownership and permissions:

```bash
chown root:root -R /root/matrix-migration
chmod 0500 /root/matrix-migration/migrator
chmod 0400 /root/matrix-migration/synapse.signing.key
```

Create the empty Tuwunel staging data directory (replace `/home/matrix/tuwunel/data` if your target database path differs):

```bash
mkdir -p /home/matrix/tuwunel/data
chmod 0700 /home/matrix/tuwunel/data
```

</details>

---

<details>
<summary><strong>Configuration File Preparation</strong></summary>

## Configuration File Preparation

> **Note:** Set `<DOMAIN>` to your Matrix `server_name` and `<SYNAPSE_URL>` to your full Synapse base URL (including the scheme, such as `https://matrix.example.net`) before running the substitution commands below. After substitution, only the `accounts` array in `migration.json` requires manual editing; each account may use `synapse_password` instead of `synapse_access_token` when password login is enabled. The `tuwunel.toml` and `element-config.json` files require no manual edits unless you customize staging ports or paths.

Download the example configuration templates and set ownership and permissions:

```bash
REPO="https://raw.githubusercontent.com/underhax/synapse-tuwunel-migration/main/examples"

curl -fsSL "${REPO}/migration.json" -o /root/matrix-migration/migration.json
curl -fsSL "${REPO}/element-config.json" -o /root/matrix-migration/element-config.json
curl -fsSL "${REPO}/tuwunel.toml" -o /root/matrix-migration/tuwunel.toml

chown root:root -R /root/matrix-migration
chmod 0600 /root/matrix-migration/{migration.json,tuwunel.toml}
chmod 0644 /root/matrix-migration/element-config.json
```

Generate a random shared secret (64 bytes) and substitute your domain, Synapse URL, and secret into the templates (replace `<DOMAIN>` and `<SYNAPSE_URL>` with your own values):

```bash
SERVER_NAME="<DOMAIN>"
SYNAPSE_URL="<SYNAPSE_URL>"
SHARED_SECRET="$(openssl rand -hex 64)"

sed -i "s|https://synapse\.example\.com|${SYNAPSE_URL}|g" /root/matrix-migration/migration.json
sed -i "s|example\.com|${SERVER_NAME}|g" /root/matrix-migration/{migration.json,tuwunel.toml,element-config.json}
sed -i "s|replace-with-tuwunel-registration-shared-secret|${SHARED_SECRET}|g" /root/matrix-migration/{migration.json,tuwunel.toml}
```

Each account requires its own `synapse_access_token` or `synapse_password`. When authenticating with tokens, obtain `synapse_access_token` for each account using one of the methods below:

- With MAS (Matrix Authentication Service), issue compatibility tokens on the MAS host or inside its container (`RUST_LOG=info` prints each issued token):

```bash
RUST_LOG=info mas-cli manage issue-compatibility-token alice
RUST_LOG=info mas-cli manage issue-compatibility-token bob
```

```bash
docker exec -it -e RUST_LOG=info <mas_container> mas-cli manage issue-compatibility-token <username>
```

- From Element Web, copy `Access Token` under `Settings -> Help & About -> Advanced`.
- Via the Synapse Admin API (for another user, authenticating with a Synapse admin token):

```bash
curl -sS -X POST https://synapse.example.com/_synapse/admin/v1/users/@bob:example.com/login \
  -H "Authorization: Bearer <SYNAPSE_ADMIN_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d "{\"valid_until_ms\": $(( ($(date +%s) + 86400) * 1000 ))}"
```

- Via `/_matrix/client/v3/login` (if password login is enabled on Synapse):

```bash
curl -sS -X POST https://synapse.example.com/_matrix/client/v3/login \
  -H "Content-Type: application/json" \
  -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"PASSWORD"}'
```

Each account also needs a `tuwunel_password` (permanent or temporary). Generate a strong password in your password manager (avoiding unescaped `"` or `\` in JSON strings), or reuse the account's Synapse password if desired.

### `migration.json`

Edit `/root/matrix-migration/migration.json` and populate the `accounts` array (adjust `local_room_version` or `replay_single_user_notes` if needed):

```bash
nano /root/matrix-migration/migration.json
```

Fields:

| Field | Required | Description |
| --- | --- | --- |
| `server_name` | Yes | Shared Matrix server domain |
| `synapse_url` | Yes | Synapse Client-Server API base URL |
| `tuwunel_url` | Yes | Staging loopback URL `http://127.0.0.1:18008` for steps 1–6; update to `https://tuwunel.example.com` at step 7 before `federate-sync` and `cleanup` |
| `tuwunel_shared_secret` | Conditional | Shared secret matching `registration.shared_secret` in `tuwunel.toml`; required when any account has `exists_on_tuwunel: false` |
| `data_dir` | Yes | Dump directory path inside `/root/matrix-migration`; do not change `"./dump"`, and always `cd /root/matrix-migration` before running `./migrator` |
| `local_room_version` | No | Room version for recreated local rooms and Spaces (`"12"` when omitted) |
| `replay_single_user_notes` | No | Decrypts and replays pure single-user note rooms (`true` in the template; `false` when omitted) |
| `accounts` | Yes | Ordered non-empty list of accounts to migrate; put the primary admin first with `admin: true` |
| `accounts[].user_id` | Yes | Full MXID matching `server_name` |
| `accounts[].synapse_access_token` | Conditional | Bearer token for this `user_id` on Synapse or MAS (recommended; skips `/login` and `/logout`; required if `synapse_password` is omitted) |
| `accounts[].synapse_password` | Conditional | Synapse password when password login is enabled (required if `synapse_access_token` is omitted) |
| `accounts[].tuwunel_password` | Yes | Tuwunel account password for `import-local` registration/UIA, `federate-sync`, and the step 6 browser check (permanent or temporary; may match the Synapse password) |
| `accounts[].recovery_key` | Yes | Account's existing Synapse Base58 SSSS Recovery Key (`EsT...`) for identity and backup restoration |
| `accounts[].admin` | No | Grants server admin privileges on Tuwunel registration (`false` when omitted) |
| `accounts[].exists_on_tuwunel` | No | Skips registration and uses `/login` if the account already exists on Tuwunel (`false` when omitted) |

</details>

---

<details>
<summary><strong>Migration Steps</strong></summary>

CLI Flags:

- `--mode`: Execution phase (`prepare-signing-key`, `export`, `import-local`, `federate-sync`, `cleanup`).
- `--config`: Path to the JSON manifest (`0400` or `0600`).
- `--replay-notes`: Override `replay_single_user_notes` for the current command.
- `--debug`: Enable debug logging (`--debug=2` for trace).
- `--json`: Emit JSON logs on `stderr`.
- `--version`: Print version and exit.

## Migration Steps

1. Prepare the Synapse signing key:

   ```bash
   ./migrator --mode prepare-signing-key --config migration.json
   ```

2. Import the signing key offline into the empty `/home/matrix/tuwunel/data` directory:

   ```bash
   docker run --rm --user 0:0 \
     -v /root/matrix-migration/tuwunel.toml:/etc/tuwunel/tuwunel.toml:ro \
     -v /root/matrix-migration/dump/tuwunel-import-key.toml:/etc/tuwunel/tuwunel-import-key.toml:ro \
     -v /home/matrix/tuwunel/data:/var/lib/tuwunel:rw \
     ghcr.io/matrix-construct/tuwunel:latest \
     --maintenance \
     -c /etc/tuwunel/tuwunel.toml \
     -c /etc/tuwunel/tuwunel-import-key.toml
   ```

3. Start staging Tuwunel:

   ```bash
   docker run -d \
     --name matrix-tuwunel-staging \
     --hostname matrix-tuwunel \
     --user 0:0 \
     -p 127.0.0.1:18008:8008 \
     -e TUWUNEL_CONFIG=/etc/tuwunel/tuwunel.toml \
     -v /root/matrix-migration/tuwunel.toml:/etc/tuwunel/tuwunel.toml:ro \
     -v /home/matrix/tuwunel/data:/var/lib/tuwunel:rw \
     ghcr.io/matrix-construct/tuwunel:latest
   ```

   Wait until the container reports `(healthy)` and verify the HTTP listener:

   ```bash
   docker ps --filter name=matrix-tuwunel-staging
   docker logs matrix-tuwunel-staging
   ```

4. Export from live Synapse, and stop Synapse immediately after the export succeeds:

   ```bash
   ./migrator --mode export --config migration.json
   ```

5. Run local import on staging Tuwunel:

   ```bash
   ./migrator --mode import-local --config migration.json
   ```

6. Verify local rooms, personal notes, and green verification shields in a temporary Element Web container over an SSH tunnel (`127.0.0.1` provides a WebCrypto Secure Context for E2EE without TLS).

   Start the temporary Element Web container on the server:

   ```bash
   docker run -d \
     --name matrix-element-staging \
     -e ELEMENT_WEB_PORT=8080 \
     -p 127.0.0.1:18080:8080 \
     -v /root/matrix-migration/element-config.json:/app/config.json:ro \
     ghcr.io/element-hq/element-web:latest
   ```

   Forward both ports from your workstation and open `http://127.0.0.1:18080` (sign in with `tuwunel_password` and your Recovery Key):

   ```bash
   ssh -N -p <ssh_port> -i <ssh_key> -L 18080:127.0.0.1:18080 -L 18008:127.0.0.1:18008 root@<server>
   ```

   Log out of the test sessions in Element Web and remove `matrix-element-staging` (do not run `--mode cleanup` yet so `session.json` tokens remain available for `federate-sync`):

   ```bash
   docker stop matrix-element-staging
   docker rm matrix-element-staging
   ```

7. Decommission staging Tuwunel and prepare production data:

   ```bash
   docker stop matrix-tuwunel-staging
   docker rm matrix-tuwunel-staging
   chown -R matrix:matrix /home/matrix/tuwunel/data
   find /home/matrix/tuwunel/data -type d -exec chmod 0700 {} +
   find /home/matrix/tuwunel/data -type f -exec chmod 0600 {} +
   ```

   Keep Synapse stopped, start production Tuwunel (Docker Compose), point `Angie` (`tuwunel.example.com` and `example.com/.well-known/matrix/*`, blocking `/_synapse/`) to production Tuwunel, and set `"tuwunel_url"` in `migration.json` to `"https://tuwunel.example.com"` (preserving mode `0600`).

8. Run federation sync against the live production stack:

   ```bash
   ./migrator --mode federate-sync --config migration.json
   ```

9. Revoke temporary CLI tokens and remove `/root/matrix-migration`:

   ```bash
   ./migrator --mode cleanup --config migration.json
   cd /root
   rm -rf /root/matrix-migration
   ```

</details>
