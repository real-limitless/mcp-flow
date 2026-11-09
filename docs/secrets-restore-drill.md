# Secrets restore drill

This is the procedure ops will run. It is not a startup check and it is not a merge gate for the secrets store.

The KEK, the keyring, and the API-key pepper are escrowed offline and kept separate from database backups. Share holders are recorded by name in ops records outside this repo. No secret value, hostname, or address belongs in this file.

## First boot

Production (`MCP_FLOW_PRODUCTION=true` or `NODE_ENV=production`, which the gateway image sets) needs three pieces on the data volume. None of them is an environment value.

| Piece | Where it lives | Variable |
| --- | --- | --- |
| Keyring directory | A directory of wrapped per-purpose files, mode 0700 when this process creates it | `MCP_FLOW_KEYRING_DIR` |
| KEK file | 32 bytes, mode 0400 | `MCP_FLOW_KEK_FILE` |
| Pepper | Wrapped file named `pepper` inside the keyring directory | (no variable; it is not `MCP_FLOW_PEPPER`) |

When those paths are unset, production defaults them to `keyring/` and `kek` beside the data directory (`MCP_FLOW_DATA_DIR`, or the directory that contains the database). Compose and the gateway image point them at `/data/keyring` and `/data/kek` on the named data volume.

On first boot the gateway entrypoint, before `serve`, creates whatever is missing when the volume has no sealed material: the directory, the KEK file, and the pepper plus the other purpose files. A later start does not overwrite the KEK, does not rewrite an existing pepper, and does not pass a new-pepper mint when `pepper` is already there. Leave `MCP_FLOW_KEK` unset. Production still refuses an environment or HKDF KEK.

If the KEK file is missing and the keyring directory or the database already holds sealed material, or if `pepper` is missing and API key or session hashes already exist, startup prints one error and exits. It does not mint a replacement. Restore the escrowed KEK and the keyring directory, including `pepper`. After the first successful boot, escrow that KEK and the whole keyring directory. This drill restores an existing KEK; it does not replace one.

## Before the drill

1. On the gateway host, confirm the KEK file at `MCP_FLOW_KEK_FILE` (mode 0400, 32 bytes) and the `pepper` file inside `MCP_FLOW_KEYRING_DIR`. First boot creates them when the volume is empty. Do not generate a second KEK or a second pepper when sealed rows or API key hashes already exist. Do not put the KEK in an environment variable or in a deployment platform's env UI.
2. Confirm each purpose file is present, including the secrets index. First boot writes any purpose file that is missing when that is safe. Do not replace a purpose file that is already there.
3. Create one canary secret with `mf_secret_create` (or `POST /v1/secrets`) and record its ref and version. Do not record the value.
4. Take a database backup and a separate escrow copy of the KEK file, the keyring directory, and the pepper file.

## Drill

1. Restore the database backup on a scratch host that is not serving traffic.
2. Restore the KEK file, the keyring directory, and the pepper from escrow. The KEK file must be mode 0400.
3. Point `MCP_FLOW_DB_PATH`, `MCP_FLOW_KEYRING_DIR`, and `MCP_FLOW_KEK_FILE` at the restored files. Leave `MCP_FLOW_KEK` unset.
4. Open the database and confirm the canary row: `kek_id` is `file:kek:v1` (or the configured KMS id), `ciphertext` and `wrapped_dek` are non-null, and `state` is `active`.
5. Unwrap the canary DEK with the restored KEK and open the ciphertext with AAD `mcp-flow/secret/v1|<workspace>|<project>|<secret id>|<version>`. The DEK wrap AAD is `mcp-flow/dek/v1|<secret id>|<version>|<kek id>`. Success is a decrypted value. Failure means escrow or the backup is wrong.
6. Do not print the value into a ticket, a log, or a chat. Destroy the scratch copy when the drill is recorded.

Printing the value through the gateway waits on the reveal tool. This store does not expose one.

## After a KEK change

Rewrap of existing DEKs is a later host CLI. Until that exists, keep the KEK that wrapped the canary in escrow. Production still refuses an environment or HKDF KEK.
