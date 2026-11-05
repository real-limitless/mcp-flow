# Secrets restore drill

This is the procedure ops will run. It is not a startup check and it is not a merge gate for the secrets store.

The KEK, the keyring, and the API-key pepper are escrowed offline and kept separate from database backups. Share holders are recorded by name in ops records outside this repo. No secret value, hostname, or address belongs in this file.

## Before the drill

1. On the gateway host, generate the KEK with the OS CSPRNG into a mode-0400 file owned by the gateway user. The path is `MCP_FLOW_KEK_FILE`. Do not put the KEK in an environment variable or in a deployment platform's env UI.
2. Initialize the keyring (`mcp-flow keyring init`) so each purpose, including the secrets index, is a distinct file wrapped by that KEK.
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
