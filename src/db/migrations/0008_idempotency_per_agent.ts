/**
 * 0008 (Security T2.5 Re-review 2, R2-1): idempotency keys are unique per AGENT, not per API key,
 * so a re-send on a rotated key replays instead of running again. The old (agent, key, idem)
 * UNIQUE stays; this one is strictly narrower.
 */
export const MIGRATION_0008 = `
CREATE UNIQUE INDEX mcpflow_call_outcome_idem_agent
  ON mcpflow_call_outcome(agent_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
`;
