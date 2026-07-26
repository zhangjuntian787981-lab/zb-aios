BEGIN;

CREATE ROLE aios_c15_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;
CREATE ROLE aios_c15_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;
CREATE ROLE aios_c15_effect_worker
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;
CREATE ROLE aios_c15_audit_worker
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;
CREATE ROLE aios_c15_recovery_reader
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_core FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_core FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_core FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_core FROM PUBLIC;

REVOKE ALL ON SCHEMA aios_decision FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_decision FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_decision FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_decision FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_decision
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_decision
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_decision
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER SCHEMA aios_decision OWNER TO aios_c15_owner;
ALTER TABLE aios_decision.draft_artifact OWNER TO aios_c15_owner;
ALTER TABLE aios_decision.synthetic_test_decision OWNER TO aios_c15_owner;
ALTER TABLE aios_decision.decision_withdrawal OWNER TO aios_c15_owner;
ALTER TABLE aios_decision.workflow_effect OWNER TO aios_c15_owner;
ALTER TABLE aios_decision.effect_outbox OWNER TO aios_c15_owner;
ALTER TABLE aios_decision.audit_intent OWNER TO aios_c15_owner;
ALTER TABLE aios_decision.audit_outbox OWNER TO aios_c15_owner;
ALTER TABLE aios_decision.command_receipt OWNER TO aios_c15_owner;
ALTER FUNCTION aios_decision.valid_audit_intent(jsonb)
  OWNER TO aios_c15_owner;
ALTER FUNCTION aios_decision.reject_append_only_change()
  OWNER TO aios_c15_owner;
ALTER FUNCTION aios_decision.enforce_command_receipt_pair()
  OWNER TO aios_c15_owner;
ALTER FUNCTION aios_decision.enforce_effect_transition()
  OWNER TO aios_c15_owner;
ALTER FUNCTION aios_decision.enforce_outbox_transition()
  OWNER TO aios_c15_owner;

CREATE POLICY c15_artifact_owner ON aios_decision.draft_artifact
  TO aios_c15_owner USING (true) WITH CHECK (true);
CREATE POLICY c15_artifact_runtime ON aios_decision.draft_artifact
  TO aios_c15_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_artifact_recovery ON aios_decision.draft_artifact
  FOR SELECT TO aios_c15_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY c15_decision_owner
  ON aios_decision.synthetic_test_decision
  TO aios_c15_owner USING (true) WITH CHECK (true);
CREATE POLICY c15_decision_runtime
  ON aios_decision.synthetic_test_decision
  TO aios_c15_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_decision_recovery
  ON aios_decision.synthetic_test_decision
  FOR SELECT TO aios_c15_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY c15_withdrawal_owner
  ON aios_decision.decision_withdrawal
  TO aios_c15_owner USING (true) WITH CHECK (true);
CREATE POLICY c15_withdrawal_runtime
  ON aios_decision.decision_withdrawal
  TO aios_c15_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_withdrawal_recovery
  ON aios_decision.decision_withdrawal
  FOR SELECT TO aios_c15_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY c15_effect_owner ON aios_decision.workflow_effect
  TO aios_c15_owner USING (true) WITH CHECK (true);
CREATE POLICY c15_effect_runtime ON aios_decision.workflow_effect
  TO aios_c15_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_effect_worker ON aios_decision.workflow_effect
  TO aios_c15_effect_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_effect_recovery ON aios_decision.workflow_effect
  FOR SELECT TO aios_c15_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY c15_effect_outbox_owner
  ON aios_decision.effect_outbox
  TO aios_c15_owner USING (true) WITH CHECK (true);
CREATE POLICY c15_effect_outbox_runtime
  ON aios_decision.effect_outbox FOR INSERT TO aios_c15_runtime
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_effect_outbox_worker
  ON aios_decision.effect_outbox TO aios_c15_effect_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_effect_outbox_recovery
  ON aios_decision.effect_outbox
  FOR SELECT TO aios_c15_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY c15_audit_intent_owner
  ON aios_decision.audit_intent
  TO aios_c15_owner USING (true) WITH CHECK (true);
CREATE POLICY c15_audit_intent_runtime
  ON aios_decision.audit_intent FOR INSERT TO aios_c15_runtime
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_audit_intent_effect_worker
  ON aios_decision.audit_intent FOR INSERT TO aios_c15_effect_worker
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_audit_intent_audit_worker
  ON aios_decision.audit_intent FOR SELECT TO aios_c15_audit_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_audit_intent_recovery
  ON aios_decision.audit_intent FOR SELECT TO aios_c15_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY c15_audit_outbox_owner
  ON aios_decision.audit_outbox
  TO aios_c15_owner USING (true) WITH CHECK (true);
CREATE POLICY c15_audit_outbox_runtime
  ON aios_decision.audit_outbox FOR INSERT TO aios_c15_runtime
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_audit_outbox_effect_worker
  ON aios_decision.audit_outbox FOR INSERT TO aios_c15_effect_worker
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_audit_outbox_audit_worker
  ON aios_decision.audit_outbox TO aios_c15_audit_worker
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_audit_outbox_recovery
  ON aios_decision.audit_outbox
  FOR SELECT TO aios_c15_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY c15_receipt_owner ON aios_decision.command_receipt
  TO aios_c15_owner USING (true) WITH CHECK (true);
CREATE POLICY c15_receipt_runtime ON aios_decision.command_receipt
  TO aios_c15_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY c15_receipt_recovery ON aios_decision.command_receipt
  FOR SELECT TO aios_c15_recovery_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_decision TO
  aios_c15_runtime,
  aios_c15_effect_worker,
  aios_c15_audit_worker,
  aios_c15_recovery_reader;
GRANT USAGE ON SCHEMA aios_data TO
  aios_c15_runtime,
  aios_c15_effect_worker,
  aios_c15_audit_worker,
  aios_c15_recovery_reader;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text) TO
  aios_c15_runtime,
  aios_c15_effect_worker,
  aios_c15_audit_worker,
  aios_c15_recovery_reader;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence() TO
  aios_c15_runtime,
  aios_c15_effect_worker,
  aios_c15_audit_worker,
  aios_c15_recovery_reader;
GRANT EXECUTE ON FUNCTION aios_decision.valid_audit_intent(jsonb) TO
  aios_c15_runtime,
  aios_c15_effect_worker;

GRANT SELECT, INSERT ON TABLE
  aios_decision.draft_artifact,
  aios_decision.synthetic_test_decision,
  aios_decision.decision_withdrawal,
  aios_decision.workflow_effect,
  aios_decision.command_receipt
TO aios_c15_runtime;
GRANT INSERT ON TABLE
  aios_decision.effect_outbox,
  aios_decision.audit_intent,
  aios_decision.audit_outbox
TO aios_c15_runtime;

GRANT SELECT, UPDATE ON TABLE
  aios_decision.workflow_effect,
  aios_decision.effect_outbox
TO aios_c15_effect_worker;
GRANT INSERT ON TABLE
  aios_decision.audit_intent,
  aios_decision.audit_outbox
TO aios_c15_effect_worker;

GRANT SELECT ON TABLE aios_decision.audit_intent
  TO aios_c15_audit_worker;
GRANT SELECT, UPDATE ON TABLE aios_decision.audit_outbox
  TO aios_c15_audit_worker;

GRANT SELECT ON ALL TABLES IN SCHEMA aios_decision
  TO aios_c15_recovery_reader;

COMMIT;
