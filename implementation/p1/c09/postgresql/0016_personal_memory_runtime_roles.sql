BEGIN;

CREATE ROLE aios_c09_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c09_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c09_scope_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;
CREATE ROLE aios_c09_retention_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_personal_memory FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_personal_memory FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_personal_memory FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_personal_memory FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA aios_personal_memory
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_personal_memory
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_personal_memory
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER SCHEMA aios_personal_memory OWNER TO aios_c09_owner;
ALTER TABLE aios_personal_memory.personal_scope_signing_secret
  OWNER TO aios_c09_owner;
ALTER TABLE aios_personal_memory.personal_profile
  OWNER TO aios_c09_owner;
ALTER TABLE aios_personal_memory.personal_memory
  OWNER TO aios_c09_owner;
ALTER TABLE aios_personal_memory.conversation_checkpoint
  OWNER TO aios_c09_owner;
ALTER TABLE aios_personal_memory.memory_event
  OWNER TO aios_c09_owner;
ALTER TABLE aios_personal_memory.command_receipt
  OWNER TO aios_c09_owner;

ALTER FUNCTION aios_personal_memory.issue_principal_scope_signature(
  text, text, text, bigint, bigint, integer, xid8, integer, uuid
) OWNER TO aios_c09_owner;
ALTER FUNCTION aios_personal_memory.runtime_principal_allows(
  text, text, text
) OWNER TO aios_c09_owner;
ALTER FUNCTION aios_personal_memory.reject_append_only_change()
  OWNER TO aios_c09_owner;
ALTER FUNCTION aios_personal_memory.reject_row_delete()
  OWNER TO aios_c09_owner;
ALTER FUNCTION aios_personal_memory.enforce_profile_update()
  OWNER TO aios_c09_owner;
ALTER FUNCTION aios_personal_memory.enforce_memory_update()
  OWNER TO aios_c09_owner;
ALTER FUNCTION aios_personal_memory.enforce_checkpoint_update()
  OWNER TO aios_c09_owner;
ALTER FUNCTION aios_personal_memory.materialize_due_expiry(
  text,
  text,
  bigint,
  text,
  text,
  text,
  text,
  text,
  bigint,
  bigint,
  jsonb
) OWNER TO aios_c09_owner;

CREATE POLICY personal_profile_owner_policy
  ON aios_personal_memory.personal_profile
  TO aios_c09_owner
  USING (true)
  WITH CHECK (true);
CREATE POLICY personal_profile_runtime_policy
  ON aios_personal_memory.personal_profile
  TO aios_c09_runtime
  USING (
    aios_personal_memory.runtime_principal_allows(
      tenant_id,
      tenant_kind,
      principal_id
    )
  )
  WITH CHECK (
    aios_personal_memory.runtime_principal_allows(
      tenant_id,
      tenant_kind,
      principal_id
    )
  );

CREATE POLICY personal_memory_owner_policy
  ON aios_personal_memory.personal_memory
  TO aios_c09_owner
  USING (true)
  WITH CHECK (true);
CREATE POLICY personal_memory_runtime_policy
  ON aios_personal_memory.personal_memory
  TO aios_c09_runtime
  USING (
    aios_personal_memory.runtime_principal_allows(
      tenant_id,
      tenant_kind,
      principal_id
    )
  )
  WITH CHECK (
    aios_personal_memory.runtime_principal_allows(
      tenant_id,
      tenant_kind,
      principal_id
    )
  );

CREATE POLICY conversation_checkpoint_owner_policy
  ON aios_personal_memory.conversation_checkpoint
  TO aios_c09_owner
  USING (true)
  WITH CHECK (true);
CREATE POLICY conversation_checkpoint_runtime_policy
  ON aios_personal_memory.conversation_checkpoint
  TO aios_c09_runtime
  USING (
    aios_personal_memory.runtime_principal_allows(
      tenant_id,
      tenant_kind,
      principal_id
    )
  )
  WITH CHECK (
    aios_personal_memory.runtime_principal_allows(
      tenant_id,
      tenant_kind,
      principal_id
    )
  );

CREATE POLICY memory_event_owner_policy
  ON aios_personal_memory.memory_event
  TO aios_c09_owner
  USING (true)
  WITH CHECK (true);
CREATE POLICY memory_event_runtime_policy
  ON aios_personal_memory.memory_event
  TO aios_c09_runtime
  USING (
    aios_personal_memory.runtime_principal_allows(
      tenant_id,
      tenant_kind,
      principal_id
    )
  )
  WITH CHECK (
    aios_personal_memory.runtime_principal_allows(
      tenant_id,
      tenant_kind,
      principal_id
    )
  );

CREATE POLICY command_receipt_owner_policy
  ON aios_personal_memory.command_receipt
  TO aios_c09_owner
  USING (true)
  WITH CHECK (true);
CREATE POLICY command_receipt_runtime_policy
  ON aios_personal_memory.command_receipt
  TO aios_c09_runtime
  USING (
    aios_personal_memory.runtime_principal_allows(
      tenant_id,
      tenant_kind,
      principal_id
    )
  )
  WITH CHECK (
    aios_personal_memory.runtime_principal_allows(
      tenant_id,
      tenant_kind,
      principal_id
    )
  );

GRANT USAGE ON SCHEMA aios_personal_memory TO
  aios_c09_runtime,
  aios_c09_scope_runtime,
  aios_c09_retention_runtime;
GRANT USAGE ON SCHEMA aios_core TO aios_c09_owner;
GRANT USAGE ON SCHEMA aios_data TO
  aios_c09_owner,
  aios_c09_runtime,
  aios_c09_retention_runtime;
GRANT SELECT ON aios_core.principal_registry TO aios_c09_owner;

GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text)
  TO aios_c09_owner, aios_c09_runtime;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence()
  TO aios_c09_runtime, aios_c09_retention_runtime;
GRANT EXECUTE ON FUNCTION
  aios_personal_memory.runtime_principal_allows(text, text, text)
  TO aios_c09_runtime;
GRANT EXECUTE ON FUNCTION
  aios_personal_memory.issue_principal_scope_signature(
    text, text, text, bigint, bigint, integer, xid8, integer, uuid
  )
  TO aios_c09_scope_runtime;
GRANT EXECUTE ON FUNCTION aios_personal_memory.materialize_due_expiry(
  text,
  text,
  bigint,
  text,
  text,
  text,
  text,
  text,
  bigint,
  bigint,
  jsonb
) TO aios_c09_retention_runtime;

GRANT SELECT, INSERT, UPDATE ON
  aios_personal_memory.personal_profile,
  aios_personal_memory.personal_memory,
  aios_personal_memory.conversation_checkpoint
  TO aios_c09_runtime;

GRANT SELECT, INSERT ON
  aios_personal_memory.memory_event,
  aios_personal_memory.command_receipt
  TO aios_c09_runtime;

COMMIT;
