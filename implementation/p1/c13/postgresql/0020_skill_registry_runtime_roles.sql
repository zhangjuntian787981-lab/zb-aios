BEGIN;

CREATE ROLE aios_c13_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c13_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_skill FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_skill FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_skill FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA aios_skill
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_skill
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER SCHEMA aios_skill OWNER TO aios_c13_owner;
ALTER TABLE aios_skill.skill_release OWNER TO aios_c13_owner;
ALTER TABLE aios_skill.skill_channel OWNER TO aios_c13_owner;
ALTER TABLE aios_skill.skill_event OWNER TO aios_c13_owner;
ALTER TABLE aios_skill.command_receipt OWNER TO aios_c13_owner;
ALTER FUNCTION aios_skill.reject_append_only_change()
  OWNER TO aios_c13_owner;
ALTER FUNCTION aios_skill.enforce_release_update()
  OWNER TO aios_c13_owner;
ALTER FUNCTION aios_skill.enforce_channel_update()
  OWNER TO aios_c13_owner;

CREATE POLICY skill_release_owner_policy
  ON aios_skill.skill_release TO aios_c13_owner
  USING (true) WITH CHECK (true);
CREATE POLICY skill_release_runtime_policy
  ON aios_skill.skill_release TO aios_c13_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY skill_channel_owner_policy
  ON aios_skill.skill_channel TO aios_c13_owner
  USING (true) WITH CHECK (true);
CREATE POLICY skill_channel_runtime_policy
  ON aios_skill.skill_channel TO aios_c13_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY skill_event_owner_policy
  ON aios_skill.skill_event TO aios_c13_owner
  USING (true) WITH CHECK (true);
CREATE POLICY skill_event_runtime_policy
  ON aios_skill.skill_event TO aios_c13_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY skill_receipt_owner_policy
  ON aios_skill.command_receipt TO aios_c13_owner
  USING (true) WITH CHECK (true);
CREATE POLICY skill_receipt_runtime_policy
  ON aios_skill.command_receipt TO aios_c13_runtime
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_skill, aios_data TO aios_c13_runtime;
GRANT EXECUTE ON FUNCTION aios_data.runtime_scope_allows(text, text)
  TO aios_c13_runtime;
GRANT EXECUTE ON FUNCTION aios_data.acquire_runtime_fence()
  TO aios_c13_runtime;

GRANT SELECT, INSERT, UPDATE ON TABLE
  aios_skill.skill_release,
  aios_skill.skill_channel
TO aios_c13_runtime;

GRANT SELECT, INSERT ON TABLE
  aios_skill.skill_event,
  aios_skill.command_receipt
TO aios_c13_runtime;

COMMIT;
