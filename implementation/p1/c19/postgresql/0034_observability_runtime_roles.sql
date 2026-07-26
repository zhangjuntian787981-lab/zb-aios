BEGIN;

CREATE ROLE aios_c19_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c19_writer
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE aios_c19_reader
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS;

REVOKE ALL ON SCHEMA aios_observability FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA aios_observability FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA aios_observability FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_observability FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA aios_observability
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_observability
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA aios_observability
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;

ALTER SCHEMA aios_observability OWNER TO aios_c19_owner;
ALTER TABLE aios_observability.telemetry_signal
  OWNER TO aios_c19_owner;
ALTER TABLE aios_observability.quota_account
  OWNER TO aios_c19_owner;
ALTER TABLE aios_observability.quota_reservation
  OWNER TO aios_c19_owner;
ALTER TABLE aios_observability.usage_ledger
  OWNER TO aios_c19_owner;
ALTER FUNCTION aios_observability.reject_append_only_change()
  OWNER TO aios_c19_owner;
ALTER FUNCTION aios_observability.enforce_reservation_transition()
  OWNER TO aios_c19_owner;
ALTER FUNCTION aios_observability.enforce_quota_account_transition()
  OWNER TO aios_c19_owner;
ALTER FUNCTION aios_observability.validate_usage_ledger_event()
  OWNER TO aios_c19_owner;
ALTER FUNCTION aios_observability.validate_quota_account_balance()
  OWNER TO aios_c19_owner;

CREATE POLICY telemetry_owner_policy
  ON aios_observability.telemetry_signal TO aios_c19_owner
  USING (true) WITH CHECK (true);
CREATE POLICY telemetry_writer_insert_policy
  ON aios_observability.telemetry_signal
  FOR INSERT TO aios_c19_writer
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY telemetry_writer_select_policy
  ON aios_observability.telemetry_signal
  FOR SELECT TO aios_c19_writer
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY telemetry_reader_policy
  ON aios_observability.telemetry_signal
  FOR SELECT TO aios_c19_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY quota_account_owner_policy
  ON aios_observability.quota_account TO aios_c19_owner
  USING (true) WITH CHECK (true);
CREATE POLICY quota_account_writer_policy
  ON aios_observability.quota_account TO aios_c19_writer
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY quota_account_reader_policy
  ON aios_observability.quota_account
  FOR SELECT TO aios_c19_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY reservation_owner_policy
  ON aios_observability.quota_reservation TO aios_c19_owner
  USING (true) WITH CHECK (true);
CREATE POLICY reservation_writer_policy
  ON aios_observability.quota_reservation TO aios_c19_writer
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind))
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY reservation_reader_policy
  ON aios_observability.quota_reservation
  FOR SELECT TO aios_c19_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

CREATE POLICY ledger_owner_policy
  ON aios_observability.usage_ledger TO aios_c19_owner
  USING (true) WITH CHECK (true);
CREATE POLICY ledger_writer_insert_policy
  ON aios_observability.usage_ledger
  FOR INSERT TO aios_c19_writer
  WITH CHECK (aios_data.runtime_scope_allows(tenant_id, tenant_kind));
CREATE POLICY ledger_reader_policy
  ON aios_observability.usage_ledger
  FOR SELECT TO aios_c19_reader
  USING (aios_data.runtime_scope_allows(tenant_id, tenant_kind));

GRANT USAGE ON SCHEMA aios_observability
  TO aios_c19_writer, aios_c19_reader;
GRANT USAGE ON SCHEMA aios_data
  TO aios_c19_writer, aios_c19_reader;
GRANT EXECUTE ON FUNCTION
  aios_data.runtime_scope_allows(text, text),
  aios_data.acquire_runtime_fence()
TO aios_c19_writer, aios_c19_reader;

GRANT SELECT, INSERT ON TABLE
  aios_observability.telemetry_signal
TO aios_c19_writer;
GRANT INSERT ON TABLE aios_observability.usage_ledger
  TO aios_c19_writer;
GRANT SELECT, INSERT, UPDATE ON TABLE
  aios_observability.quota_account,
  aios_observability.quota_reservation
TO aios_c19_writer;
GRANT SELECT ON TABLE
  aios_observability.telemetry_signal,
  aios_observability.quota_account,
  aios_observability.quota_reservation,
  aios_observability.usage_ledger
TO aios_c19_reader;

COMMIT;
