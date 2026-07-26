DO $$
DECLARE
  role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'aios_c07_owner',
    'aios_c07_lifecycle_runtime',
    'aios_c07_data_runtime',
    'aios_c07_scope_runtime',
    'aios_c07_restore_runtime',
    'aios_c18_owner',
    'aios_c18_writer',
    'aios_c18_reader',
    'aios_c18_outbox_worker',
    'aios_c18_recovery_reader',
    'aios_c18_recovery_writer',
    'aios_c18_retention_worker',
    'aios_c15_owner',
    'aios_c15_runtime',
    'aios_c15_effect_worker',
    'aios_c15_audit_worker',
    'aios_c15_recovery_reader'
  ]
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_roles WHERE rolname = role_name
    ) THEN
      EXECUTE format(
        'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
        'NOINHERIT NOREPLICATION NOBYPASSRLS',
        role_name
      );
    END IF;
  END LOOP;
END;
$$;
