DO $$
DECLARE
  role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'aios_c05_core_runtime',
    'aios_c05_outbox_worker',
    'aios_c07_owner',
    'aios_c07_lifecycle_runtime',
    'aios_c07_data_runtime',
    'aios_c07_scope_runtime',
    'aios_c07_restore_runtime',
    'aios_c09_owner',
    'aios_c09_runtime',
    'aios_c09_scope_runtime',
    'aios_c09_retention_runtime'
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
