BEGIN;

GRANT USAGE ON SCHEMA aios_core TO aios_c07_owner;
GRANT SELECT (
  event_id, tenant_id, tenant_kind, event, created_at
) ON aios_core.tenant_lifecycle_event TO aios_c07_owner;
GRANT SELECT (
  event_id, tenant_id, tenant_kind, event, created_at
) ON aios_core.tenant_outbox TO aios_c07_owner;
GRANT SELECT (
  tenant_id, tenant_kind, state, lifecycle_version, generation, operation_id
) ON aios_core.tenant_registry TO aios_c07_owner;

CREATE FUNCTION aios_data.project_tenant_lifecycle_event(event_id text)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  source_record record;
  outbox_record record;
  registry_record record;
  lifecycle_record record;
  receipt_record record;
  source_event jsonb;
  source_event_sha256 text;
  event_type text;
  next_state text;
  next_lifecycle_version bigint;
  next_generation bigint;
  next_operation_id text;
  starts_projection boolean;
  canonical_event text := '';
  stack_items jsonb[];
  stack_item jsonb;
  stack_size integer;
  stack_value jsonb;
  stack_value_type text;
  object_keys text[];
  object_key text;
  object_index integer;
  array_values jsonb[];
  array_value jsonb;
  array_index integer;
BEGIN
  IF
    event_id IS NULL
    OR event_id = ''
    OR NOT pg_has_role(
      session_user,
      'aios_c07_lifecycle_runtime',
      'MEMBER'
    )
    OR pg_has_role(session_user, 'aios_c07_owner', 'MEMBER')
    OR pg_has_role(session_user, 'aios_c07_data_runtime', 'MEMBER')
    OR pg_has_role(session_user, 'aios_c07_scope_runtime', 'MEMBER')
    OR pg_has_role(session_user, 'aios_c07_restore_runtime', 'MEMBER')
  THEN
    RAISE EXCEPTION 'lifecycle projection caller is not authorized'
      USING ERRCODE = '42501';
  END IF;

  SELECT
    source.event_id,
    source.tenant_id,
    source.tenant_kind,
    source.event,
    source.created_at
    INTO source_record
    FROM aios_core.tenant_lifecycle_event AS source
   WHERE source.event_id = project_tenant_lifecycle_event.event_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'lifecycle event does not exist'
      USING ERRCODE = 'P0701';
  END IF;

  SELECT
    outbox.event_id,
    outbox.tenant_id,
    outbox.tenant_kind,
    outbox.event,
    outbox.created_at
    INTO outbox_record
    FROM aios_core.tenant_outbox AS outbox
   WHERE outbox.event_id = project_tenant_lifecycle_event.event_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'lifecycle outbox evidence does not exist'
      USING ERRCODE = 'P0701';
  END IF;

  IF
    outbox_record.event_id IS DISTINCT FROM source_record.event_id
    OR outbox_record.tenant_id IS DISTINCT FROM source_record.tenant_id
    OR outbox_record.tenant_kind IS DISTINCT FROM source_record.tenant_kind
    OR outbox_record.event IS DISTINCT FROM source_record.event
    OR outbox_record.created_at IS DISTINCT FROM source_record.created_at
  THEN
    RAISE EXCEPTION 'lifecycle event and outbox evidence conflict'
      USING ERRCODE = 'P0703';
  END IF;

  source_event := source_record.event;
  IF
    source_record.tenant_kind IS DISTINCT FROM 'SYNTHETIC'
    OR source_event ->> 'id' IS DISTINCT FROM source_record.event_id
    OR source_event ->> 'subject' IS DISTINCT FROM source_record.tenant_id
    OR source_event ->> 'tenantkind' IS DISTINCT FROM source_record.tenant_kind
    OR source_event #>> '{data,tenant_id}'
      IS DISTINCT FROM source_record.tenant_id
    OR source_event ->> 'specversion' IS DISTINCT FROM '1.0'
    OR source_event ->> 'source'
      IS DISTINCT FROM '/aios-core/tenant-registry'
    OR source_event -> 'synthetic' IS DISTINCT FROM 'true'::jsonb
    OR jsonb_typeof(source_event -> 'data') IS DISTINCT FROM 'object'
    OR jsonb_typeof(source_event #> '{data,lifecycle_version}')
      IS DISTINCT FROM 'number'
    OR source_event #>> '{data,lifecycle_version}' !~ '^[1-9][0-9]*$'
    OR jsonb_typeof(source_event #> '{data,generation}')
      IS DISTINCT FROM 'number'
    OR source_event #>> '{data,generation}' !~ '^[1-9][0-9]*$'
    OR jsonb_typeof(source_event #> '{data,operation_id}')
      IS DISTINCT FROM 'string'
    OR source_event #>> '{data,operation_id}' = ''
    OR jsonb_typeof(source_event #> '{data,state}')
      IS DISTINCT FROM 'string'
  THEN
    RAISE EXCEPTION 'lifecycle event evidence is invalid'
      USING ERRCODE = 'P0701';
  END IF;

  event_type := source_event ->> 'type';
  next_state := source_event #>> '{data,state}';
  IF next_state IS DISTINCT FROM (CASE event_type
    WHEN 'product.tenant.provisioning-requested.v1' THEN 'PROVISIONING'
    WHEN 'product.tenant.activated.v1' THEN 'ACTIVE'
    WHEN 'product.tenant.suspended.v1' THEN 'SUSPENDED'
    WHEN 'product.tenant.resume-requested.v1' THEN 'PROVISIONING'
    WHEN 'product.tenant.deletion-requested.v1' THEN 'DELETING'
    WHEN 'product.tenant.deleted.v1' THEN 'DELETED'
    ELSE NULL
  END) THEN
    RAISE EXCEPTION 'lifecycle event type and state conflict'
      USING ERRCODE = 'P0701';
  END IF;

  next_lifecycle_version :=
    (source_event #>> '{data,lifecycle_version}')::bigint;
  next_generation := (source_event #>> '{data,generation}')::bigint;
  next_operation_id := source_event #>> '{data,operation_id}';

  stack_items := ARRAY[
    jsonb_build_object('kind', 'VALUE', 'value', source_event)
  ];
  WHILE cardinality(stack_items) > 0 LOOP
    stack_size := cardinality(stack_items);
    stack_item := stack_items[stack_size];
    IF stack_size = 1 THEN
      stack_items := ARRAY[]::jsonb[];
    ELSE
      stack_items := stack_items[1:stack_size - 1];
    END IF;

    IF stack_item ->> 'kind' = 'TOKEN' THEN
      canonical_event := canonical_event || (stack_item ->> 'token');
      CONTINUE;
    END IF;

    stack_value := stack_item -> 'value';
    stack_value_type := jsonb_typeof(stack_value);
    IF stack_value_type = 'object' THEN
      canonical_event := canonical_event || '{';
      stack_items := array_append(
        stack_items,
        jsonb_build_object('kind', 'TOKEN', 'token', '}')
      );
      SELECT array_agg(entry.key ORDER BY entry.key DESC)
        INTO object_keys
        FROM jsonb_each(stack_value) AS entry;
      object_index := 0;
      FOREACH object_key IN ARRAY coalesce(object_keys, ARRAY[]::text[])
      LOOP
        object_index := object_index + 1;
        IF object_index > 1 THEN
          stack_items := array_append(
            stack_items,
            jsonb_build_object('kind', 'TOKEN', 'token', ',')
          );
        END IF;
        stack_items := array_append(
          stack_items,
          jsonb_build_object(
            'kind',
            'VALUE',
            'value',
            stack_value -> object_key
          )
        );
        stack_items := array_append(
          stack_items,
          jsonb_build_object(
            'kind',
            'TOKEN',
            'token',
            to_jsonb(object_key)::text || ':'
          )
        );
      END LOOP;
    ELSIF stack_value_type = 'array' THEN
      canonical_event := canonical_event || '[';
      stack_items := array_append(
        stack_items,
        jsonb_build_object('kind', 'TOKEN', 'token', ']')
      );
      SELECT array_agg(entry.value ORDER BY entry.ordinality DESC)
        INTO array_values
        FROM jsonb_array_elements(stack_value)
          WITH ORDINALITY AS entry(value, ordinality);
      array_index := 0;
      FOREACH array_value IN ARRAY coalesce(array_values, ARRAY[]::jsonb[])
      LOOP
        array_index := array_index + 1;
        IF array_index > 1 THEN
          stack_items := array_append(
            stack_items,
            jsonb_build_object('kind', 'TOKEN', 'token', ',')
          );
        END IF;
        stack_items := array_append(
          stack_items,
          jsonb_build_object('kind', 'VALUE', 'value', array_value)
        );
      END LOOP;
    ELSE
      canonical_event := canonical_event || stack_value::text;
    END IF;
  END LOOP;
  source_event_sha256 := 'sha256:' || encode(
    public.digest(convert_to(canonical_event, 'UTF8'), 'sha256'),
    'hex'
  );

  PERFORM pg_advisory_xact_lock(hashtextextended(event_id, 0));
  SELECT receipt.*
    INTO receipt_record
    FROM aios_data.tenant_data_event_receipt AS receipt
   WHERE receipt.event_id = project_tenant_lifecycle_event.event_id;
  IF FOUND THEN
    IF
      receipt_record.tenant_id IS DISTINCT FROM source_record.tenant_id
      OR receipt_record.tenant_kind IS DISTINCT FROM source_record.tenant_kind
      OR receipt_record.lifecycle_version
        IS DISTINCT FROM next_lifecycle_version
      OR receipt_record.generation IS DISTINCT FROM next_generation
      OR receipt_record.operation_id IS DISTINCT FROM next_operation_id
      OR receipt_record.event_type IS DISTINCT FROM event_type
      OR receipt_record.event_sha256 IS DISTINCT FROM source_event_sha256
      OR receipt_record.event IS DISTINCT FROM source_event
    THEN
      RAISE EXCEPTION 'lifecycle event receipt conflicts with source evidence'
        USING ERRCODE = 'P0703';
    END IF;
    RETURN jsonb_build_object(
      'tenantId', source_record.tenant_id,
      'eventId', source_record.event_id,
      'lifecycleVersion', next_lifecycle_version,
      'generation', next_generation,
      'operationId', next_operation_id,
      'state', next_state,
      'status', 'SUCCEEDED',
      'duplicate', true
    );
  END IF;

  SELECT
    registry.tenant_id,
    registry.tenant_kind,
    registry.state,
    registry.lifecycle_version,
    registry.generation,
    registry.operation_id
   INTO registry_record
    FROM aios_core.tenant_registry AS registry
   WHERE registry.tenant_id = source_record.tenant_id;
  IF
    NOT FOUND
    OR registry_record.tenant_kind IS DISTINCT FROM 'SYNTHETIC'
    OR registry_record.state IS DISTINCT FROM next_state
    OR registry_record.lifecycle_version
      IS DISTINCT FROM next_lifecycle_version
    OR registry_record.generation IS DISTINCT FROM next_generation
    OR registry_record.operation_id IS DISTINCT FROM next_operation_id
  THEN
    RAISE EXCEPTION 'authoritative Tenant lifecycle does not match event'
      USING ERRCODE = 'P0702';
  END IF;

  SELECT lifecycle.*
    INTO lifecycle_record
    FROM aios_data.tenant_data_lifecycle AS lifecycle
   WHERE lifecycle.tenant_id = source_record.tenant_id
   FOR UPDATE;
  IF NOT FOUND THEN
    IF
      next_lifecycle_version <> 1
      OR next_generation <> 1
      OR next_state <> 'PROVISIONING'
    THEN
      RAISE EXCEPTION 'initial lifecycle event is stale'
        USING ERRCODE = 'P0702';
    END IF;
  ELSE
    IF next_lifecycle_version <> lifecycle_record.lifecycle_version + 1 THEN
      RAISE EXCEPTION 'lifecycle version is not next'
        USING ERRCODE = 'P0702';
    END IF;
    IF NOT (
      (lifecycle_record.state = 'PROVISIONING'
        AND next_state IN ('ACTIVE', 'SUSPENDED', 'DELETING'))
      OR (lifecycle_record.state = 'ACTIVE'
        AND next_state IN ('SUSPENDED', 'DELETING'))
      OR (lifecycle_record.state = 'SUSPENDED'
        AND next_state IN ('PROVISIONING', 'DELETING'))
      OR (lifecycle_record.state = 'DELETING'
        AND next_state = 'DELETED')
    ) THEN
      RAISE EXCEPTION 'lifecycle transition is invalid'
        USING ERRCODE = 'P0701';
    END IF;

    starts_projection := next_state IN ('PROVISIONING', 'DELETING');
    IF next_generation <> lifecycle_record.generation
      + (CASE WHEN starts_projection THEN 1 ELSE 0 END)
    THEN
      RAISE EXCEPTION 'lifecycle generation is stale'
        USING ERRCODE = 'P0702';
    END IF;
    IF
      (starts_projection
        AND next_operation_id IS NOT DISTINCT FROM lifecycle_record.operation_id)
      OR (NOT starts_projection
        AND next_operation_id IS DISTINCT FROM lifecycle_record.operation_id)
    THEN
      RAISE EXCEPTION 'lifecycle operation is stale'
        USING ERRCODE = 'P0702';
    END IF;
  END IF;

  IF next_state = 'SUSPENDED' THEN
    DELETE FROM aios_data.tenant_cache_record
     WHERE tenant_id = source_record.tenant_id
       AND tenant_kind = 'SYNTHETIC';
  END IF;
  IF next_state IN ('DELETING', 'DELETED') THEN
    DELETE FROM aios_data.tenant_cache_record
     WHERE tenant_id = source_record.tenant_id
       AND tenant_kind = 'SYNTHETIC';
    DELETE FROM aios_data.tenant_search_record
     WHERE tenant_id = source_record.tenant_id
       AND tenant_kind = 'SYNTHETIC';
    DELETE FROM aios_data.tenant_vector_record
     WHERE tenant_id = source_record.tenant_id
       AND tenant_kind = 'SYNTHETIC';
    DELETE FROM aios_data.tenant_sql_record
     WHERE tenant_id = source_record.tenant_id
       AND tenant_kind = 'SYNTHETIC';
  END IF;

  IF lifecycle_record.tenant_id IS NULL THEN
    INSERT INTO aios_data.tenant_data_lifecycle (
      tenant_id,
      tenant_kind,
      lifecycle_version,
      generation,
      operation_id,
      state,
      last_event_id,
      updated_at
    ) VALUES (
      source_record.tenant_id,
      'SYNTHETIC',
      next_lifecycle_version,
      next_generation,
      next_operation_id,
      next_state,
      source_record.event_id,
      source_record.created_at
    );
  ELSE
    UPDATE aios_data.tenant_data_lifecycle
       SET lifecycle_version = next_lifecycle_version,
           generation = next_generation,
           operation_id = next_operation_id,
           state = next_state,
           last_event_id = source_record.event_id,
           updated_at = source_record.created_at
     WHERE tenant_id = source_record.tenant_id
       AND tenant_kind = 'SYNTHETIC';
  END IF;

  INSERT INTO aios_data.tenant_data_event_receipt (
    event_id,
    tenant_id,
    tenant_kind,
    lifecycle_version,
    generation,
    operation_id,
    event_type,
    event_sha256,
    event,
    applied_at
  ) VALUES (
    source_record.event_id,
    source_record.tenant_id,
    'SYNTHETIC',
    next_lifecycle_version,
    next_generation,
    next_operation_id,
    event_type,
    source_event_sha256,
    source_event,
    statement_timestamp()
  );

  RETURN jsonb_build_object(
    'tenantId', source_record.tenant_id,
    'eventId', source_record.event_id,
    'lifecycleVersion', next_lifecycle_version,
    'generation', next_generation,
    'operationId', next_operation_id,
    'state', next_state,
    'status', 'SUCCEEDED',
    'duplicate', false
  );
END
$$;

ALTER FUNCTION aios_data.project_tenant_lifecycle_event(text)
  OWNER TO aios_c07_owner;

CREATE POLICY tenant_event_receipt_owner_select_policy
  ON aios_data.tenant_data_event_receipt
  FOR SELECT
  TO aios_c07_owner
  USING (true);
CREATE POLICY tenant_event_receipt_owner_insert_policy
  ON aios_data.tenant_data_event_receipt
  FOR INSERT
  TO aios_c07_owner
  WITH CHECK (true);
CREATE POLICY tenant_sql_owner_delete_policy
  ON aios_data.tenant_sql_record
  FOR DELETE
  TO aios_c07_owner
  USING (true);
CREATE POLICY tenant_sql_owner_select_policy
  ON aios_data.tenant_sql_record
  FOR SELECT
  TO aios_c07_owner
  USING (true);
CREATE POLICY tenant_vector_owner_delete_policy
  ON aios_data.tenant_vector_record
  FOR DELETE
  TO aios_c07_owner
  USING (true);
CREATE POLICY tenant_vector_owner_select_policy
  ON aios_data.tenant_vector_record
  FOR SELECT
  TO aios_c07_owner
  USING (true);
CREATE POLICY tenant_search_owner_delete_policy
  ON aios_data.tenant_search_record
  FOR DELETE
  TO aios_c07_owner
  USING (true);
CREATE POLICY tenant_search_owner_select_policy
  ON aios_data.tenant_search_record
  FOR SELECT
  TO aios_c07_owner
  USING (true);
CREATE POLICY tenant_cache_owner_delete_policy
  ON aios_data.tenant_cache_record
  FOR DELETE
  TO aios_c07_owner
  USING (true);
CREATE POLICY tenant_cache_owner_select_policy
  ON aios_data.tenant_cache_record
  FOR SELECT
  TO aios_c07_owner
  USING (true);

REVOKE ALL ON FUNCTION aios_data.project_tenant_lifecycle_event(text)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aios_data.project_tenant_lifecycle_event(text)
  TO aios_c07_lifecycle_runtime;
REVOKE EXECUTE ON FUNCTION aios_data.lifecycle_scope_matches(text, text)
  FROM aios_c07_lifecycle_runtime;

REVOKE INSERT, UPDATE, DELETE ON
  aios_data.tenant_data_lifecycle,
  aios_data.tenant_data_event_receipt,
  aios_data.tenant_sql_record,
  aios_data.tenant_vector_record,
  aios_data.tenant_search_record,
  aios_data.tenant_cache_record
  FROM aios_c07_lifecycle_runtime;

REVOKE SELECT ON
  aios_data.tenant_data_lifecycle,
  aios_data.tenant_data_event_receipt
  FROM aios_c07_lifecycle_runtime;
REVOKE SELECT (tenant_id, tenant_kind) ON
  aios_data.tenant_sql_record,
  aios_data.tenant_vector_record,
  aios_data.tenant_search_record,
  aios_data.tenant_cache_record
  FROM aios_c07_lifecycle_runtime;

COMMIT;
