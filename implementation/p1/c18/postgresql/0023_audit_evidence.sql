BEGIN;

-- C18 reuses the C07 signed per-transaction Tenant scope. C08 events and
-- Outbox rows may be referenced by C18, but they never replace these tables.
CREATE SCHEMA aios_audit;

CREATE FUNCTION aios_audit.jsonb_has_exact_keys(
  value jsonb,
  required_keys text[]
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT
    jsonb_typeof(value) = 'object'
    AND value ?& required_keys
    AND (
      SELECT count(*) = cardinality(required_keys)
        FROM jsonb_object_keys(value)
    );
$$;

CREATE FUNCTION aios_audit.metadata_string_matches(
  value jsonb,
  required_pattern text,
  maximum_length integer
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
DECLARE
  scalar_value text;
BEGIN
  IF jsonb_typeof(value) <> 'string' THEN
    RETURN false;
  END IF;
  scalar_value := value #>> '{}';
  RETURN
    char_length(scalar_value) BETWEEN 1 AND maximum_length
    AND scalar_value ~ required_pattern
    AND scalar_value !~* (
      'basic[[:space:]]+[a-z0-9+/=]+'
      '|bearer[[:space:]]+[a-z0-9._~-]+'
      '|sk-[a-z0-9_-]{8,}'
      '|aiza[a-z0-9_-]{8,}'
      '|akia[a-z0-9]{16}'
      '|gh[pousr]_[a-z0-9]{8,}'
      '|-----BEGIN [A-Z ]+PRIVATE KEY-----'
      '|(api[_-]?key|access[_-]?key|client[_-]?secret'
      '|password|secret|token)[[:space:]]*[:=]'
    );
END;
$$;

CREATE FUNCTION aios_audit.metadata_positive_integer(value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
DECLARE
  scalar_value text;
BEGIN
  IF jsonb_typeof(value) <> 'number' THEN
    RETURN false;
  END IF;
  scalar_value := value #>> '{}';
  IF scalar_value !~ '^[1-9][0-9]{0,15}$' THEN
    RETURN false;
  END IF;
  RETURN scalar_value::numeric <= 9007199254740991;
END;
$$;

CREATE FUNCTION aios_audit.metadata_shape(
  value jsonb,
  expected_shape text
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
DECLARE
  item jsonb;
  relation_type text;
BEGIN
  IF expected_shape = 'AUDIT_PAYLOAD' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,
      ARRAY[
        'schemaVersion','auditType','tenantId','tenantKind','occurredAt',
        'correlationId','summaryCode','retentionClass','identity',
        'authorization','model','knowledge','skill','tool',
        'humanDecision','result','c08State','provenance',
        'provenanceSha256'
      ]
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'schemaVersion','^c18-audit-event[.]v1$',64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'auditType','^[A-Z][A-Z0-9_]{0,63}$',64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'tenantId',
        '^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'tenantKind','^SYNTHETIC$',16
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'occurredAt',
        '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$',
        24
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'correlationId',
        '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$',
        128
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'summaryCode','^[A-Z][A-Z0-9_]{0,63}$',64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'retentionClass','^AUDIT_7Y$',16
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'identity','IDENTITY_EVIDENCE'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'authorization','AUTHORIZATION_EVIDENCE'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'model','COMMON_EVIDENCE'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'knowledge','EVIDENCE_ARRAY'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'skill','COMMON_EVIDENCE'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'tool','COMMON_EVIDENCE'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'humanDecision','COMMON_EVIDENCE'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'result','COMMON_EVIDENCE'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'c08State','COMMON_EVIDENCE'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'provenance','PROVENANCE'
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'provenanceSha256','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE;
  END IF;

  IF expected_shape = 'COMMON_EVIDENCE' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,ARRAY['evidenceRef','version','sha256']
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'evidenceRef',
        '^(evidence|fixture|policy|profile|prov|synthetic|test)://[A-Za-z0-9][A-Za-z0-9._~:/-]*$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'version','^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$',128
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'sha256','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE;
  END IF;

  IF expected_shape = 'AUTHORIZATION_EVIDENCE' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,ARRAY['decisionId','evidenceRef','version','sha256']
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'decisionId','^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$',256
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value - 'decisionId','COMMON_EVIDENCE'
      ) IS TRUE;
  END IF;

  IF expected_shape = 'EVIDENCE_ARRAY' THEN
    IF jsonb_typeof(value) <> 'array'
       OR jsonb_array_length(value) = 0 THEN
      RETURN false;
    END IF;
    FOR item IN SELECT jsonb_array_elements(value)
    LOOP
      IF aios_audit.metadata_shape(
        item,'COMMON_EVIDENCE'
      ) IS NOT TRUE THEN
        RETURN false;
      END IF;
    END LOOP;
    RETURN true;
  END IF;

  IF expected_shape = 'IDENTITY_EVIDENCE' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,
      ARRAY[
        'evidenceRef','version','sha256','artifact',
        'humanPrincipalRef','workloadPrincipalRef','delegationRef'
      ]
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'evidenceRef',
        '^evidence://c05/action-identities/stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'version','^c18-action-identity-artifact-v1$',64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'sha256','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'artifact','ACTION_IDENTITY_ARTIFACT'
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'humanPrincipalRef',
        '^evidence://c05/principals/prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'workloadPrincipalRef',
        '^evidence://c05/principals/prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'delegationRef',
        '^evidence://c05/delegations/dlg_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE;
  END IF;

  IF expected_shape = 'ACTION_IDENTITY_ARTIFACT' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,
      ARRAY[
        'schemaVersion','tenantId','evidenceType','artifactId',
        'sourceWorkPackage','identityAccountSha256',
        'identityLinkSha256','sessionSha256','purposeRef',
        'humanSubject','workloadActor','delegationChain','trustSource'
      ]
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'schemaVersion',
        '^c18-action-identity-artifact[.]v1$',64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'tenantId',
        '^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'evidenceType','^IDENTITY$',16
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'artifactId',
        '^synthetic-action-identity-stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        128
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'sourceWorkPackage','^C05$',8
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'identityAccountSha256','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'identityLinkSha256','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'sessionSha256','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'purposeRef',
        '^(evidence|fixture|policy|profile|prov|synthetic|test)://[A-Za-z0-9][A-Za-z0-9._~:/-]*$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'humanSubject','HUMAN_SUBJECT'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'workloadActor','WORKLOAD_ACTOR'
      ) IS TRUE
      AND aios_audit.metadata_shape(
        value -> 'delegationChain','DELEGATION_ARRAY'
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'trustSource',
        '^VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT$',
        64
      ) IS TRUE;
  END IF;

  IF expected_shape = 'HUMAN_SUBJECT' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,ARRAY['principalRef','lifecycleVersion','securityEpoch']
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'principalRef',
        '^evidence://c05/principals/prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_positive_integer(
        value -> 'lifecycleVersion'
      ) IS TRUE
      AND aios_audit.metadata_positive_integer(
        value -> 'securityEpoch'
      ) IS TRUE;
  END IF;

  IF expected_shape = 'WORKLOAD_ACTOR' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,
      ARRAY[
        'principalRef','principalType','lifecycleVersion','securityEpoch'
      ]
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'principalRef',
        '^evidence://c05/principals/prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'principalType','^(AGENT|SERVICE)$',16
      ) IS TRUE
      AND aios_audit.metadata_positive_integer(
        value -> 'lifecycleVersion'
      ) IS TRUE
      AND aios_audit.metadata_positive_integer(
        value -> 'securityEpoch'
      ) IS TRUE;
  END IF;

  IF expected_shape = 'DELEGATION_ARRAY' THEN
    IF jsonb_typeof(value) <> 'array'
       OR jsonb_array_length(value) = 0 THEN
      RETURN false;
    END IF;
    FOR item IN SELECT jsonb_array_elements(value)
    LOOP
      IF aios_audit.metadata_shape(item,'DELEGATION') IS NOT TRUE THEN
        RETURN false;
      END IF;
    END LOOP;
    RETURN true;
  END IF;

  IF expected_shape = 'DELEGATION' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,
      ARRAY[
        'delegationRef','delegatorPrincipalRef','delegatePrincipalRef',
        'purposeRef','lifecycleVersion','expiresAt'
      ]
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'delegationRef',
        '^evidence://c05/delegations/dlg_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'delegatorPrincipalRef',
        '^evidence://c05/principals/prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'delegatePrincipalRef',
        '^evidence://c05/principals/prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'purposeRef',
        '^(evidence|fixture|policy|profile|prov|synthetic|test)://[A-Za-z0-9][A-Za-z0-9._~:/-]*$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_positive_integer(
        value -> 'lifecycleVersion'
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'expiresAt',
        '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$',
        24
      ) IS TRUE;
  END IF;

  IF expected_shape = 'PROVENANCE' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,
      ARRAY['profileVersion','activities','agents','entities','relations']
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    IF aios_audit.metadata_string_matches(
      value -> 'profileVersion','^c18-w3c-prov-profile[.]v1$',64
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    IF jsonb_typeof(value -> 'activities') <> 'array'
       OR jsonb_array_length(value -> 'activities') = 0
       OR jsonb_typeof(value -> 'agents') <> 'array'
       OR jsonb_array_length(value -> 'agents') = 0
       OR jsonb_typeof(value -> 'entities') <> 'array'
       OR jsonb_array_length(value -> 'entities') = 0
       OR jsonb_typeof(value -> 'relations') <> 'array'
       OR jsonb_array_length(value -> 'relations') = 0 THEN
      RETURN false;
    END IF;
    FOR relation_type,item IN
      SELECT 'PROV_ACTIVITY',entry
        FROM jsonb_array_elements(value -> 'activities') AS entry
      UNION ALL
      SELECT 'PROV_AGENT',entry
        FROM jsonb_array_elements(value -> 'agents') AS entry
      UNION ALL
      SELECT 'PROV_ENTITY',entry
        FROM jsonb_array_elements(value -> 'entities') AS entry
      UNION ALL
      SELECT 'PROV_RELATION',entry
        FROM jsonb_array_elements(value -> 'relations') AS entry
    LOOP
      IF aios_audit.metadata_shape(
        item,relation_type
      ) IS NOT TRUE THEN
        RETURN false;
      END IF;
    END LOOP;
    RETURN true;
  END IF;

  IF expected_shape = 'PROV_ACTIVITY' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,ARRAY['id','type','occurredAt']
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'id',
        '^prov://c18/activities/aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'type','^aios:AuditedAction$',32
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'occurredAt',
        '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$',
        24
      ) IS TRUE;
  END IF;

  IF expected_shape = 'PROV_AGENT' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,ARRAY['id','type']
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'id',
        '^evidence://c05/principals/prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'type','^prov:(Person|SoftwareAgent)$',32
      ) IS TRUE;
  END IF;

  IF expected_shape = 'PROV_ENTITY' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,ARRAY['id','type','version','sha256']
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'id',
        '^(evidence|fixture|policy|profile|prov|synthetic|test)://[A-Za-z0-9][A-Za-z0-9._~:/-]*$',
        1024
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'type',
        '^aios:(Identity|Authorization|Model|Knowledge|Skill|Tool|HumanDecision|Result|C08State)Evidence$',
        64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'version','^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$',128
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'sha256','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE;
  END IF;

  IF expected_shape = 'PROV_RELATION' THEN
    IF jsonb_typeof(value) <> 'object' THEN
      RETURN false;
    END IF;
    relation_type := value ->> 'type';
    IF relation_type = 'prov:wasAssociatedWith' THEN
      IF aios_audit.jsonb_has_exact_keys(
        value,ARRAY['type','activity','agent']
      ) IS NOT TRUE THEN
        RETURN false;
      END IF;
      RETURN
        aios_audit.metadata_string_matches(
          value -> 'activity',
          '^prov://c18/activities/aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
          1024
        ) IS TRUE
        AND aios_audit.metadata_string_matches(
          value -> 'agent',
          '^evidence://c05/principals/prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
          1024
        ) IS TRUE;
    END IF;
    IF relation_type = 'prov:actedOnBehalfOf' THEN
      IF aios_audit.jsonb_has_exact_keys(
        value,ARRAY['type','delegate','responsible']
      ) IS NOT TRUE THEN
        RETURN false;
      END IF;
      RETURN
        aios_audit.metadata_string_matches(
          value -> 'delegate',
          '^evidence://c05/principals/prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
          1024
        ) IS TRUE
        AND aios_audit.metadata_string_matches(
          value -> 'responsible',
          '^evidence://c05/principals/prn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
          1024
        ) IS TRUE;
    END IF;
    IF relation_type = 'prov:used' THEN
      IF aios_audit.jsonb_has_exact_keys(
        value,ARRAY['type','activity','entity']
      ) IS NOT TRUE THEN
        RETURN false;
      END IF;
      RETURN
        aios_audit.metadata_string_matches(
          value -> 'activity',
          '^prov://c18/activities/aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
          1024
        ) IS TRUE
        AND aios_audit.metadata_string_matches(
          value -> 'entity',
          '^(evidence|fixture|policy|profile|prov|synthetic|test)://[A-Za-z0-9][A-Za-z0-9._~:/-]*$',
          1024
        ) IS TRUE;
    END IF;
    IF relation_type = 'prov:wasGeneratedBy' THEN
      IF aios_audit.jsonb_has_exact_keys(
        value,ARRAY['type','entity','activity']
      ) IS NOT TRUE THEN
        RETURN false;
      END IF;
      RETURN
        aios_audit.metadata_string_matches(
          value -> 'entity',
          '^(evidence|fixture|policy|profile|prov|synthetic|test)://[A-Za-z0-9][A-Za-z0-9._~:/-]*$',
          1024
        ) IS TRUE
        AND aios_audit.metadata_string_matches(
          value -> 'activity',
          '^prov://c18/activities/aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
          1024
        ) IS TRUE;
    END IF;
    IF relation_type = 'prov:wasDerivedFrom' THEN
      IF aios_audit.jsonb_has_exact_keys(
        value,ARRAY['type','generatedEntity','usedEntity']
      ) IS NOT TRUE THEN
        RETURN false;
      END IF;
      RETURN
        aios_audit.metadata_string_matches(
          value -> 'generatedEntity',
          '^(evidence|fixture|policy|profile|prov|synthetic|test)://[A-Za-z0-9][A-Za-z0-9._~:/-]*$',
          1024
        ) IS TRUE
        AND aios_audit.metadata_string_matches(
          value -> 'usedEntity',
          '^(evidence|fixture|policy|profile|prov|synthetic|test)://[A-Za-z0-9][A-Za-z0-9._~:/-]*$',
          1024
        ) IS TRUE;
    END IF;
    RETURN false;
  END IF;

  IF expected_shape = 'CLOUD_EVENT' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,
      ARRAY[
        'specversion','id','source','type','time','datacontenttype',
        'subject','dataschema','tenantkind','correlationid','synthetic',
        'data'
      ]
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'specversion','^1[.]0$',8
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'id',
        '^aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'source','^/aios-core/audit-evidence$',64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'type',
        '^product[.]aios[.]audit-evidence-recorded[.]v1$',
        64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'time',
        '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$',
        24
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'datacontenttype','^application/json$',32
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'subject',
        '^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'dataschema',
        '^synthetic://c18/schemas/audit-event[.]v1$',
        64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'tenantkind','^SYNTHETIC$',16
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'correlationid',
        '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$',
        128
      ) IS TRUE
      AND value -> 'synthetic' = 'true'::jsonb
      AND aios_audit.metadata_shape(
        value -> 'data','CLOUD_EVENT_DATA'
      ) IS TRUE;
  END IF;

  IF expected_shape = 'CLOUD_EVENT_DATA' THEN
    IF aios_audit.jsonb_has_exact_keys(
      value,
      ARRAY[
        'tenant_id','audit_event_id','sequence','previous_event_hash',
        'event_hash','payload_sha256','provenance_sha256','audit_type',
        'retention_class'
      ]
    ) IS NOT TRUE THEN
      RETURN false;
    END IF;
    RETURN
      aios_audit.metadata_string_matches(
        value -> 'tenant_id',
        '^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'audit_event_id',
        '^aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        64
      ) IS TRUE
      AND aios_audit.metadata_positive_integer(
        value -> 'sequence'
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'previous_event_hash','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'event_hash','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'payload_sha256','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'provenance_sha256','^sha256:[a-f0-9]{64}$',71
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'audit_type','^[A-Z][A-Z0-9_]{0,63}$',64
      ) IS TRUE
      AND aios_audit.metadata_string_matches(
        value -> 'retention_class','^AUDIT_7Y$',16
      ) IS TRUE;
  END IF;

  RETURN false;
END;
$$;

CREATE FUNCTION aios_audit.metadata_only(value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
BEGIN
  IF jsonb_typeof(value) <> 'object' THEN
    RETURN false;
  END IF;
  IF value ->> 'schemaVersion' = 'c18-audit-event.v1' THEN
    RETURN aios_audit.metadata_shape(value,'AUDIT_PAYLOAD') IS TRUE;
  END IF;
  IF value ->> 'specversion' = '1.0' THEN
    RETURN aios_audit.metadata_shape(value,'CLOUD_EVENT') IS TRUE;
  END IF;
  RETURN false;
END;
$$;

CREATE TABLE aios_audit.audit_head (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  last_sequence bigint NOT NULL DEFAULT 0
    CHECK (last_sequence BETWEEN 0 AND 9007199254740991),
  last_event_id text,
  last_event_hash text NOT NULL DEFAULT
    'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    CHECK (last_event_hash ~ '^sha256:[a-f0-9]{64}$'),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id),
  UNIQUE (tenant_id, tenant_kind),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    (
      last_sequence = 0
      AND last_event_id IS NULL
      AND last_event_hash =
        'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    )
    OR (
      last_sequence > 0
      AND last_event_id IS NOT NULL
      AND last_event_id ~
        '^aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
  )
);

CREATE TABLE aios_audit.audit_event (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event_id text NOT NULL
    CHECK (
      event_id ~
        '^aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
  sequence bigint NOT NULL
    CHECK (sequence BETWEEN 1 AND 9007199254740991),
  previous_event_hash text NOT NULL
    CHECK (previous_event_hash ~ '^sha256:[a-f0-9]{64}$'),
  event_hash text NOT NULL
    CHECK (event_hash ~ '^sha256:[a-f0-9]{64}$'),
  payload_sha256 text NOT NULL
    CHECK (payload_sha256 ~ '^sha256:[a-f0-9]{64}$'),
  payload jsonb NOT NULL
    CHECK (jsonb_typeof(payload) = 'object')
    CONSTRAINT audit_event_metadata_only
      CHECK (aios_audit.metadata_only(payload))
    CHECK ((payload ->> 'schemaVersion') = 'c18-audit-event.v1')
    CHECK ((payload ->> 'tenantId') IS NOT DISTINCT FROM tenant_id)
    CHECK ((payload ->> 'tenantKind') IS NOT DISTINCT FROM tenant_kind)
    CHECK ((payload ->> 'retentionClass') = 'AUDIT_7Y'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (tenant_id, sequence),
  UNIQUE (tenant_id, event_hash),
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

CREATE TABLE aios_audit.audit_delivery_intent (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event_id text NOT NULL,
  event jsonb NOT NULL
    CHECK (jsonb_typeof(event) = 'object')
    CONSTRAINT audit_delivery_intent_metadata_only
      CHECK (aios_audit.metadata_only(event))
    CHECK ((event ->> 'id') IS NOT DISTINCT FROM event_id)
    CHECK (
      (event ->> 'type') =
        'product.aios.audit-evidence-recorded.v1'
    )
    CHECK ((event ->> 'tenantkind') IS NOT DISTINCT FROM tenant_kind),
  retention_class text NOT NULL CHECK (retention_class = 'AUDIT_7Y'),
  legal_hold boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, event_id)
    REFERENCES aios_audit.audit_event(tenant_id, event_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

ALTER TABLE aios_audit.audit_event
  ADD CONSTRAINT audit_event_delivery_intent_pair
  FOREIGN KEY (tenant_id, event_id)
  REFERENCES aios_audit.audit_delivery_intent(tenant_id, event_id)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE aios_audit.audit_outbox (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  event_id text NOT NULL,
  status text NOT NULL
    CHECK (status IN ('PENDING', 'PROCESSING', 'FAILED', 'PUBLISHED')),
  attempt_count bigint NOT NULL DEFAULT 0
    CHECK (attempt_count BETWEEN 0 AND 9007199254740991),
  lease_version bigint NOT NULL DEFAULT 0
    CHECK (lease_version BETWEEN 0 AND 9007199254740991),
  leased_by text,
  lease_until timestamptz,
  available_at timestamptz NOT NULL,
  published_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, event_id)
    REFERENCES aios_audit.audit_delivery_intent(tenant_id, event_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT,
  CHECK (
    leased_by IS NULL
    OR char_length(btrim(leased_by)) BETWEEN 1 AND 128
  ),
  CHECK (
    last_error_code IS NULL
    OR last_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'
  ),
  CONSTRAINT audit_outbox_state_shape CHECK (
    (
      status IN ('PENDING', 'FAILED')
      AND leased_by IS NULL
      AND lease_until IS NULL
      AND published_at IS NULL
    )
    OR (
      status = 'PROCESSING'
      AND leased_by IS NOT NULL
      AND lease_until IS NOT NULL
      AND published_at IS NULL
    )
    OR (
      status = 'PUBLISHED'
      AND leased_by IS NULL
      AND lease_until IS NULL
      AND published_at IS NOT NULL
      AND last_error_code IS NULL
    )
  )
);

CREATE TABLE aios_audit.audit_command_receipt (
  tenant_id text NOT NULL,
  tenant_kind text NOT NULL CHECK (tenant_kind = 'SYNTHETIC'),
  idempotency_key text NOT NULL
    CHECK (char_length(btrim(idempotency_key)) BETWEEN 1 AND 128),
  request_hash text NOT NULL
    CHECK (request_hash ~ '^sha256:[a-f0-9]{64}$'),
  event_id text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, idempotency_key),
  UNIQUE (tenant_id, event_id),
  FOREIGN KEY (tenant_id, event_id)
    REFERENCES aios_audit.audit_event(tenant_id, event_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, tenant_kind)
    REFERENCES aios_core.tenant_registry(tenant_id, tenant_kind)
    ON DELETE RESTRICT
);

ALTER TABLE aios_audit.audit_event
  ADD CONSTRAINT audit_event_receipt_pair
  FOREIGN KEY (tenant_id, event_id)
  REFERENCES aios_audit.audit_command_receipt(tenant_id, event_id)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE aios_audit.audit_head
  ADD CONSTRAINT audit_head_event_ref
  FOREIGN KEY (tenant_id, last_event_id)
  REFERENCES aios_audit.audit_event(tenant_id, event_id)
  ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX audit_event_retention_query_idx
  ON aios_audit.audit_event (tenant_id, created_at, sequence);

CREATE INDEX audit_outbox_delivery_idx
  ON aios_audit.audit_outbox (
    tenant_id,
    status,
    available_at,
    created_at,
    event_id
  );

CREATE INDEX audit_outbox_published_retention_idx
  ON aios_audit.audit_outbox (tenant_id, published_at, event_id)
  WHERE status = 'PUBLISHED';

CREATE FUNCTION aios_audit.restore_target_is_empty(target_tenant_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, aios_audit
AS $$
  SELECT
    target_tenant_id =
      current_setting('aios.tenant_id', true)
    AND aios_data.runtime_scope_allows(
      target_tenant_id,
      'SYNTHETIC'
    )
    AND NOT EXISTS (
      SELECT 1 FROM aios_audit.audit_head
       WHERE tenant_id = target_tenant_id
    )
    AND NOT EXISTS (
      SELECT 1 FROM aios_audit.audit_event
       WHERE tenant_id = target_tenant_id
    )
    AND NOT EXISTS (
      SELECT 1 FROM aios_audit.audit_delivery_intent
       WHERE tenant_id = target_tenant_id
    )
    AND NOT EXISTS (
      SELECT 1 FROM aios_audit.audit_outbox
       WHERE tenant_id = target_tenant_id
    )
    AND NOT EXISTS (
      SELECT 1 FROM aios_audit.audit_command_receipt
       WHERE tenant_id = target_tenant_id
    );
$$;

CREATE FUNCTION aios_audit.reject_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'C18 append-only history cannot be changed'
    USING ERRCODE = '42501',
          CONSTRAINT = 'audit_append_only_guard';
END;
$$;

CREATE FUNCTION aios_audit.enforce_head_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'C18 Audit Head cannot be deleted'
      USING ERRCODE = '42501',
            CONSTRAINT = 'audit_head_delete_guard';
  END IF;

  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR NEW.last_sequence <> OLD.last_sequence + 1
     OR NEW.updated_at < OLD.updated_at
     OR NOT EXISTS (
       SELECT 1
         FROM aios_audit.audit_event AS event
        WHERE event.tenant_id = NEW.tenant_id
          AND event.event_id = NEW.last_event_id
          AND event.sequence = NEW.last_sequence
          AND event.previous_event_hash = OLD.last_event_hash
          AND event.event_hash = NEW.last_event_hash
     ) THEN
    RAISE EXCEPTION 'C18 Audit Head must advance by one verified event'
      USING ERRCODE = '23514',
            CONSTRAINT = 'audit_head_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_audit.enforce_outbox_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF pg_has_role(
         current_user,
         'aios_c18_retention_worker',
         'MEMBER'
       )
       AND OLD.status = 'PUBLISHED'
       AND OLD.published_at <= statement_timestamp() - interval '30 days'
       AND EXISTS (
         SELECT 1
           FROM aios_audit.audit_delivery_intent AS intent
          WHERE intent.tenant_id = OLD.tenant_id
            AND intent.event_id = OLD.event_id
            AND intent.legal_hold = false
       ) THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'C18 Outbox deletion is not retention-eligible'
      USING ERRCODE = '42501',
            CONSTRAINT = 'audit_outbox_delete_guard';
  END IF;

  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.tenant_kind IS DISTINCT FROM OLD.tenant_kind
     OR NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR (
       NEW.status = 'PROCESSING'
       AND NOT (
         OLD.status IN ('PENDING', 'FAILED', 'PROCESSING')
         AND NEW.attempt_count = OLD.attempt_count + 1
         AND NEW.lease_version = OLD.lease_version + 1
         AND NEW.leased_by IS NOT NULL
         AND NEW.lease_until IS NOT NULL
         AND NEW.lease_until > statement_timestamp()
         AND NEW.lease_until <=
           statement_timestamp() + interval '300 seconds'
         AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
         AND NEW.published_at IS NULL
         AND NEW.last_error_code IS NULL
         AND (
           (
             OLD.status IN ('PENDING', 'FAILED')
             AND OLD.available_at <= statement_timestamp()
           )
           OR (
             OLD.status = 'PROCESSING'
             AND OLD.lease_until <= statement_timestamp()
           )
         )
       )
     )
     OR (
       NEW.status = 'PUBLISHED'
       AND NOT (
         OLD.status = 'PROCESSING'
         AND NEW.attempt_count = OLD.attempt_count
         AND NEW.lease_version = OLD.lease_version
         AND NEW.leased_by IS NULL
         AND NEW.lease_until IS NULL
         AND OLD.lease_until >= statement_timestamp()
         AND NEW.available_at IS NOT DISTINCT FROM OLD.available_at
         AND NEW.published_at IS NOT DISTINCT FROM statement_timestamp()
         AND NEW.last_error_code IS NULL
       )
     )
     OR (
       NEW.status = 'FAILED'
       AND NOT (
         OLD.status = 'PROCESSING'
         AND NEW.attempt_count = OLD.attempt_count
         AND NEW.lease_version = OLD.lease_version
         AND NEW.leased_by IS NULL
         AND NEW.lease_until IS NULL
         AND OLD.lease_until >= statement_timestamp()
         AND NEW.published_at IS NULL
         AND NEW.last_error_code IS NOT NULL
         AND NEW.available_at > statement_timestamp()
         AND NEW.available_at <=
           statement_timestamp() + interval '3600 seconds'
       )
     )
     OR NEW.status = 'PENDING'
  THEN
    RAISE EXCEPTION 'C18 Outbox transition is invalid'
      USING ERRCODE = '23514',
            CONSTRAINT = 'audit_outbox_transition_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION aios_audit.require_initial_outbox()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, aios_audit
AS $$
BEGIN
  IF pg_has_role(
       session_user,
       'aios_c18_recovery_writer',
       'MEMBER'
     )
     AND NOT EXISTS (
       SELECT 1
         FROM pg_catalog.pg_roles
        WHERE rolname = session_user
          AND (rolsuper OR rolbypassrls)
     ) THEN
    RETURN NULL;
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM aios_audit.audit_outbox AS outbox
     WHERE outbox.tenant_id = NEW.tenant_id
       AND outbox.event_id = NEW.event_id
  ) THEN
    RAISE EXCEPTION 'C18 AuditEvent requires an initial Outbox row'
      USING ERRCODE = '23503',
            CONSTRAINT = 'audit_event_outbox_pair';
  END IF;
  RETURN NULL;
END;
$$;

CREATE TRIGGER audit_event_append_only_guard
BEFORE UPDATE OR DELETE ON aios_audit.audit_event
FOR EACH ROW EXECUTE FUNCTION aios_audit.reject_append_only_change();

CREATE TRIGGER audit_delivery_intent_append_only_guard
BEFORE UPDATE OR DELETE ON aios_audit.audit_delivery_intent
FOR EACH ROW EXECUTE FUNCTION aios_audit.reject_append_only_change();

CREATE TRIGGER audit_receipt_append_only_guard
BEFORE UPDATE OR DELETE ON aios_audit.audit_command_receipt
FOR EACH ROW EXECUTE FUNCTION aios_audit.reject_append_only_change();

CREATE TRIGGER audit_head_transition_guard
BEFORE UPDATE OR DELETE ON aios_audit.audit_head
FOR EACH ROW EXECUTE FUNCTION aios_audit.enforce_head_transition();

CREATE TRIGGER audit_outbox_transition_guard
BEFORE UPDATE OR DELETE ON aios_audit.audit_outbox
FOR EACH ROW EXECUTE FUNCTION aios_audit.enforce_outbox_transition();

CREATE CONSTRAINT TRIGGER audit_event_outbox_pair
AFTER INSERT ON aios_audit.audit_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION aios_audit.require_initial_outbox();

ALTER TABLE aios_audit.audit_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_delivery_intent ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_command_receipt ENABLE ROW LEVEL SECURITY;

ALTER TABLE aios_audit.audit_head FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_event FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_delivery_intent FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE aios_audit.audit_command_receipt FORCE ROW LEVEL SECURITY;

COMMIT;
