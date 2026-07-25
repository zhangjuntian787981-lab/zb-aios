BEGIN;

-- This migration runs after C04 0002_identity_federation.sql.
-- The application outbox worker must not own this table or these triggers.

ALTER TABLE aios_core.identity_outbox
  ADD CONSTRAINT identity_outbox_worker_id_shape
    CHECK (
      leased_by IS NULL
      OR (
        char_length(btrim(leased_by)) BETWEEN 1 AND 128
      )
    ),
  ADD CONSTRAINT identity_outbox_error_code_shape
    CHECK (
      last_error_code IS NULL
      OR (
        char_length(btrim(last_error_code)) BETWEEN 1 AND 128
      )
    ),
  ADD CONSTRAINT identity_outbox_attempt_lease_match
    CHECK (attempt_count::bigint = lease_version),
  ADD CONSTRAINT identity_outbox_delivery_shape
    CHECK (
      (
        status = 'PENDING'
        AND attempt_count = 0
        AND lease_version = 0
        AND leased_by IS NULL
        AND lease_until IS NULL
        AND last_error_code IS NULL
        AND published_at IS NULL
      )
      OR (
        status = 'PROCESSING'
        AND attempt_count > 0
        AND leased_by IS NOT NULL
        AND lease_until IS NOT NULL
        AND last_error_code IS NULL
        AND published_at IS NULL
      )
      OR (
        status = 'FAILED'
        AND attempt_count > 0
        AND leased_by IS NULL
        AND lease_until IS NULL
        AND last_error_code IS NOT NULL
        AND published_at IS NULL
      )
      OR (
        status = 'PUBLISHED'
        AND attempt_count > 0
        AND leased_by IS NULL
        AND lease_until IS NULL
        AND last_error_code IS NULL
        AND published_at IS NOT NULL
      )
    );

CREATE FUNCTION aios_core.enforce_identity_outbox_delivery_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING'
      OR NEW.attempt_count <> 0
      OR NEW.lease_version <> 0
      OR NEW.leased_by IS NOT NULL
      OR NEW.lease_until IS NOT NULL
      OR NEW.last_error_code IS NOT NULL
      OR NEW.published_at IS NOT NULL
    THEN
      RAISE EXCEPTION 'identity outbox must start pending'
        USING ERRCODE = '23000',
              CONSTRAINT = 'identity_outbox_initial_state_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PUBLISHED' THEN
    RAISE EXCEPTION 'published identity outbox event is final'
      USING ERRCODE = '23000',
            CONSTRAINT = 'identity_outbox_published_guard';
  END IF;

  IF OLD.status IN ('PENDING', 'FAILED')
    AND NEW.status = 'PROCESSING'
  THEN
    IF OLD.available_at > statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count + 1
      OR NEW.lease_version <> OLD.lease_version + 1
      OR NEW.available_at IS DISTINCT FROM OLD.available_at
      OR NEW.leased_by IS NULL
      OR NEW.lease_until <= statement_timestamp()
      OR NEW.last_error_code IS NOT NULL
      OR NEW.published_at IS NOT NULL
    THEN
      RAISE EXCEPTION 'identity outbox claim is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'identity_outbox_claim_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PROCESSING'
    AND NEW.status = 'PROCESSING'
  THEN
    IF OLD.lease_until >= statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count + 1
      OR NEW.lease_version <> OLD.lease_version + 1
      OR NEW.available_at IS DISTINCT FROM OLD.available_at
      OR NEW.leased_by IS NULL
      OR NEW.lease_until <= statement_timestamp()
      OR NEW.last_error_code IS NOT NULL
      OR NEW.published_at IS NOT NULL
    THEN
      RAISE EXCEPTION 'identity outbox reclaim is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'identity_outbox_reclaim_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PROCESSING'
    AND NEW.status = 'FAILED'
  THEN
    IF OLD.lease_until < statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count
      OR NEW.lease_version <> OLD.lease_version
      OR NEW.available_at <= statement_timestamp()
      OR NEW.leased_by IS NOT NULL
      OR NEW.lease_until IS NOT NULL
      OR NEW.last_error_code IS NULL
      OR NEW.published_at IS NOT NULL
    THEN
      RAISE EXCEPTION 'identity outbox failure receipt is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'identity_outbox_failure_guard';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status = 'PROCESSING'
    AND NEW.status = 'PUBLISHED'
  THEN
    IF OLD.lease_until < statement_timestamp()
      OR NEW.attempt_count <> OLD.attempt_count
      OR NEW.lease_version <> OLD.lease_version
      OR NEW.available_at IS DISTINCT FROM OLD.available_at
      OR NEW.leased_by IS NOT NULL
      OR NEW.lease_until IS NOT NULL
      OR NEW.last_error_code IS NOT NULL
      OR NEW.published_at IS NULL
    THEN
      RAISE EXCEPTION 'identity outbox completion is invalid'
        USING ERRCODE = '23000',
              CONSTRAINT = 'identity_outbox_completion_guard';
    END IF;
    RETURN NEW;
  END IF;

  RAISE EXCEPTION 'identity outbox transition is invalid'
    USING ERRCODE = '23000',
          CONSTRAINT = 'identity_outbox_transition_guard';
END;
$$;

CREATE TRIGGER identity_outbox_delivery_state_guard
BEFORE INSERT OR UPDATE ON aios_core.identity_outbox
FOR EACH ROW
EXECUTE FUNCTION aios_core.enforce_identity_outbox_delivery_state();

COMMIT;
