CREATE TABLE `governance_events` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`revision` integer NOT NULL,
	`event_type` text NOT NULL,
	`payload` text NOT NULL,
	`actor_id` text NOT NULL,
	`idempotency_key` text NOT NULL,
	`command_hash` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `governance_events_project_revision_idx` ON `governance_events` (`project_id`,`revision`);--> statement-breakpoint
CREATE UNIQUE INDEX `governance_events_project_idempotency_idx` ON `governance_events` (`project_id`,`idempotency_key`);--> statement-breakpoint
CREATE TRIGGER `governance_events_no_update`
BEFORE UPDATE ON `governance_events`
BEGIN
	SELECT RAISE(ABORT, 'governance_events are append-only');
END;--> statement-breakpoint
CREATE TRIGGER `governance_events_no_delete`
BEFORE DELETE ON `governance_events`
BEGIN
	SELECT RAISE(ABORT, 'governance_events are append-only');
END;
