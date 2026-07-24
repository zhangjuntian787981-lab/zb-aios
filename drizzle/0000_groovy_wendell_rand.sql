CREATE TABLE `connectors` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`name` text NOT NULL,
	`maturity` text NOT NULL,
	`status_label` text NOT NULL,
	`data_mode` text NOT NULL,
	`resume_condition` text NOT NULL,
	`note` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `projects` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`scope_version` text NOT NULL,
	`current_phase` text NOT NULL,
	`status` text NOT NULL,
	`summary` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `task_events` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`project_id` text NOT NULL,
	`task_id` text,
	`connector_id` text,
	`event_type` text NOT NULL,
	`message` text NOT NULL,
	`actor` text NOT NULL,
	`idempotency_key` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `task_events_idempotency_idx` ON `task_events` (`idempotency_key`);--> statement-breakpoint
CREATE TABLE `tasks` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`phase` text NOT NULL,
	`title` text NOT NULL,
	`plain_summary` text NOT NULL,
	`acceptance` text NOT NULL,
	`status` text NOT NULL,
	`owner` text NOT NULL,
	`weight` integer NOT NULL,
	`next_step` text NOT NULL,
	`blocked_reason` text,
	`evidence` text,
	`updated_at` text NOT NULL
);
