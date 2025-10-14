# GRC Portal: Data Archiving and Retention Implementation Plan

## Chosen Technology
* **Name:** Flask-SQLAlchemy Migrations & Task Scheduling (APScheduler)
* **Purpose:** Safely manage schema changes (retention tables) and automate the background process of moving old records to ensure long-term regulatory compliance (7-year retention) without impacting live system performance.

## Implementation Workflow

### Phase 1: Database Setup and Migration (Focus on Task 1)
1.  **Model Definition (SQLAlchemy):** Define the schema for the new tables:
    * `retention_config`: Stores policy for each table (e.g., `retention_days`, `archive_enabled`).
    * `risk_archive`, `audit_archive`, `incident_archive`: Identical schemas to their respective live tables.
2.  **Run Migration (T1):** Execute database migrations to create all archive tables and the `retention_config` table.
3.  **Validation:** Verify that the new tables are present and correctly structured.


### Phase 2: Core Archiving Logic (Focus on Task 2)
1.  **Develop Archiving Function (T2):** Create the Python function `archive_old_records()`:
    * Iterate through tables configured in `retention_config`.
    * Implement batch transfer logic: SELECT records older than the configured `retention_days` and INSERT into the corresponding `*_archive` table, then DELETE from the main table.
    * Add conditional logic (e.g., number of rows > 25) for safe execution.
2.  **Testing (T2):** Populate the `risk` table with test data (some older than 2 days) and manually run the function to confirm records are successfully moved and counts are accurate.
3.  **Purge Function:** Create an optional, admin-triggered `purge_archived_records()` function.


### Phase 3: Automation and Admin Integration (Focus on Task 3)
1.  **Integrate APScheduler (T3):** Set up and configure APScheduler to run the main `archive_old_records()` function on the defined schedule (e.g., weekly).
2.  **Audit Logging:** Ensure all archiving and purging operations are logged immediately to the audit trail (preventing log loss).
3.  **Admin UI (`/admin/retention_settings`):** Build the interface for Administrators to manage retention policies:
    * Form fields for `retention_days`, `archive_enabled`, and `auto_purge` for each table.
    * Add a link to view the archived data tables.
    * Include a manual "Archive Trigger" button.
4.  **Validation:** Verify the scheduler runs successfully and logs the event without errors.


### Phase 4: Safety, Performance, and Documentation
1.  **Safety Measures:** Implement required safeguards:
    * Require explicit admin approval for all *purging* operations.
    * Implement dry-run mode for testing archiving logic.
    * Trigger backup export (CSV/JSON) before any purging operation.
2.  **Performance Tuning:** Ensure batch operations and indexed date columns are used for efficiency.
3.  **UI Feedback:** Display archive statistics (last run, records archived) in the "Archive Management" section.
4.  **Testing & Documentation:** Validate the integrity of archived data and document procedures for auditors.