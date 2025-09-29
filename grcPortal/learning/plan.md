Name: Saroj Kushwaha

Date created: 2025-10-04

Chosen technology (name): **Flask-SQLAlchemy Migrations & Task Scheduling (e.g., APScheduler)**
                            (SQLAlchemy 2.0 / APScheduler 3.x)

**Why I chose this technology**

This technology is crucial for implementing a **data retention and archiving feature** by allowing me to safely modify the database schema (add archive tables) and automate the background process of moving old records. This capability ensures the grcPortal remains compliant with long-term data retention regulations (e.g., 7 years for SOX/GDPR) without impacting the performance of the live application.

---


Task 1 — **Schema Design and Migration for Archiving**

Description: Use Flask-SQLAlchemy to create the `retention_config` table and a corresponding `risk_archive` table with an identical schema to the main `risk` table.

Start date: 2025-10-07

Target completion date: 2025-10-11

Success criterion: Database migrations successfully run, and the two new tables (`retention_config` and `risk_archive`) are present in the database with the correct columns, as verified by a SQL query.

Proof method: Screenshot of the successful migration script output and a terminal output showing the schema (e.g., `sqlite3 .schema`) pasted into `learning/README.md`.
Where I will start Task 1: with local database (SQLite)

---


Task 2 — **Develop and Test Core Archiving Function**

Description: Implement a Python function, `archive_old_risks()`, that uses a hardcoded date and condition (e.g.- older than 2 days and number of rows in database table is more than 25) to select records from the `risk`, `audit`, and etc. table and move them to the `risk_archive`, and `audit_archive` table.

Start date: 2025-10-14

Target completion date: 2025-10-18

Success criterion: A manual test successfully moves 5 out of 10 sample records from the `risk` table to the `risk_archive` table, and the move is verified by record counts on both tables.

Proof method: Screenshot of the console log showing the function execution and SQL query results (before/after record counts) pasted into `learning/README.md`.

---


Task 3 — **Integrate Basic Scheduled Job**

Description: Integrate APScheduler to run the `archive_old_risks()` function developed in Task 2 on a fixed schedule (e.g., every 5 minutes) and log the event to the console.

Start date: 2025-10-21

Target completion date: 2025-10-25

Success criterion: The scheduler successfully executes the archiving function at least once, and the console log shows the scheduled job running and the function output without errors.

Proof method: A short screen recording (e.g., GIF or video link) showing the application running and the scheduled job firing multiple times in the console output.

---