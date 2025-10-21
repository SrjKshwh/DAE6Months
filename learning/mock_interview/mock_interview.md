# 🧪 Mock Interview Questions & Answers

This file is a living document of technical and reflective questions based on my Semester 5 self-learning and integration project.  
Use it to prepare for real interviews, practice answering out loud, and reflect on how to explain your work clearly and confidently.



_Last updated: 10/20/2025_

# 📘 GRC Portal – Data Archiving & Retention Project  
**Semester 5 – Cybersecurity and Secure Software Development**

---

## 1. What is the primary purpose of this learning project, and how does it relate to regulatory compliance?

**Answer:**  
The project focuses on implementing **data archiving and retention features** in the GRC Portal application to ensure compliance with long-term data retention regulations such as **SOX** and **GDPR** (typically 7-year retention).  
It demonstrates practical use of **Flask-SQLAlchemy migrations** for schema changes and **APScheduler** for automated background tasks, allowing old records to be archived without impacting live application performance.  
This is part of **Semester 5 coursework**, emphasizing the intersection of **cybersecurity**, **software engineering**, and **Governance, Risk, and Compliance (GRC)**.

---

## 2. What technologies were chosen for this project, and why were they selected?

**Answer:**  
- **Flask-SQLAlchemy (v2.0):** Used for ORM and schema migrations, enabling safe modifications (e.g., creating archive tables).  
- **APScheduler (v3.x):** Handles scheduled background tasks, such as weekly archiving or purging.  
- **SQLite:** Used for local development and testing due to simplicity and easy schema inspection.  

These technologies were selected to ensure:
- Controlled database schema evolution.  
- Automated, reliable archival processes.  
- Compliance with retention policies (e.g., 7-year retention) while maintaining system performance.

---

## 3. Can you describe the three core tasks outlined in the implementation plan?

**Answer:**

### 🧩 Task 1 – Schema Design and Migration for Archiving
- Use **Flask-SQLAlchemy** to create `retention_config` and archive tables (e.g., `risk_archive`) with schemas identical to main tables.  
- **Start:** 2025-10-07 | **Target:** 2025-10-11  
- **Success Criteria:** Verified through migration outputs and schema queries.

### 🧩 Task 2 – Develop and Test Core Archiving Function
- Implement `archive_old_risks()` to move records older than a set date (e.g., 2 days) and where row count > 25.  
- **Start:** 2025-10-14 | **Target:** 2025-10-18  
- **Success Criteria:** Manual test confirming successful record transfer and count verification.

### 🧩 Task 3 – Integrate Basic Scheduled Job
- Use **APScheduler** to run `archive_old_risks()` weekly with logging enabled.  
- **Start:** 2025-10-21 | **Target:** 2025-10-25  
- **Success Criteria:** Verified via scheduled log execution and no runtime errors.

---

## 4. What are the four phases of the subdivided implementation workflow, and what does each phase entail?

**Answer:**

### 🔹 Phase 1 – Database Setup and Migration
- Define SQLAlchemy models for `retention_config` and archive tables (`risk_archive`, etc.).  
- Run migrations and validate database schemas.

### 🔹 Phase 2 – Core Archiving Logic
- Develop `archive_old_records()` to batch-transfer records older than `retention_days` from live tables to archive tables.  
- Add conditions (e.g., row count > 25) and optional `purge_archived_records()` for cleanup.  
- Test with sample data for validation.

### 🔹 Phase 3 – Automation and Admin Integration
- Integrate **APScheduler** for periodic job scheduling.  
- Implement audit logging and an admin UI (`/admin/retention_settings`) for managing retention policies and manual triggers.  
- Validate scheduler performance and logs.

### 🔹 Phase 4 – Safety, Performance, and Documentation
- Add safeguards: admin approval before purging, dry-run mode for testing, backup exports (CSV/JSON).  
- Optimize batch operations and indexing.  
- Add UI statistics and comprehensive documentation for audit readiness.

---

## 5. How does the core archiving function (`archive_old_records()`) work, and what safety measures are included?

**Answer:**  
The function iterates over tables listed in `retention_config`, selecting records older than the configured `retention_days` and moving them from main tables (e.g., `risk`) to their archive counterparts (`risk_archive`).  

**Key Logic & Safeguards:**
- Executes only if the record count exceeds the defined threshold (e.g., >25).  
- Supports **dry-run mode** for validation before execution.  
- Requires **admin approval** for purging archived data.  
- Performs **backup exports** (CSV/JSON) before deletion to prevent data loss.  
- Designed for safe concurrent operation and transaction rollback on errors.

---

## 6. What are the learning objectives of this project, and how does it prepare for technical interviews?

**Answer:**  
**Learning Objectives:**
- Master **database migrations** and schema version control.  
- Implement **automated background processes** using APScheduler.  
- Enforce **regulatory compliance** via data retention and archiving.  
- Build **admin-facing interfaces** for configuration and policy management.  
- Develop habits of **secure coding, documentation, and audit-readiness**.

This project also prepares for technical interviews by providing clear examples of:
- End-to-end software design in a compliance context.  
- Security-conscious database and backend development.  
- Demonstrable problem-solving with automation and optimization.  
- Professional documentation explaining architecture, rationale, and results.

---

**✅ Deliverable Summary:**  
- Flask-SQLAlchemy database models and migrations  
- APScheduler-based background job integration  
- Archive table logic and retention configuration  
- Documentation (`readme.md`, `plan.md`, `plan_subDivided.md`)  
- Demonstration logs and screenshots (schema, migrations, scheduler)

---
