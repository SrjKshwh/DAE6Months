# Learning Project: Data Archiving and Retention Implementation

This folder contains documentation, plans, and preparation materials for a self-learning project focused on implementing data archiving and retention features in the GRC Portal application. The project demonstrates practical application of Flask-SQLAlchemy migrations and APScheduler for automated background tasks to ensure regulatory compliance with long-term data retention requirements (e.g., 7 years for SOX/GDPR).

## Files Overview

### [`plan.md`](plan.md)
The main implementation plan outlining the chosen technology (Flask-SQLAlchemy Migrations & APScheduler) and three core tasks:
- **Task 1**: Schema design and migration for archiving tables
- **Task 2**: Development and testing of core archiving functions
- **Task 3**: Integration of scheduled jobs for automated archiving

Includes start dates, target completion dates, success criteria, and proof methods for each task.

### [`plan_subDivided.md`](plan_subDivided.md)
A detailed breakdown of the implementation workflow divided into four phases:
- **Phase 1**: Database setup and migration
- **Phase 2**: Core archiving logic development
- **Phase 3**: Automation and admin interface integration
- **Phase 4**: Safety measures, performance tuning, and documentation

Provides step-by-step guidance for each phase with specific implementation details.

### [`mock_interview.md`](mock_interview.md)
A living document containing mock interview questions and answers based on the learning project. Includes:
- Template for preparing technical interview responses
- Examples of how to structure answers with code snippets, logs, and evidence
- Tips for explaining the project clearly and confidently
- Questions covering technology choices, integration challenges, testing, and improvements

### [`Data Archiving and Retention Implementation Plan.pdf`](Data%20Archiving%20and%20Retention%20Implementation%20Plan.pdf)
PDF document containing the comprehensive implementation plan for data archiving and retention features in the GRC Portal.

## Technology Stack
- **Flask-SQLAlchemy**: For database schema management and migrations
- **APScheduler**: For task scheduling and automation
- **SQLite**: Local database for development and testing

## Learning Objectives
- Master database migrations for schema changes
- Implement automated background processes
- Ensure regulatory compliance through data retention policies
- Develop admin interfaces for configuration management
- Prepare for technical interviews through reflective documentation

## Project Context
This learning project is part of Semester 5 coursework, focusing on practical application of cybersecurity and software development concepts in a Governance, Risk, and Compliance (GRC) portal.