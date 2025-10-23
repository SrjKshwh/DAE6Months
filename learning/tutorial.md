# Tutorial: Implementing Data Archiving and Retention in Flask Applications

## Introduction

Data archiving and retention is a critical feature for applications that handle sensitive or regulated data, such as those in Governance, Risk, and Compliance (GRC) systems. This tutorial guides you through implementing automated data archiving and retention using Flask-SQLAlchemy for database migrations and APScheduler for background task scheduling. The goal is to ensure compliance with regulations like SOX or GDPR by automatically moving old records to archive tables and purging them when necessary, without impacting the live application's performance.

This tutorial is based on the learning project in this folder, which demonstrates practical implementation in a GRC Portal application.

## Prerequisites

Before starting, ensure you have:
- Python 3.8+
- Flask and SQLAlchemy installed (`pip install flask flask-sqlalchemy`)
- APScheduler installed (`pip install apscheduler`)
- A basic Flask application with a database (e.g., SQLite for development)
- Understanding of database migrations and scheduling concepts

## Step 1: Setting Up the Database Schema

### 1.1 Define Models for Retention Configuration

Create a model for storing retention policies:

```python
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class RetentionConfig(db.Model):
    __tablename__ = 'retention_config'
    id = db.Column(db.Integer, primary_key=True)
    table_name = db.Column(db.String(50), unique=True, nullable=False)
    retention_days = db.Column(db.Integer, default=2555)  # ~7 years
    archive_enabled = db.Column(db.Boolean, default=True)
    auto_purge = db.Column(db.Boolean, default=False)
```

### 1.2 Create Archive Tables

For each main table (e.g., `risk`, `audit`), create an identical archive table:

```python
class RiskArchive(db.Model):
    __tablename__ = 'risk_archive'
    # Copy all columns from the original Risk model
    id = db.Column(db.Integer, primary_key=True)
    # ... other columns matching Risk table
    archived_at = db.Column(db.DateTime, default=datetime.utcnow)
```

### 1.3 Run Migrations

Use Flask-Migrate to create the tables:

```bash
flask db init
flask db migrate -m "Add retention config and archive tables"
flask db upgrade
```

Verify the tables exist with `sqlite3 yourdb.db .schema`.

## Step 2: Implementing the Core Archiving Function

### 2.1 Develop the Archiving Logic

Create a function to move old records:

```python
from datetime import datetime, timedelta

def archive_old_records():
    configs = RetentionConfig.query.filter_by(archive_enabled=True).all()
    for config in configs:
        table_name = config.table_name
        retention_date = datetime.utcnow() - timedelta(days=config.retention_days)

        # Assuming you have a way to get the model class dynamically
        main_model = get_model_by_name(table_name)
        archive_model = get_archive_model_by_name(table_name)

        # Select old records
        old_records = main_model.query.filter(main_model.created_at < retention_date).all()

        # Move to archive
        for record in old_records:
            archive_record = archive_model(**record.__dict__)
            db.session.add(archive_record)
            db.session.delete(record)

        db.session.commit()
        print(f"Archived {len(old_records)} records from {table_name}")
```

### 2.2 Add Safety Conditions

Include checks like minimum row count:

```python
if len(old_records) > 25:  # Example condition
    # Proceed with archiving
```

### 2.3 Test the Function

Populate your database with test data and run the function manually. Check record counts before and after.

## Step 3: Integrating Scheduled Jobs with APScheduler

### 3.1 Set Up the Scheduler

In your Flask app:

```python
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(func=archive_old_records, trigger="interval", weeks=1)
scheduler.start()
```

### 3.2 Run the Application

Start your Flask app and monitor the console for scheduled job executions.

## Step 4: Building an Admin Interface

### 4.1 Create a Route for Retention Settings

```python
@app.route('/admin/retention_settings', methods=['GET', 'POST'])
@login_required
def retention_settings():
    if request.method == 'POST':
        # Update retention configs
        pass
    configs = RetentionConfig.query.all()
    return render_template('retention_settings.html', configs=configs)
```

### 4.2 Add Manual Trigger

Include a button to run archiving manually:

```html
<form action="/admin/trigger_archive" method="POST">
    <button type="submit">Trigger Archive Now</button>
</form>
```

## Step 5: Safety Measures and Best Practices

- Always backup data before purging.
- Implement dry-run mode for testing.
- Log all operations to an audit trail.
- Require admin approval for purging operations.
- Use batch operations for performance.

## Conclusion

By following this tutorial, you've implemented a robust data archiving and retention system that ensures compliance and maintains application performance. This approach can be extended to other tables and customized for specific regulatory requirements. For the full implementation details, refer to the plan.md and plan_subDivided.md files in this learning folder.

## Additional Resources

- Flask-SQLAlchemy Documentation
- APScheduler Documentation
- GRC Portal Source Code in the grcPortal folder