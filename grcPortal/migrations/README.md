# 🗄️ Migrations Directory

This directory contains database migration scripts and configuration for the GRC Portal, managing schema evolution and data transformations using Flask-Migrate (Alembic).

## 📂 Directory Structure

```
migrations/
├── README.md                   # This documentation
├── alembic.ini                # Alembic configuration file
├── env.py                     # Migration environment script
├── README                     # Legacy README (deprecated)
├── script.py.mako             # Migration script template
└── versions/                  # Migration script versions
    ├── [revision_id].py       # Individual migration scripts
    ├── 34558889d887_add_risk_management_program_models.py
    ├── add_missing_risk_fields.py
    └── [additional migrations]
```

## 🔧 Alembic Configuration

### alembic.ini
**Main configuration file for Alembic migration tool:**
```ini
[alembic]
script_location = migrations
sqlalchemy.url = driver://user:pass@localhost/dbname

[post_write_hooks]
# Hooks for post-migration actions

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic
```

### Environment Configuration (env.py)
**Migration environment and connection setup:**
```python
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

# Import application models
from models import Base

# Configure logging
fileConfig(config.config_file_name)

def run_migrations_offline():
    """Run migrations in 'offline' mode"""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations in 'online' mode"""
    connectable = engine_from_config(
        config.get_section(config.config_file_name),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
```

## 📋 Migration Scripts

### Migration File Structure
Each migration file follows the pattern: `{revision_id}_{description}.py`

**Example Migration:**
```python
"""add_risk_management_program_models

Revision ID: 34558889d887
Revises: abc123def456
Create Date: 2024-12-01 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic
revision = '34558889d887'
down_revision = 'abc123def456'
branch_labels = None
depends_on = None

def upgrade():
    """Upgrade database schema"""
    # Create new tables
    op.create_table('risk_management_frameworks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('version', sa.String(length=20), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Add new columns
    op.add_column('risks', sa.Column('evaluation_criteria', sa.Text(), nullable=True))

    # Create indexes
    op.create_index('ix_risk_management_frameworks_name', 'risk_management_frameworks', ['name'])

def downgrade():
    """Downgrade database schema"""
    # Reverse operations in opposite order
    op.drop_index('ix_risk_management_frameworks_name', 'risk_management_frameworks')
    op.drop_column('risks', 'evaluation_criteria')
    op.drop_table('risk_management_frameworks')
```

## 🚀 Migration Workflow

### Creating New Migrations
```bash
# Generate migration for model changes
flask db migrate -m "add new feature models"

# Review generated migration
# Edit migrations/versions/[revision_id].py as needed

# Apply migration
flask db upgrade

# Rollback if needed
flask db downgrade
```

### Migration Commands
```bash
# Initialize migrations (first time)
flask db init

# Create migration from model changes
flask db migrate -m "migration description"

# Apply migrations
flask db upgrade

# Rollback migrations
flask db downgrade

# Show migration status
flask db current

# Show migration history
flask db history

# Check for pending migrations
flask db check
```

## 📊 Database Schema Evolution

### Major Schema Versions

#### Version 1.0 - Core GRC Models
- User authentication and authorization
- Basic risk assessment (NIST RMF)
- Compliance framework mapping
- Incident management
- Audit logging

#### Version 2.0 - Advanced Risk Management
- Risk management program lifecycle
- Gap analysis and remediation tracking
- Critical asset register
- Environmental change monitoring
- Risk indicators and KPIs

#### Version 3.0 - AI Integration (Current)
- AI-powered risk analysis
- Multi-criteria risk scoring
- Automated mitigation planning
- Communication strategy generation
- Continuous monitoring enhancements

### Schema Relationships
```
User (1) --> (*) Upload
User (1) --> (*) Incident
User (1) --> (*) RiskApproval
User (1) --> (*) AuditLog

Risk (1) --> (*) Compliance
Risk (1) --> (*) RiskApproval
Risk (1) --> (*) GovernanceDecision

Incident (1) --> (*) Evidence

RiskManagementFramework (1) --> (*) RiskProgramPlan
RiskProgramPlan (1) --> (*) ProgramPhase
RiskProgramPlan (1) --> (*) GapAnalysis
```

## 🔒 Data Integrity & Safety

### Migration Safety Features
- **Transaction Wrapping**: All migrations run in transactions
- **Rollback Support**: Ability to reverse migrations
- **Data Preservation**: Careful handling of existing data
- **Dependency Checking**: Migration dependency validation

### Backup Requirements
```bash
# Backup before migration
pg_dump grc_portal > backup_pre_migration.sql

# Or for SQLite
cp instance/app.db instance/app.db.backup

# Restore if needed
pg_restore -d grc_portal backup_pre_migration.sql
```

### Testing Migrations
```python
# Test migration in development
def test_migration_upgrade():
    """Test migration upgrade"""
    # Create test database
    engine = create_engine("sqlite:///:memory:")

    # Run migration
    command.upgrade(config, revision)

    # Verify schema changes
    inspector = inspect(engine)
    assert "new_table" in inspector.get_table_names()

def test_migration_downgrade():
    """Test migration downgrade"""
    # Test rollback capability
    command.downgrade(config, revision)
    # Verify schema reverted
```

## 📈 Migration Monitoring

### Migration Status Tracking
```python
# Check migration status
from alembic import command
from alembic.config import Config

config = Config("migrations/alembic.ini")
command.current(config)  # Show current revision
command.history(config)  # Show migration history
```

### Automated Migration Checks
```bash
# Pre-deployment migration check
#!/bin/bash
flask db check
if [ $? -ne 0 ]; then
    echo "Pending migrations found. Run 'flask db upgrade' before deployment."
    exit 1
fi
```

## 🏗️ Advanced Migration Patterns

### Data Migrations
```python
def upgrade():
    # Schema change
    op.add_column('risks', sa.Column('new_field', sa.String(100)))

    # Data migration
    connection = op.get_bind()
    connection.execute(
        sa.text("UPDATE risks SET new_field = 'default_value' WHERE new_field IS NULL")
    )

def downgrade():
    # Reverse data migration first
    connection = op.get_bind()
    connection.execute(
        sa.text("UPDATE risks SET new_field = NULL")
    )

    # Then schema change
    op.drop_column('risks', 'new_field')
```

### Conditional Migrations
```python
def upgrade():
    # Check if column exists
    bind = op.get_bind()
    inspector = inspect(bind)

    if 'new_column' not in [col['name'] for col in inspector.get_columns('table_name')]:
        op.add_column('table_name', sa.Column('new_column', sa.String(100)))
```

### Multi-Database Support
```python
# For multi-tenant or multi-database setups
def upgrade():
    # Run migration on multiple databases
    databases = ['tenant1', 'tenant2', 'tenant3']

    for db_name in databases:
        # Switch database context
        with op.batch_alter_table("users", schema=db_name) as batch_op:
            batch_op.add_column(sa.Column('tenant_id', sa.Integer()))
```

## 🔧 Configuration

### Production Configuration
```python
# Production migration settings
MIGRATION_CONFIG = {
    "safety_checks": True,      # Enable safety validations
    "backup_required": True,    # Require backup before migration
    "dry_run": False,          # Enable dry-run mode for testing
    "timeout": 300,            # Migration timeout in seconds
    "batch_size": 1000         # Batch size for large data migrations
}
```

### Environment-Specific Settings
```bash
# Development
FLASK_ENV=development
DATABASE_URL=sqlite:///instance/app.db

# Production
FLASK_ENV=production
DATABASE_URL=postgresql://user:pass@host:5432/grc_prod

# Testing
FLASK_ENV=testing
DATABASE_URL=sqlite:///:memory:
```

## 📋 Migration Best Practices

### Development Workflow
1. **Make Model Changes**: Update SQLAlchemy models in `models.py`
2. **Generate Migration**: `flask db migrate -m "description"`
3. **Review Migration**: Check generated script for accuracy
4. **Test Migration**: Run in development environment
5. **Commit Migration**: Include migration in version control

### Production Deployment
1. **Backup Database**: Create full backup before migration
2. **Test Migration**: Run in staging environment first
3. **Schedule Maintenance**: Plan deployment during low-traffic periods
4. **Monitor Migration**: Watch for performance and errors
5. **Verify Success**: Confirm application functionality post-migration

### Migration Guidelines
- **Atomic Changes**: Each migration should be a single, reversible change
- **Descriptive Names**: Use clear, descriptive migration messages
- **Data Safety**: Never delete data without backup
- **Testing**: Test both upgrade and downgrade paths
- **Documentation**: Document complex migrations thoroughly

## 🚨 Troubleshooting

### Common Issues

#### Migration Fails with Data Error
```bash
# Check data constraints
flask db check

# Fix data issues
# Then retry migration
flask db upgrade
```

#### Migration Stuck/Locked
```bash
# For PostgreSQL
# Check for active locks
SELECT * FROM pg_locks WHERE NOT granted;

# Kill blocking processes if safe
SELECT pg_cancel_backend(pid);
```

#### Migration Version Mismatch
```bash
# Check current version
flask db current

# Force specific version (careful!)
flask db stamp head
```

### Recovery Procedures
1. **Stop Application**: Prevent new transactions during recovery
2. **Assess Damage**: Determine extent of migration failure
3. **Restore Backup**: Rollback to pre-migration state if needed
4. **Fix Issues**: Address root cause of migration failure
5. **Retry Migration**: Apply corrected migration
6. **Verify Integrity**: Test application functionality

## 🔮 Future Enhancements

### Advanced Features
- **Blue-Green Deployments**: Zero-downtime migrations
- **Canary Releases**: Gradual migration rollout
- **Schema Diffing**: Automated schema comparison
- **Migration Testing**: Automated migration validation
- **Multi-Tenant Migrations**: Tenant-specific schema updates

### Integration Capabilities
- **CI/CD Integration**: Automated migration in deployment pipelines
- **Monitoring**: Migration performance and success tracking
- **Rollback Automation**: Automated rollback on failure detection
- **Audit Logging**: Comprehensive migration audit trails

---

**🗄️ For database schema details, see [../docs/index.md#database](../docs/index.md#database)**

**🔗 Back to main project: [../README.md](../README.md)**