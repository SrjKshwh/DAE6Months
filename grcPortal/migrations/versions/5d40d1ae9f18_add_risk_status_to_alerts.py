"""add_risk_status_to_alerts

Revision ID: 5d40d1ae9f18
Revises: 03200e221393
Create Date: 2025-11-11 23:59:24.432477

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5d40d1ae9f18'
down_revision = '03200e221393'
branch_labels = None
depends_on = None


def upgrade():
    # Add risk_status column to alerts table
    op.add_column('alerts', sa.Column('risk_status', sa.String(length=50), nullable=False, default='unassessed'))


def downgrade():
    # Remove risk_status column from alerts table
    op.drop_column('alerts', 'risk_status')
