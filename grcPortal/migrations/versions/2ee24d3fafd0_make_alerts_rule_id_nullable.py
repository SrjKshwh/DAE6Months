"""make_alerts_rule_id_nullable

Revision ID: 2ee24d3fafd0
Revises: 9cac64371aed
Create Date: 2025-10-22 14:26:37.155144

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2ee24d3fafd0'
down_revision = '9cac64371aed'
branch_labels = None
depends_on = None


def upgrade():
    # Make rule_id nullable in alerts table
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.alter_column('rule_id',
               existing_type=sa.INTEGER(),
               nullable=True)


def downgrade():
    # Make rule_id NOT NULL in alerts table (reverse migration)
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.alter_column('rule_id',
               existing_type=sa.INTEGER(),
               nullable=False)
