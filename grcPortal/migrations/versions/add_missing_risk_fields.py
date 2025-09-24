"""Add missing risk fields

Revision ID: add_missing_risk_fields
Revises: 34558889d887
Create Date: 2025-09-24 17:48:30.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_missing_risk_fields'
down_revision = '34558889d887'
branch_labels = None
depends_on = None


def upgrade():
    # Add missing columns to risks table
    op.add_column('risks', sa.Column('annual_occurrence_probability', sa.Float(), nullable=True))
    op.add_column('risks', sa.Column('ale_calculated', sa.Float(), nullable=True))
    op.add_column('risks', sa.Column('emv_calculated', sa.Float(), nullable=True))
    op.add_column('risks', sa.Column('evaluation_criteria', sa.Text(), nullable=True))
    op.add_column('risks', sa.Column('stakeholder_approval_required', sa.Boolean(), nullable=False, default=True))
    op.add_column('risks', sa.Column('stakeholder_approval_notes', sa.Text(), nullable=True))
    op.add_column('risks', sa.Column('mitigation_plan_json', sa.Text(), nullable=True))
    op.add_column('risks', sa.Column('mitigation_plan_updated', sa.DateTime(), nullable=True))


def downgrade():
    # Remove the added columns
    op.drop_column('risks', 'mitigation_plan_updated')
    op.drop_column('risks', 'mitigation_plan_json')
    op.drop_column('risks', 'stakeholder_approval_notes')
    op.drop_column('risks', 'stakeholder_approval_required')
    op.drop_column('risks', 'evaluation_criteria')
    op.drop_column('risks', 'emv_calculated')
    op.drop_column('risks', 'ale_calculated')
    op.drop_column('risks', 'annual_occurrence_probability')