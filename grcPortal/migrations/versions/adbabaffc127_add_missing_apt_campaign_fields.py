"""add_missing_apt_campaign_fields

Revision ID: adbabaffc127
Revises: 5d40d1ae9f18
Create Date: 2025-11-17 15:31:17.160070

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'adbabaffc127'
down_revision = '5d40d1ae9f18'
branch_labels = None
depends_on = None


def upgrade():
    # Add missing columns to apt_campaigns table
    op.add_column('apt_campaigns', sa.Column('analysis_type', sa.String(length=100), nullable=True))
    op.add_column('apt_campaigns', sa.Column('malware_sample', sa.String(length=500), nullable=True))
    op.add_column('apt_campaigns', sa.Column('reverse_engineering_output', sa.Text(), nullable=True))
    op.add_column('apt_campaigns', sa.Column('attack_patterns', sa.Text(), nullable=True))
    op.add_column('apt_campaigns', sa.Column('iocs_extracted', sa.Text(), nullable=True))


def downgrade():
    # Remove the added columns
    op.drop_column('apt_campaigns', 'iocs_extracted')
    op.drop_column('apt_campaigns', 'attack_patterns')
    op.drop_column('apt_campaigns', 'reverse_engineering_output')
    op.drop_column('apt_campaigns', 'malware_sample')
    op.drop_column('apt_campaigns', 'analysis_type')
