"""add_advanced_compliance_strategy_models

Revision ID: 03200e221393
Revises: 5a6f6c12291b
Create Date: 2025-11-10 20:07:25.158866

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '03200e221393'
down_revision = '5a6f6c12291b'
branch_labels = None
depends_on = None


def upgrade():
    # Create compliance_strategies table
    op.create_table('compliance_strategies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('organization_name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('geographic_scope', sa.Text(), nullable=True),
        sa.Column('industry_sector', sa.String(length=100), nullable=True),
        sa.Column('employee_count', sa.Integer(), nullable=True),
        sa.Column('annual_revenue', sa.Float(), nullable=True),
        sa.Column('primary_frameworks', sa.Text(), nullable=True),
        sa.Column('secondary_frameworks', sa.Text(), nullable=True),
        sa.Column('regulatory_bodies', sa.Text(), nullable=True),
        sa.Column('strategic_objectives', sa.Text(), nullable=True),
        sa.Column('risk_appetite_statement', sa.Text(), nullable=True),
        sa.Column('compliance_maturity_target', sa.String(length=50), nullable=True),
        sa.Column('conflict_resolution_methodology', sa.String(length=100), nullable=True),
        sa.Column('conflict_prioritization_criteria', sa.Text(), nullable=True),
        sa.Column('total_budget', sa.Float(), nullable=True),
        sa.Column('fte_allocation', sa.Integer(), nullable=True),
        sa.Column('technology_budget', sa.Float(), nullable=True),
        sa.Column('strategy_owner', sa.Integer(), nullable=False),
        sa.Column('approval_authority', sa.String(length=100), nullable=True),
        sa.Column('review_frequency', sa.String(length=50), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('version', sa.String(length=20), nullable=True),
        sa.Column('effective_date', sa.DateTime(), nullable=True),
        sa.Column('next_review_date', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['strategy_owner'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create regulatory_conflicts table
    op.create_table('regulatory_conflicts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('strategy_id', sa.Integer(), nullable=False),
        sa.Column('conflict_title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('framework_a', sa.Enum('NIST_SP_800_53', 'NIST_CSF', 'ISO_27001', 'ISO_27002', 'PCI_DSS', 'HIPAA', 'SOX', 'GDPR', 'CIS_CONTROLS', 'COBIT', name='complianceframework'), nullable=False),
        sa.Column('requirement_a', sa.String(length=255), nullable=False),
        sa.Column('framework_b', sa.Enum('NIST_SP_800_53', 'NIST_CSF', 'ISO_27001', 'ISO_27002', 'PCI_DSS', 'HIPAA', 'SOX', 'GDPR', 'CIS_CONTROLS', 'COBIT', name='complianceframework'), nullable=False),
        sa.Column('requirement_b', sa.String(length=255), nullable=False),
        sa.Column('applicable_regions', sa.Text(), nullable=True),
        sa.Column('business_processes_affected', sa.Text(), nullable=True),
        sa.Column('conflict_severity', sa.String(length=20), nullable=True),
        sa.Column('business_impact', sa.Text(), nullable=True),
        sa.Column('compliance_risk', sa.Text(), nullable=True),
        sa.Column('operational_complexity', sa.String(length=20), nullable=True),
        sa.Column('resolution_strategy', sa.String(length=100), nullable=False),
        sa.Column('resolution_details', sa.Text(), nullable=True),
        sa.Column('implementation_plan', sa.Text(), nullable=True),
        sa.Column('resolution_status', sa.String(length=50), nullable=True),
        sa.Column('resolution_date', sa.DateTime(), nullable=True),
        sa.Column('effectiveness_rating', sa.Integer(), nullable=True),
        sa.Column('identified_by', sa.Integer(), nullable=False),
        sa.Column('resolved_by', sa.Integer(), nullable=True),
        sa.Column('approved_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['approved_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['identified_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['strategy_id'], ['compliance_strategies.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create compliance_roadmaps table
    op.create_table('compliance_roadmaps',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('strategy_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('timeframe_years', sa.Integer(), nullable=True),
        sa.Column('start_date', sa.DateTime(), nullable=False),
        sa.Column('end_date', sa.DateTime(), nullable=True),
        sa.Column('phase_1_objectives', sa.Text(), nullable=True),
        sa.Column('phase_2_objectives', sa.Text(), nullable=True),
        sa.Column('phase_3_objectives', sa.Text(), nullable=True),
        sa.Column('total_budget', sa.Float(), nullable=True),
        sa.Column('budget_breakdown', sa.Text(), nullable=True),
        sa.Column('fte_requirements', sa.Text(), nullable=True),
        sa.Column('technology_investments', sa.Text(), nullable=True),
        sa.Column('milestones', sa.Text(), nullable=True),
        sa.Column('kpis', sa.Text(), nullable=True),
        sa.Column('success_criteria', sa.Text(), nullable=True),
        sa.Column('roadmap_risks', sa.Text(), nullable=True),
        sa.Column('mitigation_strategies', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('progress_percentage', sa.Float(), nullable=True),
        sa.Column('last_progress_update', sa.DateTime(), nullable=True),
        sa.Column('roadmap_owner', sa.Integer(), nullable=False),
        sa.Column('steering_committee', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['roadmap_owner'], ['users.id'], ),
        sa.ForeignKeyConstraint(['strategy_id'], ['compliance_strategies.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create roadmap_milestones table
    op.create_table('roadmap_milestones',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('roadmap_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('milestone_type', sa.String(length=50), nullable=False),
        sa.Column('planned_date', sa.DateTime(), nullable=False),
        sa.Column('actual_completion_date', sa.DateTime(), nullable=True),
        sa.Column('prerequisites', sa.Text(), nullable=True),
        sa.Column('dependencies', sa.Text(), nullable=True),
        sa.Column('budget_allocated', sa.Float(), nullable=True),
        sa.Column('fte_allocated', sa.Float(), nullable=True),
        sa.Column('resources_required', sa.Text(), nullable=True),
        sa.Column('success_criteria', sa.Text(), nullable=True),
        sa.Column('deliverables', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('progress_percentage', sa.Float(), nullable=True),
        sa.Column('delay_reason', sa.String(), nullable=True),
        sa.Column('responsible_party', sa.Integer(), nullable=True),
        sa.Column('approval_required', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['responsible_party'], ['users.id'], ),
        sa.ForeignKeyConstraint(['roadmap_id'], ['compliance_roadmaps.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create compliance_architectures table
    op.create_table('compliance_architectures',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('strategy_id', sa.Integer(), nullable=False),
        sa.Column('architecture_name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('total_employees', sa.Integer(), nullable=True),
        sa.Column('number_of_locations', sa.Integer(), nullable=True),
        sa.Column('geographic_distribution', sa.Text(), nullable=True),
        sa.Column('core_platform', sa.String(length=100), nullable=True),
        sa.Column('integration_platforms', sa.Text(), nullable=True),
        sa.Column('automation_tools', sa.Text(), nullable=True),
        sa.Column('compliance_team_structure', sa.Text(), nullable=True),
        sa.Column('governance_committees', sa.Text(), nullable=True),
        sa.Column('reporting_hierarchy', sa.Text(), nullable=True),
        sa.Column('control_families', sa.Text(), nullable=True),
        sa.Column('control_mappings', sa.Text(), nullable=True),
        sa.Column('automation_coverage', sa.Text(), nullable=True),
        sa.Column('data_collection_methods', sa.Text(), nullable=True),
        sa.Column('data_storage_strategy', sa.String(length=100), nullable=True),
        sa.Column('reporting_capabilities', sa.Text(), nullable=True),
        sa.Column('performance_requirements', sa.Text(), nullable=True),
        sa.Column('high_availability_requirements', sa.Text(), nullable=True),
        sa.Column('disaster_recovery_plan', sa.Text(), nullable=True),
        sa.Column('access_control_model', sa.String(length=100), nullable=True),
        sa.Column('encryption_standards', sa.Text(), nullable=True),
        sa.Column('audit_trail_requirements', sa.Text(), nullable=True),
        sa.Column('implementation_phases', sa.Text(), nullable=True),
        sa.Column('migration_strategy', sa.Text(), nullable=True),
        sa.Column('change_management_approach', sa.Text(), nullable=True),
        sa.Column('total_cost_estimate', sa.Float(), nullable=True),
        sa.Column('cost_breakdown', sa.Text(), nullable=True),
        sa.Column('roi_projections', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('version', sa.String(length=20), nullable=True),
        sa.Column('architecture_owner', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['architecture_owner'], ['users.id'], ),
        sa.ForeignKeyConstraint(['strategy_id'], ['compliance_strategies.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create control_mappings table
    op.create_table('control_mappings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('control_id', sa.String(length=100), nullable=False),
        sa.Column('control_name', sa.String(length=255), nullable=False),
        sa.Column('control_description', sa.Text(), nullable=True),
        sa.Column('framework_mappings', sa.Text(), nullable=True),
        sa.Column('control_family', sa.String(length=100), nullable=True),
        sa.Column('control_type', sa.String(length=50), nullable=True),
        sa.Column('automation_potential', sa.String(length=20), nullable=True),
        sa.Column('implementation_guidance', sa.Text(), nullable=True),
        sa.Column('testing_procedures', sa.Text(), nullable=True),
        sa.Column('evidence_requirements', sa.Text(), nullable=True),
        sa.Column('risk_reduction_potential', sa.Integer(), nullable=True),
        sa.Column('implementation_complexity', sa.String(length=20), nullable=True),
        sa.Column('resource_requirements', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('version', sa.String(length=20), nullable=True),
        sa.Column('last_reviewed', sa.DateTime(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=False),
        sa.Column('approved_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['approved_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('control_mappings')
    op.drop_table('compliance_architectures')
    op.drop_table('roadmap_milestones')
    op.drop_table('compliance_roadmaps')
    op.drop_table('regulatory_conflicts')
    op.drop_table('compliance_strategies')
