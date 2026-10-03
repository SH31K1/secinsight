"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-18

"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tool", sa.String(50), index=True),
        sa.Column("target", sa.String(255), nullable=True, index=True),
        sa.Column("source_filename", sa.String(255), nullable=True),
        sa.Column("score", sa.Integer),
        sa.Column("grade", sa.String(2)),
        sa.Column("counts", sa.JSON),
        sa.Column("scan_json", sa.JSON),
        sa.Column("created_at", sa.DateTime, index=True),
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), index=True),
        sa.Column("format", sa.String(10)),
        sa.Column("mode", sa.String(10)),
        sa.Column("file_path", sa.String(500)),
        sa.Column("created_at", sa.DateTime),
    )


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("scans")
