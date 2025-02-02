"""Change password to otp

Revision ID: 9ca5eff0dcd4
Revises: f128e4e89fda
Create Date: 2024-12-09 15:15:07.415383

"""
from alembic import op
import sqlalchemy as sa
import sqlmodel.sql.sqltypes


# revision identifiers, used by Alembic.
revision = '9ca5eff0dcd4'
down_revision = 'f128e4e89fda'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('hashed_otp', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column('user', sa.Column('otp_expires_at', sa.DateTime(), nullable=True))
    op.drop_column('user', 'hashed_password')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('hashed_password', sa.VARCHAR(), autoincrement=False, nullable=False))
    op.drop_column('user', 'otp_expires_at')
    op.drop_column('user', 'hashed_otp')
    # ### end Alembic commands ###
