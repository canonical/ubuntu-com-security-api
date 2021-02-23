import os

from sqlalchemy import create_engine
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.orm import scoped_session, sessionmaker

from webapp.models import Release, BaseFilterQuery

db_engine = create_engine(os.environ["DATABASE_URL"])
db_session = scoped_session(
    sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=db_engine,
        query_cls=BaseFilterQuery,
    )
)

inspector = Inspector.from_engine(db_engine)

release_codenames = []
if "release" in inspector.get_table_names():
    release_codenames = [
        rel.codename for rel in db_session.query(Release).all()
    ]

status_statuses = []
for enum in inspector.get_enums():
    if enum["name"] == "statuses":
        status_statuses = enum["labels"]
