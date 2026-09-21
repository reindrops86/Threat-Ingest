from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def session_factory(database_url: str) -> sessionmaker[Session]:
    return sessionmaker(create_engine(database_url, pool_pre_ping=True), expire_on_commit=False)