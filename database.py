from sqlmodel import Field, Session, SQLModel, create_engine
from typing import Optional
from datetime import datetime


# Database setup
sqlite_url = "sqlite:///app.db"
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

# Dependency to get DB session
def get_session():
    """Utility function to get a database session."""

    with Session(engine) as session:
        yield session

def update_db(session: Session, instance, refresh: bool = True, delete: bool = False):
    """Utility function to add, update, or delete an instance in the database."""

    if delete:
        session.delete(instance)
    else:
        session.add(instance)
        
    session.commit()
    if refresh:
        session.refresh(instance)
    return instance

# DB Tables
class User(SQLModel, table=True):
    id : Optional[int] = Field(default=None, primary_key=True)
    username : str = Field(unique=True, index=True)
    hashed_password: str

class Expense(SQLModel, table=True):
    id : Optional[int] = Field(default=None, primary_key=True)
    description : str
    amount : float
    owner_id: int
    currency : str = "ZAR"
    created_at: datetime = Field(default_factory=datetime.now)

class Income(SQLModel, table=True):
    id : Optional[int] = Field(default=None, primary_key=True)
    description : str
    amount : float
    owner_id: int
    currency : str = "ZAR"
    created_at: datetime = Field(default_factory=datetime.now)

