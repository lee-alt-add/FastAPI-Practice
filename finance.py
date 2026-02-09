from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer
from sqlmodel import Field, select, Session, SQLModel, create_engine
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

# Configurations
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Responsible for encrypting and verifying encrypted passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Responsible for created a token for user
oauth2_scheme = OAuth2AuthorizationCodeBearer(tokenUrl="token")

# DB Tables
class User(SQLModel, table=True):
    id : Optional[int] = Field(default=None, primary_key=True)
    username : str = Field(unique=True, index=True)
    hashed_password: str

class Expenses(SQLModel, table=True):
    id : Optional[int] = Field(default=None, primary_key=True)
    description : str
    amount : float
    currency : str = "ZAR"
    created_at: datetime = Field(default_factory=datetime.now())

class Income(SQLModel, table=True):
    id : Optional[int] = Field(default=None, primary_key=True)
    description : str
    amount : float
    currency : str = "ZAR"
    created_at: datetime = Field(default_factory=datetime.now())


# Database setup
sqlite_url = "sqlite:///app.db"
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

def get_session():
    with Session(engine) as session:
        yield session

app = FastAPI()

app.on_event("startup")
def startup():
    SQLModel.metadata.create_all(engine)

# Security utilities
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user = session.exec(select(User).where(User.username == username)).first()
        if user is None:
            raise HTTPException(status_code=401, detail="User Not Found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")