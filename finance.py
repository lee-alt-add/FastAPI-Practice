from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
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

# Responsible for hashing and verifying hashed passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Responsible for getting a token from the request header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

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
    created_at: datetime = Field(default_factory=datetime.now())


# Database setup
sqlite_url = "sqlite:///app.db"
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

# Dependency to get DB session
def get_session():
    with Session(engine) as session:
        yield session

app = FastAPI()

# Create tables on startup
@app.on_event("startup")
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

@app.post("/register")
def register(username: str, password: str, session: Session =Depends(get_session)):
    hashed_password = pwd_context.hash(password)
    user = User(username=username, hashed_password=hashed_password)
    session.add(user)
    session.commit()
    return {"message": "User created"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/expense", response_model=Expense)
def add_expense(data: dict, current_user: User=Depends(get_current_user), session: Session=Depends(get_session)):
    new_expense = Expense(
        description=data["description"], 
        amount=float(data["amount"]), 
        owner_id=current_user.id
        )
    session.add(new_expense)
    session.commit()
    session.refresh(new_expense)
    return new_expense

@app.post("/income", response_model=Income)
def add_income(data: dict, current_user: User=Depends(get_current_user), session: Session=Depends(get_session)):
    new_income = Income(
        description=data["description"], 
        amount=float(data["amount"]), 
        owner_id=current_user.id
        )
    session.add(new_income)
    session.commit()
    session.refresh(new_income)
    return new_income
