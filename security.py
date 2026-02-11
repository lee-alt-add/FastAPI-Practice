import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import select, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from database import User, get_session

# Configurations
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Responsible for hashing and verifying hashed passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Responsible for getting a token from the request header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


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
        expiry = payload.get("exp")

        if datetime.now().timestamp() > expiry:
            raise HTTPException(status_code=401, detail="Token expired")
        
        user = session.exec(select(User).where(User.username == username)).first()
        if user is None:
            raise HTTPException(status_code=401, detail="User Not Found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
