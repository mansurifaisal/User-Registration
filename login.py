# Import libraries
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from typing import Optional
import random

# FastAPI instance
app = FastAPI(title="User Registration")
security = OAuth2PasswordBearer(tokenUrl="/login")

# JWT authentication
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password Security
PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

# SQLite database
SQLALCHEMY_DATABASE_URL = "sqlite:///./Auth.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# database models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(50), unique=True, index=True)
    password = Column(String(50))
    full_name = Column(String(50))
    joined_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Integer, default=1)
    otp = Column(String, nullable=True)
    otp_expiry = Column(DateTime, nullable=True)


# database tables
Base.metadata.create_all(bind=engine)


# Pydantic models for request and response
class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None


class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    email: str
    password: str


class UserOTP(BaseModel):
    email: str


class UserNewPassword(BaseModel):
    email: str
    otp: str
    new_password: str


class UserChangePassword(BaseModel):
    old_password: str
    new_password: str


# functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_by_email(db, email):
    return db.query(User).filter(User.email == email).first()


def create_user(db, user):
    db_user = User(email=user.email, password=user.password, full_name=user.full_name)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def generate_otp():
    otp = ""
    for i in range(6):
        otp += str(random.randint(0, 9))
    return otp


def verify_password(plain_password: str, hashed_password: str):
    return PWD_CONTEXT.verify(plain_password, hashed_password)


def hash_password(password: str):
    return PWD_CONTEXT.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# API endpoints

@app.post("/register")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    user.password = hash_password(user.password)
    db_user = create_user(db, user)
    return db_user


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_email(db, form_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or password")
    if not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/forgot-password")
async def forgot_password(user: UserOTP, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if not db_user:
        raise HTTPException(status_code=400, detail="Email not registered")
    otp = generate_otp()
    db_user.otp = otp
    db_user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.commit()
    return f"your OTP is: {otp}"


@app.post("/reset-password")
async def reset_password(user: UserNewPassword, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if not db_user:
        raise HTTPException(status_code=400, detail="Email not registered")
    db_user.password = hash_password(user.new_password)
    db_user.otp = None
    db_user.otp_expiry = None
    db.commit()
    return {"detail": "Password reset successful"}


@app.put("/change-password")
async def change_password(password: str, current_password: str, token: str = Depends(security),
                          db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Invalid email or password")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    db_user = get_user_by_email(db, email)
    if not db_user:
        raise credentials_exception
    if not verify_password(current_password, db_user.password):
        raise credentials_exception
    db_user.password = hash_password(password)
    db.commit()
    return {"detail": "Password changed successfully"}


@app.put("/update-self-info")
async def update_user_info(new_name: str, token: str = Depends(security),
                           db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user_db = db.query(User).filter(User.email == email).first()
        if not user_db:
            raise HTTPException(status_code=404, detail="User not found")
        user_db.full_name = new_name
        db.commit()
        return {"message": "User information updated successfully"}
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


@app.delete("/delete-user")
async def delete_user(token: str = Depends(security), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user_db = db.query(User).filter(User.email == email).first()
        if not user_db:
            raise HTTPException(status_code=404, detail="User not found")
        db.delete(user_db)
        db.commit()
        return {"message": "User account deleted successfully"}
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
