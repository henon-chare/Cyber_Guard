# auth.py

from fastapi import HTTPException
from pydantic import EmailStr
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import re
import uuid
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

# ---------------- Password & Lock Settings ----------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
MAX_ATTEMPTS = 5
LOCK_DURATION = timedelta(minutes=30)

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def validate_password(password: str, username: str):
    if len(password) < 8:
        return False, "Password too short"
    if username.lower() in password.lower():
        return False, "Password too similar to username"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain uppercase"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain lowercase"
    if not re.search(r"\d", password):
        return False, "Password must contain a number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain a special character"
    return True, ""

# ---------------- Email Setup ----------------
conf = ConnectionConfig(
    MAIL_USERNAME="henonchare21@gmail.com",
    MAIL_PASSWORD="pcfo czmw tnce becs ",
    MAIL_FROM="henonchare21@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True
)


async def send_reset_email(email, token):
    # CRITICAL FIX: subtype="html" is now present
    message = MessageSchema(
        subject="Password Reset",
        recipients=[email],
        body=f"Click here to reset your password: <a href='http://localhost:3000/reset-password/{token}'>Reset Password</a>",
        subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)

# ---------------- Auth Functions ----------------

def register_user(db: Session, User, username: str, email: EmailStr, password: str):
    valid, msg = validate_password(password, username)
    if not valid:
        raise HTTPException(status_code=400, detail=msg)
    
    existing = db.query(User).filter((User.username==username)|(User.email==email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    new_user = User(
        username=username,
        email=email,
        password_hash=hash_password(password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

def login_user(db: Session, User, LoginAttempt, username: str, password: str):
    user = db.query(User).filter(User.username==username).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    
    # Check lock
    if user.is_locked and user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(status_code=403, detail=f"Account locked until {user.locked_until}")
    elif user.is_locked and user.locked_until and user.locked_until <= datetime.utcnow():
        user.is_locked = False
        user.locked_until = None
        db.commit()
    
    if not verify_password(password, user.password_hash):
        attempt = LoginAttempt(user_id=user.id, success=False)
        db.add(attempt)
        db.commit()

        attempts = db.query(LoginAttempt).filter(
            LoginAttempt.user_id==user.id,
            LoginAttempt.success==False,
            LoginAttempt.attempt_time > datetime.utcnow() - timedelta(minutes=30)
        ).count()

        if attempts >= MAX_ATTEMPTS:
            user.is_locked = True
            user.locked_until = datetime.utcnow() + LOCK_DURATION
            db.commit()
            raise HTTPException(status_code=403, detail="Account locked for 30 minutes")

        raise HTTPException(status_code=400, detail="Incorrect password")
    
    attempt = LoginAttempt(user_id=user.id, success=True)
    db.add(attempt)
    db.commit()
    return {"message": "Login successful"}

async def forgot_password(db: Session, User, email: EmailStr):
    user = db.query(User).filter(User.email==email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Email not found")
    
    token = str(uuid.uuid4())
    user.reset_token = token
    db.commit()
    await send_reset_email(user.email, token)
    return {"message": "Password reset email sent"}

def reset_password(db: Session, User, token: str, new_password: str):
    user = db.query(User).filter(User.reset_token==token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")
    
    valid, msg = validate_password(new_password, user.username)
    if not valid:
        raise HTTPException(status_code=400, detail=msg)
    
    user.password_hash = hash_password(new_password)
    user.reset_token = None
    db.commit()
    return {"message": "Password reset successful"}