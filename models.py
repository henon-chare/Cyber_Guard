# models.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    
    # --- Security & Lockout Columns ---
    locked_until = Column(DateTime, nullable=True) 
    is_locked = Column(Boolean, default=False)
    failed_attempts = Column(Integer, default=0)

    # --- Password Reset Columns ---
    reset_token = Column(String, nullable=True)
    reset_token_expires = Column(DateTime, nullable=True) 

    # --- Relationships ---
    domains = relationship("Domain", back_populates="owner")
    monitors = relationship("Monitor", back_populates="owner")

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    attempt_time = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean)
    user = relationship("User")

# models.py

# models.py

class Domain(Base):
    __tablename__ = "tracked_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True) 
    
    
    security_score = Column(Integer, default=0)
    last_scanned = Column(DateTime, default=datetime.utcnow)
    
    # JSON strings for storing scan results
    ssl_data = Column(String(2000), default='{}')
    whois_data = Column(String(2000), default='{}')
    dns_data = Column(String(2000), default='{}')
    
    # THIS LINE MUST BE HERE, INDENTED TO MATCH THE OTHER COLUMNS
    manual_data = Column(String(2000), default='{}')

    # Relationship
    owner = relationship("User", back_populates="domains")

class Monitor(Base):
    __tablename__ = "monitors"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_url = Column(String(500), nullable=False)
    friendly_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="monitors")
    logs = relationship("MonitorLog", back_populates="monitor", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="monitor", cascade="all, delete-orphan")


class MonitorLog(Base):
    __tablename__ = "monitor_logs"
    id = Column(Integer, primary_key=True, index=True)
    monitor_id = Column(Integer, ForeignKey("monitors.id"), nullable=False)
    status_code = Column(Integer, nullable=True)
    response_time = Column(Float, nullable=True)
    is_up = Column(Boolean, default=False)
    checked_at = Column(DateTime, default=datetime.utcnow, index=True)
    monitor = relationship("Monitor", back_populates="logs")


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    monitor_id = Column(Integer, ForeignKey("monitors.id"), nullable=False)
    status = Column(String(50), default="Ongoing")
    error_type = Column(String(100), nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    ended_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    monitor = relationship("Monitor", back_populates="incidents")