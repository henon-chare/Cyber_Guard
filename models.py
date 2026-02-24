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
    # 1. Existing relationship to tracked_domains (renamed)
    domains = relationship("Domain", back_populates="owner")
    
    # 2. NEW: Relationship to monitors (Uptime monitoring)
    monitors = relationship("Monitor", back_populates="owner")

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    attempt_time = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean)
    user = relationship("User")

# --- UPDATED: Renamed Table ---
class Domain(Base):
    __tablename__ = "tracked_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True) 
    
    # Monitoring & Tracking Data
    security_score = Column(Integer, default=0)
    last_scanned = Column(DateTime, default=datetime.utcnow)
    
    # JSON strings for storing scan results
    ssl_data = Column(String(2000), default='{}')
    whois_data = Column(String(2000), default='{}')
    dns_data = Column(String(2000), default='{}')
    
    # Relationship
    owner = relationship("User", back_populates="domains")

# ==================================================================================
#                              NEW TABLES START HERE
# ==================================================================================

class Monitor(Base):
    """
    Stores the list of websites a user wants to monitor for uptime.
    """
    __tablename__ = "monitors"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # The URL being monitored (e.g., https://google.com)
    target_url = Column(String(500), nullable=False)
    
    # A custom name the user gives (e.g., "Main Website")
    friendly_name = Column(String(255), nullable=True)
    
    # To pause monitoring without deleting it
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    owner = relationship("User", back_populates="monitors")
    
    # Relationship to logs (if monitor is deleted, delete its logs)
    logs = relationship("MonitorLog", back_populates="monitor", cascade="all, delete-orphan")
    
    # Relationship to incidents
    incidents = relationship("Incident", back_populates="monitor", cascade="all, delete-orphan")


class MonitorLog(Base):
    """
    Stores the result of every single check (every 1.5 seconds).
    """
    __tablename__ = "monitor_logs"

    id = Column(Integer, primary_key=True, index=True)
    monitor_id = Column(Integer, ForeignKey("monitors.id"), nullable=False)
    
    # The HTTP status code (200, 404, 500, etc.)
    status_code = Column(Integer, nullable=True)
    
    # How long the request took in milliseconds
    response_time = Column(Float, nullable=True)
    
    # Boolean flag for easy calculation of uptime
    is_up = Column(Boolean, default=False)
    
    # Timestamp of the check
    checked_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationship
    monitor = relationship("Monitor", back_populates="logs")


class Incident(Base):
    """
    Stores records of downtime events.
    """
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    monitor_id = Column(Integer, ForeignKey("monitors.id"), nullable=False)
    
    # 'Ongoing' or 'Resolved'
    status = Column(String(50), default="Ongoing")
    
    # Type of error: 'Timeout', '404', 'Connection Refused', etc.
    error_type = Column(String(100), nullable=True)
    
    # When the incident started
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # When it ended (NULL if still ongoing)
    ended_at = Column(DateTime, nullable=True)
    
    # Calculated duration in seconds
    duration_seconds = Column(Integer, nullable=True)

    # Relationship
    monitor = relationship("Monitor", back_populates="incidents")

# ==================================================================================
#                              NEW TABLES END HERE
# ==================================================================================