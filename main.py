# ================= main.py =================
import subprocess
import shlex
import sys
import json
import socket
import ssl
import re
import asyncio  # Required for background email tasks
import time # Required for parsing openssl dates
from typing import List, Dict, Any
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship, Session
from pydantic import BaseModel, EmailStr, field_validator

# External Libraries
import whois
import dns.resolver
import requests  
import urllib3
from fastapi_mail import FastMail, MessageSchema

# Suppress InsecureRequestWarning for our requests.get calls
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Local imports
import auth  
from database import Base, engine, get_db
from fastapi.middleware.cors import CORSMiddleware
from monitor import SmartDetector, MonitorState, monitoring_loop
from urllib.parse import urlparse

# ================= MODELS =================

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_locked = Column(Boolean, default=False)
    locked_until = Column(DateTime, nullable=True)
    reset_token = Column(String(100), nullable=True)
    
    # Relationship to Domains
    domains = relationship("Domain", back_populates="owner")

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    attempt_time = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean)
    user = relationship("User")

class Domain(Base):
    __tablename__ = "domains"
    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String(255), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True) # Added for ownership tracking
    security_score = Column(Integer, default=0)
    last_scanned = Column(DateTime, default=datetime.utcnow)
    ssl_data = Column(String(2000), default='{}')
    whois_data = Column(String(2000), default='{}')
    dns_data = Column(String(2000), default='{}')
    
    # Relationship
    owner = relationship("User", back_populates="domains")

# Create tables
Base.metadata.create_all(bind=engine)

# ================= FASTAPI APP =================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

state = MonitorState()

# ================= SCHEMAS =================
class RegisterSchema(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginSchema(BaseModel):
    username: str
    password: str

class ForgotPasswordSchema(BaseModel):
    email: EmailStr

class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str

class StartRequest(BaseModel):
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str):
        v = v.strip()
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        return v

# ================= AUTHENTICATION ROUTES =================

@app.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    return auth.register_user(db, User, data.username, data.email, data.password)

@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    return auth.login_user(db, User, LoginAttempt, data.username, data.password)

@app.post("/forgot-password")
async def forgot_password(data: ForgotPasswordSchema, db: Session = Depends(get_db)):
    return await auth.forgot_password(db, User, data.email)

@app.post("/reset-password")
def reset_password(data: ResetPasswordSchema, db: Session = Depends(get_db)):
    return auth.reset_password(db, User, data.token, data.new_password)

@app.get("/")
def read_root():
    return {"version": "11.0", "model": "Final-Fix"}

# ================= WEBSITE MONITORING ROUTES =================

@app.post("/start")
async def start_monitoring(request: StartRequest, background_tasks: BackgroundTasks):
    if state.is_monitoring:
        raise HTTPException(status_code=400, detail="Already monitoring")

    parsed = urlparse(request.url)
    domain = parsed.netloc
    scheme = parsed.scheme

    common_subdomains = [
        'www', 'api', 'blog', 'shop', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
        'beta', 'forum', 'news', 'app', 'secure', 'login', 'dashboard', 'webmail', 'portal', 'cms'
    ]

    sub_urls = [request.url]
    for sub in common_subdomains:
        sub_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(sub_domain)
            sub_urls.append(f"{scheme}://{sub_domain}")
        except socket.gaierror:
            pass

    state.targets = list(set(sub_urls))
    state.is_monitoring = True
    state.target_url = request.url
    state.detectors = {t: SmartDetector(alpha=0.15, threshold=2.0) for t in state.targets}
    state.histories = {}
    state.timestamps = {}
    state.baseline_avgs = {}
    state.current_statuses = {t: "Idle" for t in state.targets}
    state.http_status_codes = {t: 0 for t in state.targets}

    background_tasks.add_task(monitoring_loop, state)
    return {"message": "Monitoring Started", "targets": state.targets}

@app.post("/stop")
async def stop_monitoring():
    state.is_monitoring = False
    for t in state.targets:
        state.current_statuses[t] = "Stopped"
    return {"message": "Stopped"}

@app.get("/status")
async def get_status():
    return {
        "is_monitoring": state.is_monitoring,
        "targets": state.targets,
        "current_latencies": {t: state.histories.get(t, [0])[-1] if t in state.histories else 0 for t in state.targets},
        "baseline_avgs": state.baseline_avgs,
        "status_messages": state.current_statuses,
        "histories": state.histories,
        "timestamps": state.timestamps
    }

# ================= DOMAIN TRACKING LOGIC (FIXED RDAP) =================

def _get_rdap_info_ultra(domain_name):
    """
    Uses RDAP with forced redirects and SSL verification disabled 
    to ensure we get data even on restricted networks.
    """
    try:
        url = f"https://rdap.org/domain/{domain_name}"
        headers = {'Accept': 'application/rdap+json', 'User-Agent': 'Mozilla/5.0'}
        
        # CRITICAL FIXES:
        # 1. allow_redirects=True: RDAP redirects to registrar server. We MUST follow it.
        # 2. verify=False: Ignore SSL certificate errors common on local dev machines.
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True, verify=False)
        
        print(f"[DEBUG] RDAP Status Code for {domain_name}: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            info = {"registrar": None, "created": None, "expires": None}
            
            # 1. EXTRACT DATES
            events = data.get("events", [])
            
            for event in events:
                action = str(event.get("eventAction", "")).lower()
                date_val = event.get("eventDate")
                
                # Look for Expiry
                if "expir" in action:
                    info["expires"] = date_val
                    print(f"[DEBUG] Found Expiry: {date_val}")
                
                # Look for Creation
                if "regist" in action or "creat" in action:
                    info["created"] = date_val
                    print(f"[DEBUG] Found Creation: {date_val}")

            # 2. EXTRACT REGISTRAR
            entities = data.get("entities", [])
            
            for entity in entities:
                roles = [str(r).lower() for r in entity.get("roles", [])]
                if "registrar" in roles:
                    # Try vcard
                    vcard = entity.get("vcardArray")
                    if vcard and isinstance(vcard, list) and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                info["registrar"] = item[3]
                                print(f"[DEBUG] Found Registrar (vcard): {info['registrar']}")
                                break
                    
                    # Fallback to handle
                    if not info["registrar"]:
                        handle = entity.get("handle")
                        if handle:
                            info["registrar"] = handle
                            print(f"[DEBUG] Found Registrar (handle): {handle}")
                            
                    # Last fallback
                    if not info["registrar"]:
                         info["registrar"] = "Redacted / Privacy Service"

            return info, "RDAP"
        else:
            print(f"[ERROR] RDAP failed with status {response.status_code}")
            return None, "Error"
            
    except Exception as e:
        print(f"[ERROR] RDAP Exception: {e}")
        return None, "Error"

def _parse_date_string(date_str):
    """Tries to parse ISO 8601, standard date strings, etc."""
    if not date_str: return None
    
    date_formats = [
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", # ISO 8601 (RDAP)
        "%Y-%m-%d", "%d-%b-%Y", "%d-%B-%Y",
        "%Y/%m/%d", "%d/%m/%Y",
        "%Y.%m.%d",
        "%d-%m-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"
    ]
    
    clean_str = str(date_str).split('T')[0].split('+')[0].split('Z')[0]
    
    for fmt in date_formats:
        try:
            return datetime.strptime(clean_str, fmt)
        except ValueError:
            continue
    return None

async def _send_expiry_alert(email: str, domain_name: str, expiry_date: str, days_left: int):
    """Sends email alert using FastMail config from auth.py"""
    try:
        subject = f"⚠️ URGENT: {domain_name} Expiring in {days_left} Days"
        body = f"""
        <html>
        <body>
            <h2 style="color: #d32f2f;">Domain Expiration Alert</h2>
            <p>The domain <strong>{domain_name}</strong> is expiring soon.</p>
            <ul>
                <li>Expiration Date: {expiry_date}</li>
                <li>Days Remaining: <strong>{days_left}</strong></li>
            </ul>
            <p>Please renew your domain immediately to avoid service disruption.</p>
        </body>
        </html>
        """
        
        # Use the existing auth configuration
        conf = auth.conf
        
        message = MessageSchema(subject=subject, recipients=[email], body=body, subtype="html")
        fm = FastMail(conf)
        await fm.send_message(message)
        print(f"[SUCCESS] Sent expiry alert to {email}")
    except Exception as e:
        print(f"[ERROR] Failed to send alert: {e}")

# ================= OPENSSL HELPER (MOST RELIABLE + SMART KEYWORD FALLBACK) =================
def _get_cert_via_openssl(domain_name):
    """
    Uses system's 'openssl' command to get Cert Details.
    Includes Smart Keyword Fallback to guarantee Issuer is found for major sites (Google, etc.).
    """
    try:
        # Command: Connect, show certs, print to stdout
        cmd = f"openssl s_client -connect {domain_name}:443 -servername {domain_name} -showcerts"
        
        # Run command
        result = subprocess.run(
            cmd, 
            shell=True,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            print(f"    -> [FAIL] OpenSSL command failed for {domain_name}")
            return None

        output = result.stdout + result.stderr
        
        # 1. Extract Issuer (Primary Regex)
        # Looks for: issuer=... or Issuer: ...
        issuer_match = re.search(r'Issuer\s*:\s*(.*)$', output, re.IGNORECASE | re.MULTILINE)
        issuer_name = None
        
        if issuer_match:
            raw_issuer = issuer_match.group(1).strip()
            # Check if it looks like a list attribute "O=..."
            if raw_issuer.startswith('O=') or raw_issuer.startswith('o='):
                # Extract the clean part
                parts = raw_issuer.split('=')
                if len(parts) > 1:
                    val = parts[1].strip('"').strip("'")
                    # Remove trailing "..." if present
                    val = val.rstrip('...').replace('...', '')
                    issuer_name = val
            else:
                issuer_name = raw_issuer
            print(f"    -> [SUCCESS] OpenSSL found Issuer (RegEx): {issuer_name}")
        
        # 2. Extract Expiry (Primary Regex)
        # Match: Not After : Nov  2 13:23:34 2028 GMT
        # Matches the LAST "Not After" line and captures everything after it
        expiry_match = re.search(r'Not After\s*:\s*(.*)$', output, re.IGNORECASE | re.MULTILINE)
        expiry_date = None
        
        if expiry_match:
            raw_expiry = expiry_match.group(1).strip()
            # Remove "GMT" and newlines
            expiry_date = raw_expiry.replace("GMT", "").strip()
            # Remove extra spaces that sometimes appear
            expiry_date = ' '.join(expiry_date.split())
            print(f"    -> [SUCCESS] OpenSSL found Expiry: {expiry_date}")

        # 3. SMART KEYWORD FALLBACK (NEW FIX FOR GOOGLE)
        # If Primary Regex failed (issuer_name is still None), search for keywords
        if not issuer_name:
            print("    -> [INFO] Regex failed, trying Smart Keyword Search...")
            known_keywords = ["google", "microsoft", "amazon", "cloudflare", "digicert", "godaddy", "namecheap", "sectigo", "cybertrust", "letsencrypt", "dod"]
            
            # Convert output to lowercase for easier searching
            output_lower = output.lower()
            
            for keyword in known_keywords:
                if keyword in output_lower:
                    # Extracts the line containing the keyword
                    lines = output.split('\n')
                    for line in lines:
                        if keyword in line:
                            # Try to parse out the name (Simple heuristic)
                            # e.g. "O=Google Trust Services..." -> "Google Trust Services"
                            if '=' in line:
                                parts = line.split('=')
                                if len(parts) > 1:
                                    val = parts[1].strip('"').strip("'")
                                    # Clean trailing "..." or separators
                                    val = val.rstrip('...').replace('...', '')
                                    issuer_name = val
                                    print(f"    -> [SUCCESS] Found Issuer (Smart Keyword): {issuer_name}")
                                    break
                            if issuer_name:
                                break
                    if issuer_name:
                        break

        if issuer_name or expiry_date:
            return {
                "status": "Valid",
                "issuer": issuer_name,
                "expires": expiry_date
            }
        else:
            return None
            
    except FileNotFoundError:
        # OpenSSL is not installed on this machine
        print("    -> [INFO] OpenSSL command not found, falling back to Python SSL")
        return "NOT_INSTALLED"
    except Exception as e:
        print(f"    -> [ERROR] OpenSSL helper failed: {e}")
        return None

def _perform_scan(domain: Domain, db: Session):
    domain_name = domain.domain_name
    score = 0
    
    # Initialize
    # REMOVED 'SSL/TLS Details' logic from scan flow. We now only track necessary fields.
    ssl_info = {"status": "Unknown", "issuer": "N/A", "expires": None}
    whois_info = {"registrar": "Unknown", "created": None, "expires": None}
    dns_info = {"A": [], "MX": [], "NS": []}
    
    print(f"--- SCANNING {domain_name} ---")
    
    # --- PHASE 1: ULTRA RDAP (Primary Source) ---
    print(f"[*] Querying RDAP for {domain_name}...")
    rdap_data, source = _get_rdap_info_ultra(domain_name)
    
    if rdap_data:
        print(f"    -> [SUCCESS] Data found via {source}")
        if rdap_data.get("registrar"):
            whois_info["registrar"] = rdap_data["registrar"]
            score += 30
        if rdap_data.get("created"):
            whois_info["created"] = rdap_data["created"]
            score += 10
        if rdap_data.get("expires"):
            whois_info["expires"] = rdap_data["expires"]
            score += 10
    else:
        print(f"    -> [WARNING] RDAP returned no data.")
            
    # --- PHASE 2: FALLBACK TO PYTHON-WHOIS ---
    # Only runs if RDAP failed completely or returned empty critical fields
    if not rdap_data or not whois_info["expires"] or whois_info["registrar"] == "Unknown":
        print(f"[*] Fallback: Checking Python Whois library...")
        try:
            w = whois.whois(domain_name)
            
            if whois_info["registrar"] == "Unknown" and w.registrar:
                val = w.registrar[0] if isinstance(w.registrar, list) else w.registrar
                whois_info["registrar"] = val
                
            if not whois_info["created"] and w.creation_date:
                d = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                whois_info["created"] = d.isoformat() if hasattr(d, 'isoformat') else str(d)
                
            if not whois_info["expires"] and w.expiration_date:
                d = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                whois_info["expires"] = d.isoformat() if hasattr(d, 'isoformat') else str(d)
                
            if w.registrar or w.expiration_date:
                print("    -> [SUCCESS] Data found via Python Whois")
        except Exception as e:
            print(f"    -> [FAIL] Python Whois error: {e}")

    # --- PHASE 3: DNS ---
    print(f"[*] Checking DNS Records...")
    try:
        answers = dns.resolver.resolve(domain_name, 'A')
        dns_info["A"] = [rdata.address for rdata in answers]
        score += 10
    except Exception: pass
    try:
        answers = dns.resolver.resolve(domain_name, 'MX')
        dns_info["MX"] = [rdata.exchange.to_text() for rdata in answers]
        score += 10
    except Exception: pass
    try:
        answers = dns.resolver.resolve(domain_name, 'NS')
        dns_info["NS"] = [rdata.to_text() for rdata in answers]
        score += 10
    except Exception: pass

    # --- PHASE 4: SSL (OPENSSL + SMART FALLBACK) ---
    print(f"[*] Checking SSL Certificate...")
    
    ssl_result = _get_cert_via_openssl(domain_name)
    
    # Check if OpenSSL succeeded
    if ssl_result and ssl_result != "NOT_INSTALLED":
        print("    -> [SUCCESS] Using OpenSSL data.")
        ssl_info["status"] = ssl_result["status"]
        ssl_info["issuer"] = ssl_result["issuer"]
        
        # Parse Date for DB
        if ssl_result.get("expires"):
            try:
                import time
                raw_expiry = ssl_result["expires"]
                # Split GMT/Time parts safely
                time_str = raw_expiry.split(" GMT")[0].strip() if "GMT" in raw_expiry else raw_expiry
                # Format: "Nov  2 13:23:34 2028"
                parsed_time = time.strptime(time_str, "%b %d %H:%M:%S %Y")
                ssl_info["expires"] = parsed_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                # If parsing fails, use raw string
                ssl_info["expires"] = ssl_result["expires"]
    else:
        # Fallback if OpenSSL not installed
        print("    -> [INFO] OpenSSL not installed, falling back to Python Request Method")
        
        is_https_valid = False
        try:
            r = requests.head(f"https://{domain_name}", timeout=5, allow_redirects=True, verify=False)
            if r.status_code < 500:
                is_https_valid = True
        except Exception:
            pass

        if is_https_valid:
            ssl_info["status"] = "Valid"
            # Try socket method as a last resort for details
            try:
                ip_address = socket.gethostbyname(domain_name)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((ip_address, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                        cert = ssock.getpeercert()
                        issuer_dict = dict(x[0] for x in cert['issuer'])
                        ssl_info["issuer"] = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown'))
                        ssl_info["expires"] = cert.get('notAfter')
            except Exception:
                pass 
        else:
            ssl_info["status"] = "Invalid / No SSL"

    # ================= EXPIRY ALERT LOGIC =================
    print(f"[*] Checking Expiry Alert...")
    if whois_info["expires"]:
        exp_date_obj = _parse_date_string(whois_info["expires"])
        if exp_date_obj:
            days_remaining = (exp_date_obj - datetime.utcnow()).days
            
            # Check if 30 days or less
            if days_remaining <= 30:
                print(f"    -> [ALERT] Domain expires in {days_remaining} days!")
                
                # SAFETY CHECK: Use MAIL_FROM if no owner (prevents crash)
                recipient_email = domain.owner.email if domain.owner else auth.conf.MAIL_FROM
                
                # Send Email (Async in Sync context)
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.create_task(_send_expiry_alert(recipient_email, domain_name, whois_info["expires"], days_remaining))
                    else:
                        asyncio.run(_send_expiry_alert(recipient_email, domain_name, whois_info["expires"], days_remaining))
                except Exception as e:
                    print(f"    -> [FAIL] Failed to schedule email: {e}")
            else:
                print(f"    -> [OK] Domain is safe ({days_remaining} days left)")

    # Update DB
    domain.security_score = score
    domain.last_scanned = datetime.utcnow()
    domain.ssl_data = json.dumps(ssl_info)
    domain.whois_data = json.dumps(whois_info)
    domain.dns_data = json.dumps(dns_info)
    db.commit()
    print(f"--- DONE {domain_name} (Score: {score}) ---")

# ================= DOMAIN ROUTES =================

@app.get("/domain/list")
def get_domain_list(db: Session = Depends(get_db)):
    domains = db.query(Domain).all()
    return [{"id": d.id, "domain_name": d.domain_name, "security_score": d.security_score} for d in domains]

@app.post("/domain/add")
async def add_domain(request: Request, db: Session = Depends(get_db)):
    body_bytes = await request.body()
    domain_input = body_bytes.decode("utf-8").strip().strip('"').strip("'")
    parsed = urlparse(domain_input)
    clean_domain = parsed.netloc if parsed.netloc else parsed.path
    clean_domain = clean_domain.lower()
    if not clean_domain or "." not in clean_domain: raise HTTPException(status_code=400, detail="Invalid domain name")

    existing = db.query(Domain).filter(Domain.domain_name == clean_domain).first()
    if existing:
        _perform_scan(existing, db)
        return {"message": "Domain refreshed", "id": existing.id}
    
    # Assign to first user (or implement proper session auth)
    default_user = db.query(User).first()
    
    new_domain = Domain(
        domain_name=clean_domain, 
        security_score=0, 
        user_id=default_user.id if default_user else None,
        ssl_data='{}', whois_data='{}', dns_data='{}'
    )
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)
    _perform_scan(new_domain, db)
    return {"message": "Domain added and scanned", "id": new_domain.id}

@app.get("/domain/detail/{id}")
def get_domain_detail(id: int, db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == id).first()
    if not domain: raise HTTPException(status_code=404, detail="Domain not found")
    try:
        ssl_data = json.loads(domain.ssl_data)
        whois_data = json.loads(domain.whois_data)
        dns_data = json.loads(domain.dns_data)
    except:
        ssl_data, whois_data, dns_data = {}, {}, {}

    return {
        "id": domain.id,
        "domain_name": domain.domain_name,
        "security_score": domain.security_score,
        "last_scanned": domain.last_scanned,
        "ssl_status": ssl_data.get("status", "Unknown"),
        "ssl_issuer": ssl_data.get("issuer", "N/A"), # Note: Frontend handles N/A display
        "ssl_expires": ssl_data.get("expires"),
        "registrar": whois_data.get("registrar", "Unknown"),
        "creation_date": whois_data.get("created"),
        "expiration_date": whois_data.get("expires"),
        "dns_records": dns_data
    }

@app.post("/domain/scan/{id}")
def trigger_scan(id: int, db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == id).first()
    if not domain: raise HTTPException(status_code=404, detail="Domain not found")
    _perform_scan(domain, db)
    return {"message": "Live scan complete", "security_score": domain.security_score}

@app.delete("/domain/{id}")
def delete_domain(id: int, db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == id).first()
    if not domain: raise HTTPException(status_code=404, detail="Domain not found")
    db.delete(domain)
    db.commit()
    return {"message": "Domain deleted successfully"}