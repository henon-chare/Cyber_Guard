# ================= main.py =================
import subprocess
import shlex
import sys
import json
import socket
import ssl
import re
import asyncio
import time
import copy
from typing import List, Dict, Any
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request, Body
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship, Session
from pydantic import BaseModel, EmailStr, field_validator

# External Libraries
import whois
import dns.resolver
import requests
import urllib3
from fastapi_mail import FastMail, MessageSchema

# PDF Generation Libraries
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pdfencrypt import StandardEncryption

# CHART Libraries
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

# Local imports
import auth
from database import Base, engine, get_db
from fastapi.middleware.cors import CORSMiddleware
from monitor import SmartDetector, MonitorState, monitoring_loop
from urllib.parse import urlparse

# Import Models
from models import User, LoginAttempt, Domain, Monitor

from io import BytesIO
from fastapi.responses import StreamingResponse

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

# Report Schemas - UPDATED: Removed default password
class GlobalReportRequest(BaseModel):
    password: str

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
    return {"version": "17.0", "model": "Detailed-Subdomain-Analysis"}

# ================= GLOBAL REPORT GENERATION =================

# --- Custom Colors ---
# PDF specific colors (Dark text for white background)
PDF_TITLE_COLOR = colors.HexColor("#0f172a") # Slate 900
PDF_TEXT_COLOR = colors.HexColor("#1f2937")  # Slate 800 (Dark Gray) - Readable on White
PDF_MUTED_COLOR = colors.HexColor("#4b5563") # Gray 600

# UI Colors (kept for specific highlights)
CYBER_CYAN = colors.HexColor("#06b6d4")
DARK_BG = colors.HexColor("#0f172a")
LIGHT_BG = colors.HexColor("#1e293b")
STATUS_GREEN = colors.HexColor("#10b981")
STATUS_RED = colors.HexColor("#ef4444")
STATUS_ORANGE = colors.HexColor("#f59e0b")
WHITE = colors.white
GRAY_TEXT = colors.HexColor("#94a3b8")

def create_global_pie_chart(data):
    drawing = Drawing(400, 200)
    pc = Pie()
    pc.x = 120; pc.y = 25; pc.width = 150; pc.height = 150
    pc.data = [data.get('up', 0), data.get('down', 0), data.get('warning', 0)]
    pc.labels = ['Operational', 'Down', 'Warning']
    pc.slices[0].fillColor = STATUS_GREEN
    pc.slices[1].fillColor = STATUS_RED
    pc.slices[2].fillColor = STATUS_ORANGE
    pc.slices.strokeWidth = 0.5; pc.slices.strokeColor = colors.white
    title = String(200, 180, 'Global System Status', fontName='Helvetica-Bold', fontSize=14, fillColor=PDF_TITLE_COLOR, textAnchor='middle')
    drawing.add(pc); drawing.add(title)
    return drawing

def create_mini_pie(healthy, unhealthy):
    """Creates a small 100x100 pie chart for individual subdomains"""
    drawing = Drawing(100, 100)
    if healthy == 0 and unhealthy == 0:
        return drawing

    pc = Pie()
    pc.x = 15; pc.y = 10; pc.width = 70; pc.height = 70
    pc.data = [healthy, unhealthy]
    pc.slices[0].fillColor = STATUS_GREEN
    pc.slices[1].fillColor = STATUS_RED
    pc.slices.strokeWidth = 0.5; pc.slices.strokeColor = colors.white
    
    drawing.add(pc)
    return drawing

def analyze_subdomain(target, status, history):
    """Generates text analysis and metrics for a specific subdomain"""
    
    # 1. Calculate Metrics
    total_checks = len(history)
    valid_latency = [h for h in history if h > 0]
    
    # Healthy = Latency > 0 and < 3000ms
    healthy_count = len([h for h in history if h > 0 and h < 3000])
    unhealthy_count = total_checks - healthy_count
    
    uptime_pct = (healthy_count / total_checks * 100) if total_checks > 0 else 0
    
    avg_lat = sum(valid_latency) / len(valid_latency) if valid_latency else 0
    max_lat = max(valid_latency) if valid_latency else 0
    min_lat = min(valid_latency) if valid_latency else 0
    
    # 2. Determine Status Type
    is_down = "DOWN" in status or "ERROR" in status or "REFUSED" in status or "404" in status
    is_slow = "WARNING" in status or "TIMEOUT" in status or avg_lat > 1500
    is_healthy = not is_down and not is_slow

    # 3. Generate Text Description
    short_url = target.replace("https://", "").replace("http://", "")
    
    # Using darker colors for PDF readability
    if is_down:
        desc = (f"<b>Critical Alert:</b> The subdomain <font color='#dc2626'><b>{short_url}</b></font> is currently <b>DOWN</b>. "
                f"The last check returned status: <i>{status}</i>. "
                f"This service has experienced <b>{unhealthy_count}</b> failed attempts out of {total_checks} checks. "
                "Immediate investigation is recommended.")
        status_color = STATUS_RED
        status_label = "CRITICAL"
    elif is_slow:
        desc = (f"<b>Performance Warning:</b> The subdomain <font color='#d97706'><b>{short_url}</b></font> is responding with high latency. "
                f"Average response time is <b>{avg_lat:.0f}ms</b>. "
                f"While the service is technically up, the slow response times may impact user experience.")
        status_color = STATUS_ORANGE
        status_label = "WARNING"
    else:
        desc = (f"<b>Status Operational:</b> The subdomain <font color='#059669'><b>{short_url}</b></font> is healthy. "
                f"It has maintained an uptime of <b>{uptime_pct:.1f}%</b> over the last {total_checks} checks. "
                f"Average latency is stable at <b>{avg_lat:.0f}ms</b>.")
        status_color = STATUS_GREEN
        status_label = "OPERATIONAL"

    return {
        "desc": desc,
        "uptime": uptime_pct,
        "avg": avg_lat,
        "min": min_lat,
        "max": max_lat,
        "healthy": healthy_count,
        "unhealthy": unhealthy_count,
        "status_color": status_color,
        "status_label": status_label
    }

def generate_global_monitoring_pdf(password: str, state_data: dict):
    """Generates a secure, detailed PDF report with per-subdomain analysis."""
    buffer = BytesIO()
    
    # STRICT ENCRYPTION
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
        
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=20, encrypt=encryption)
    
    elements = []
    styles = getSampleStyleSheet()
    
    # --- Custom Styles (Updated for White Background Readability) ---
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER, spaceAfter=10)
    # FIX: Changed from GRAY_TEXT to PDF_MUTED_COLOR (Dark Gray)
    subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=10, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER)
    header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=16, textColor=WHITE, backColor=DARK_BG, borderPadding=10, spaceBefore=15, spaceAfter=10)
    
    # FIX: Changed text color to Dark Slate for readability on white
    analysis_style = ParagraphStyle('Analysis', parent=styles['Normal'], fontSize=9, textColor=PDF_TEXT_COLOR, alignment=TA_JUSTIFY, spaceBefore=10, spaceAfter=15, leading=14)
    
    # --- Cover Page ---
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph(f"Global Monitoring Report | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    elements.append(Paragraph(f"<font color='red'><b>SECURED DOCUMENT - PASSWORD PROTECTED</b></font>", ParagraphStyle('Secure', fontSize=9, alignment=TA_CENTER, spaceAfter=20)))

    # --- Data Extraction ---
    targets = state_data.get("targets", [])
    current_statuses = state_data.get("current_statuses", {})
    histories = state_data.get("histories", {})

    # Global Counts
    up_count = 0; down_count = 0; warning_count = 0
    analysis_results = []

    # Pre-calculate analysis for global stats
    for target in targets:
        status = current_statuses.get(target, "Unknown")
        history = histories.get(target, [])
        
        res = analyze_subdomain(target, status, history)
        analysis_results.append({"target": target, "data": res})

        if res['status_label'] == "OPERATIONAL": up_count += 1
        elif res['status_label'] == "CRITICAL": down_count += 1
        else: warning_count += 1

    # --- 1. Global Summary Section ---
    elements.append(Paragraph("Executive Summary", header_style))
    
    summary_data = [
        ["Total Targets", "Operational", "Down", "Warnings"],
        [str(len(targets)), str(up_count), str(down_count), str(warning_count)]
    ]
    t_summary = Table(summary_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), DARK_BG),
        ('TEXTCOLOR', (0, 0), (-1, 0), GRAY_TEXT),
        ('TEXTCOLOR', (1, 1), (1, 1), STATUS_GREEN),
        ('TEXTCOLOR', (2, 1), (2, 1), STATUS_RED),
        ('TEXTCOLOR', (3, 1), (3, 1), STATUS_ORANGE),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 18),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b")),
    ]))
    elements.append(t_summary)
    elements.append(Spacer(1, 20))

    # Global Pie Chart
    pie_data = {'up': up_count, 'down': down_count, 'warning': warning_count}
    if any(v > 0 for v in pie_data.values()):
        elements.append(create_global_pie_chart(pie_data))
    
    elements.append(PageBreak())

    # --- 2. Detailed Subdomain Analysis ---
    elements.append(Paragraph("Detailed Subdomain Analysis", header_style))
    elements.append(Spacer(1, 10))

    for item in analysis_results:
        target = item['target']
        res = item['data']
        
        # Container for each subdomain
        subdomain_elements = []

        # Header Bar
        header_table = Table([[Paragraph(f"{res['status_label']}", ParagraphStyle('H', fontSize=10, textColor=WHITE, alignment=TA_CENTER)), 
                              Paragraph(f"<b>{target}</b>", ParagraphStyle('Url', fontSize=10, textColor=WHITE))]],
                             colWidths=[1*inch, 5.5*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), res['status_color']),
            ('BACKGROUND', (1, 0), (1, 0), LIGHT_BG),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        subdomain_elements.append(header_table)
        subdomain_elements.append(Spacer(1, 5))

        # Text Description
        subdomain_elements.append(Paragraph(res['desc'], analysis_style))

        # Analysis Table (Metrics + Mini Chart)
        # Create the mini pie chart
        mini_chart = create_mini_pie(res['healthy'], res['unhealthy'])
        
        metric_data = [
            ["Uptime", f"{res['uptime']:.1f}%"],
            ["Avg Latency", f"{res['avg']:.0f} ms"],
            ["Max Latency", f"{res['max']:.0f} ms"],
            ["Checks", f"{res['healthy'] + res['unhealthy']}"]
        ]
        
        t_metrics = Table(metric_data, colWidths=[1.5*inch, 1*inch])
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f3f4f6")), # Light Gray BG
            ('TEXTCOLOR', (0, 0), (0, -1), PDF_MUTED_COLOR), # Dark Text
            ('TEXTCOLOR', (1, 0), (1, -1), PDF_TEXT_COLOR),  # Dark Text
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('GRID', (0, 0), (-1, -1), 0.2, colors.HexColor("#d1d5db")),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))

        # FIX: Increased spacing and adjusted layout to prevent overlap
        content_layout = Table([[t_metrics, mini_chart]], colWidths=[3*inch, 3.5*inch])
        content_layout.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ALIGN', (1, 0), (1, 0), 'CENTER'),
            ('LEFTPADDING', (0,0), (0,0), 0),
            ('RIGHTPADDING', (1,0), (1,0), 0),
        ]))
        subdomain_elements.append(content_layout)
        
        # Add a separator line
        subdomain_elements.append(Spacer(1, 20))
        line = Table([['']], colWidths=[6.5*inch])
        line.setStyle(TableStyle([
            ('LINEABOVE', (0, 0), (-1, 0), 0.5, colors.HexColor("#e5e7eb")),
        ]))
        subdomain_elements.append(line)
        subdomain_elements.append(Spacer(1, 10))

        elements.append(KeepTogether(subdomain_elements))

    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/monitoring/global-report")
async def download_global_monitoring_report(data: GlobalReportRequest, current_user: User = Depends(auth.get_current_user)):
    try:
        # Snapshot data
        state_data = {
            "targets": list(state.targets),
            "current_statuses": dict(state.current_statuses),
            "histories": {k: list(v) for k, v in state.histories.items()}
        }

        # Generate PDF with password
        pdf_buffer = generate_global_monitoring_pdf(data.password, state_data)
        
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=cyberguard_detailed_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        })
    except Exception as e:
        import traceback
        print(f"[ERROR] Failed to generate report: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

def generate_global_domain_report(user_id: int, db: Session, password: str):
    """Generates a secure PDF report for Domains"""
    buffer = BytesIO()
    
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
        
    doc = SimpleDocTemplate(buffer, pagesize=A4, encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER)
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph("Domain Intel Inventory", ParagraphStyle('Sub', fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=20)))

    domains = db.query(Domain).filter(Domain.user_id == user_id).all()
    
    table_data = [["Domain Name", "Score", "SSL Status", "Expiration"]]

    for d in domains:
        ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
        whois_data = json.loads(d.whois_data) if d.whois_data else {}
        
        ssl_status = ssl_data.get("status", "Unknown")
        ssl_color = STATUS_GREEN if ssl_status == "Valid" else STATUS_RED

        exp_str = whois_data.get("expires", "N/A")
        try:
            exp_date = datetime.strptime(exp_str.split("T")[0], "%Y-%m-%d")
            days_left = (exp_date - datetime.utcnow()).days
            if days_left < 0: exp_color = STATUS_RED
            elif days_left < 30: exp_color = STATUS_ORANGE
            else: exp_color = STATUS_GREEN
        except: exp_color = GRAY_TEXT

        table_data.append([
            Paragraph(d.domain_name, ParagraphStyle('Cell', fontSize=9, textColor=PDF_TEXT_COLOR)),
            Paragraph(f"{d.security_score}/100", ParagraphStyle('Score', fontSize=9, textColor=CYBER_CYAN, alignment=TA_CENTER)),
            Paragraph(ssl_status, ParagraphStyle('Status', fontSize=9, textColor=ssl_color, alignment=TA_CENTER)),
            Paragraph(exp_str.split("T")[0], ParagraphStyle('Date', fontSize=9, textColor=exp_color, alignment=TA_CENTER))
        ])

    t = Table(table_data, colWidths=[3*inch, 1*inch, 1.2*inch, 1.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), CYBER_CYAN),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('ALIGN', (0, 1), (0, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
        ('TEXTCOLOR', (0, 1), (-1, -1), PDF_TEXT_COLOR), # Dark text for rows
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(t)

    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/domain/global-report")
async def download_global_domain_report(data: GlobalReportRequest, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    try:
        pdf_buffer = generate_global_domain_report(current_user.id, db, data.password)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=domain_inventory_{datetime.now().strftime('%Y%m%d')}.pdf"
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ================= HYBRID SUBDOMAIN DISCOVERY =================

SAFE_SUBDOMAIN_LIST = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'imap',
    'admin', 'api', 'dev', 'staging', 'test', 'beta', 'portal', 'shop',
    'secure', 'vpn', 'remote', 'blog', 'forum', 'cdn', 'static', 'media',
    'assets', 'img', 'images', 'video', 'app', 'apps', 'mobile', 'm',
    'store', 'support', 'help', 'wiki', 'docs', 'status', 'panel', 'cpanel',
    'webdisk', 'autodiscover', 'autoconfig', 'owa', 'exchange', 'email',
    'relay', 'mx', 'mx1', 'mx2', 'news', 'tv', 'radio', 'chat', 'sip',
    'proxy', 'gateway', 'monitor', 'jenkins', 'git', 'gitlab', 'svn'
]

def get_passive_subdomains_sync(domain: str):
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            try:
                data = response.json()
                for entry in data:
                    names_raw = entry.get('name_value', '')
                    names_list = names_raw.split('\n')
                    
                    for name in names_list:
                        name = name.strip()
                        if not name: continue
                        if name.startswith('*.'): continue
                        if name.endswith(domain):
                            subdomains.add(name)
            except Exception: pass
    except Exception: pass
    return list(subdomains)

# ================= WEBSITE MONITORING ROUTES =================

@app.post("/start")
async def start_monitoring(request: StartRequest, background_tasks: BackgroundTasks, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    if state.is_monitoring:
        raise HTTPException(status_code=400, detail="Already monitoring")

    parsed = urlparse(request.url)
    domain = parsed.netloc
    scheme = parsed.scheme

    loop = asyncio.get_event_loop()
    passive_subs = await loop.run_in_executor(None, get_passive_subdomains_sync, domain)
    
    active_subs = []
    for sub in SAFE_SUBDOMAIN_LIST:
        full_domain = f"{sub}.{domain}"
        try:
            await loop.run_in_executor(None, socket.gethostbyname, full_domain)
            active_subs.append(f"{scheme}://{full_domain}")
        except socket.gaierror: pass
    
    sub_urls = set()
    sub_urls.add(request.url)
    for sub in passive_subs: sub_urls.add(f"{scheme}://{sub}")
    sub_urls.update(active_subs)
    
    state.targets = list(sub_urls)
    state.is_monitoring = True
    state.target_url = request.url
    state.detectors = {t: SmartDetector(alpha=0.15, threshold=2.0) for t in state.targets}
    state.histories = {}; state.timestamps = {}; state.baseline_avgs = {}
    state.current_statuses = {t: "Idle" for t in state.targets}

    existing_monitor = db.query(Monitor).filter(Monitor.user_id == current_user.id, Monitor.target_url == request.url).first()
    if existing_monitor: existing_monitor.is_active = True
    else:
        new_monitor = Monitor(user_id=current_user.id, target_url=request.url, friendly_name=request.url, is_active=True)
        db.add(new_monitor)
    db.commit()

    background_tasks.add_task(monitoring_loop, state)
    return {"message": f"Monitoring Started", "targets": state.targets}

@app.post("/stop")
async def stop_monitoring(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    state.is_monitoring = False
    for t in state.targets: state.current_statuses[t] = "Stopped"
    db_monitor = db.query(Monitor).filter(Monitor.user_id == current_user.id, Monitor.target_url == state.target_url).first()
    if db_monitor:
        db_monitor.is_active = False
        db.commit()
    return {"message": "Stopped"}

@app.get("/status")
async def get_status(current_user: User = Depends(auth.get_current_user)):
    return {
        "is_monitoring": state.is_monitoring,
        "target_url": state.target_url,
        "targets": state.targets,
        "current_latencies": {t: state.histories.get(t, [0])[-1] if t in state.histories else 0 for t in state.targets},
        "baseline_avgs": state.baseline_avgs,
        "status_messages": state.current_statuses,
        "histories": state.histories,
        "timestamps": state.timestamps
    }

# ================= DOMAIN TRACKING LOGIC =================
def _get_rdap_info_ultra(domain_name):
    try:
        url = f"https://rdap.org/domain/{domain_name}"
        headers = {'Accept': 'application/rdap+json', 'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True, verify=False)
        if response.status_code == 200:
            data = response.json()
            info = {"registrar": None, "created": None, "expires": None}
            events = data.get("events", [])
            for event in events:
                action = str(event.get("eventAction", "")).lower()
                date_val = event.get("eventDate")
                if "expir" in action: info["expires"] = date_val
                if "regist" in action or "creat" in action: info["created"] = date_val
            entities = data.get("entities", [])
            for entity in entities:
                roles = [str(r).lower() for r in entity.get("roles", [])]
                if "registrar" in roles:
                    vcard = entity.get("vcardArray")
                    if vcard and isinstance(vcard, list) and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                info["registrar"] = item[3]; break
                    if not info["registrar"]:
                        handle = entity.get("handle")
                        if handle: info["registrar"] = handle
                    if not info["registrar"]: info["registrar"] = "Redacted"
            return info, "RDAP"
        else: return None, "Error"
    except Exception: return None, "Error"

def _parse_date_string(date_str):
    if not date_str: return None
    date_formats = ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d", "%d-%b-%Y", "%d-%B-%Y", "%Y/%m/%d", "%d/%m/%Y", "%Y.%m.%d", "%d-%m-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"]
    clean_str = str(date_str).split('T')[0].split('+')[0].split('Z')[0]
    for fmt in date_formats:
        try: return datetime.strptime(clean_str, fmt)
        except ValueError: continue
    return None

async def _send_expiry_alert(email: str, domain_name: str, expiry_date: str, days_left: int):
    try:
        subject = f"⚠️ URGENT: {domain_name} Expiring in {days_left} Days"
        body = f"<html><body><h2>Domain Expiration Alert</h2><p>{domain_name} expires soon.</p></body></html>"
        conf = auth.conf
        message = MessageSchema(subject=subject, recipients=[email], body=body, subtype="html")
        fm = FastMail(conf)
        await fm.send_message(message)
    except Exception: pass

def _get_cert_via_openssl(domain_name):
    try:
        cmd = f"openssl s_client -connect {domain_name}:443 -servername {domain_name} -showcerts"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if result.returncode != 0: return None
        output = result.stdout + result.stderr
        expiry_match = re.search(r'Not After\s*:\s*(.*)$', output, re.IGNORECASE | re.MULTILINE)
        expiry_date = None
        if expiry_match:
            raw_expiry = expiry_match.group(1).strip()
            expiry_date = raw_expiry.replace("GMT", "").strip()
            expiry_date = ' '.join(expiry_date.split())
        if expiry_date: return {"status": "Valid", "expires": expiry_date}
        else: return None
    except: return None

def _perform_scan(domain: Domain, db: Session):
    domain_name = domain.domain_name
    score = 0
    ssl_info = {"status": "Unknown", "expires": None}
    whois_info = {"registrar": "Unknown", "created": None, "expires": None}
    dns_info = {"A": [], "MX": [], "NS": []}
    
    rdap_data, source = _get_rdap_info_ultra(domain_name)
    if rdap_data:
        if rdap_data.get("registrar"): whois_info["registrar"] = rdap_data["registrar"]; score += 30
        if rdap_data.get("created"): whois_info["created"] = rdap_data["created"]; score += 10
        if rdap_data.get("expires"): whois_info["expires"] = rdap_data["expires"]; score += 10
    if not rdap_data or not whois_info["expires"]:
        try:
            w = whois.whois(domain_name)
            if whois_info["registrar"] == "Unknown" and w.registrar: whois_info["registrar"] = w.registrar
            if not whois_info["expires"] and w.expiration_date: whois_info["expires"] = w.expiration_date.isoformat() if hasattr(w.expiration_date, 'isoformat') else str(w.expiration_date)
        except: pass
    try: answers = dns.resolver.resolve(domain_name, 'A'); dns_info["A"] = [rdata.address for rdata in answers]; score += 10
    except: pass
    try: answers = dns.resolver.resolve(domain_name, 'MX'); dns_info["MX"] = [rdata.exchange.to_text() for rdata in answers]; score += 10
    except: pass
    try: answers = dns.resolver.resolve(domain_name, 'NS'); dns_info["NS"] = [rdata.to_text() for rdata in answers]; score += 10
    except: pass
    ssl_result = _get_cert_via_openssl(domain_name)
    if ssl_result:
        ssl_info["status"] = ssl_result["status"]; ssl_info["expires"] = ssl_result["expires"]
    else:
        try: 
            r = requests.head(f"https://{domain_name}", timeout=5, verify=False)
            if r.status_code < 500: ssl_info["status"] = "Valid"
        except: pass

    if whois_info["expires"]:
        exp_date_obj = _parse_date_string(whois_info["expires"])
        if exp_date_obj:
            days_remaining = (exp_date_obj - datetime.utcnow()).days
            if days_remaining <= 30:
                recipient_email = domain.owner.email if domain.owner else auth.conf.MAIL_FROM
                try: asyncio.create_task(_send_expiry_alert(recipient_email, domain_name, whois_info["expires"], days_remaining))
                except: pass

    domain.security_score = score; domain.last_scanned = datetime.utcnow()
    domain.ssl_data = json.dumps(ssl_info); domain.whois_data = json.dumps(whois_info); domain.dns_data = json.dumps(dns_info)
    db.commit()

# ================= DOMAIN ROUTES =================

@app.get("/domain/list")
def get_domain_list(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    domains = db.query(Domain).filter(Domain.user_id == current_user.id).all()
    return [{"id": d.id, "domain_name": d.domain_name, "security_score": d.security_score} for d in domains]

@app.post("/domain/add")
async def add_domain(request: Request, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    body_bytes = await request.body()
    domain_input = body_bytes.decode("utf-8").strip().strip('"').strip("'")
    parsed = urlparse(domain_input)
    clean_domain = parsed.netloc if parsed.netloc else parsed.path
    clean_domain = clean_domain.lower()
    if not clean_domain or "." not in clean_domain: raise HTTPException(status_code=400, detail="Invalid domain name")

    existing = db.query(Domain).filter(Domain.domain_name == clean_domain, Domain.user_id == current_user.id).first()
    if existing:
        _perform_scan(existing, db)
        return {"message": "Domain refreshed", "id": existing.id}
    
    new_domain = Domain(domain_name=clean_domain, security_score=0, user_id=current_user.id, ssl_data='{}', whois_data='{}', dns_data='{}', manual_data='{}')
    db.add(new_domain); db.commit(); db.refresh(new_domain)
    _perform_scan(new_domain, db)
    return {"message": "Domain added", "id": new_domain.id}

@app.get("/domain/detail/{id}")
def get_domain_detail(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not domain: 
        raise HTTPException(status_code=404, detail="Domain not found")
    
    # Parse the JSON data that EXISTS in the model
    ssl_data = json.loads(domain.ssl_data) if domain.ssl_data else {}
    whois_data = json.loads(domain.whois_data) if domain.whois_data else {}
    dns_data = json.loads(domain.dns_data) if domain.dns_data else {}

    # FIX: Re-implemented manual_data parsing with error handling
    # We wrap it in try-except to prevent crashes if data is corrupted in DB
    manual_data = {}
    try:
        if domain.manual_data:
            manual_data = json.loads(domain.manual_data)
    except (json.JSONDecodeError, TypeError):
        # If data is bad, default to empty dict so app doesn't crash
        manual_data = {}

    return {
        "id": domain.id, 
        "domain_name": domain.domain_name, 
        "security_score": domain.security_score,
        "last_scanned": domain.last_scanned, 
        "ssl_status": ssl_data.get("status", "Unknown"),
        "ssl_expires": ssl_data.get("expires"), 
        "ssl_issuer": ssl_data.get("issuer", "Unknown"), 
        "registrar": whois_data.get("registrar", "Unknown"), 
        "creation_date": whois_data.get("created"), 
        "expiration_date": whois_data.get("expires"), 
        "dns_records": dns_data,
        "manual_data": manual_data  # CRITICAL: Sending this back to Frontend
    }

@app.post("/domain/update-manual/{id}")
def update_domain_manual(id: int, payload: dict, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Endpoint to save the manual asset profile data."""
    domain = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not domain: raise HTTPException(status_code=404, detail="Domain not found")
    
    # Save the entire payload as JSON string
    domain.manual_data = json.dumps(payload)
    db.commit()
    return {"message": "Manual data updated successfully"}

@app.post("/domain/scan/{id}")
def trigger_scan(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not domain: raise HTTPException(status_code=404, detail="Domain not found")
    _perform_scan(domain, db)
    return {"message": "Scan complete", "security_score": domain.security_score}

@app.delete("/domain/{id}")
def delete_domain(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not domain: raise HTTPException(status_code=404, detail="Domain not found")
    db.delete(domain); db.commit()
    return {"message": "Deleted"}