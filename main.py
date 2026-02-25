# ================= main.py =================
import subprocess
import shlex
import sys
import json
import socket
import ssl  # Native SSL library
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
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
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

# Report Schemas
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
    return {"version": "17.1", "model": "CyberGuard-Domain-Intel"}

# ================= GLOBAL REPORT GENERATION (MONITORING) =================

# --- Custom Colors ---
PDF_TITLE_COLOR = colors.HexColor("#0f172a")
PDF_TEXT_COLOR = colors.HexColor("#1f2937")
PDF_MUTED_COLOR = colors.HexColor("#4b5563")

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
    drawing = Drawing(100, 100)
    if healthy == 0 and unhealthy == 0: return drawing
    pc = Pie()
    pc.x = 15; pc.y = 10; pc.width = 70; pc.height = 70
    pc.data = [healthy, unhealthy]
    pc.slices[0].fillColor = STATUS_GREEN
    pc.slices[1].fillColor = STATUS_RED
    pc.slices.strokeWidth = 0.5; pc.slices.strokeColor = colors.white
    drawing.add(pc)
    return drawing

def analyze_subdomain(target, status, history):
    total_checks = len(history)
    valid_latency = [h for h in history if h > 0]
    healthy_count = len([h for h in history if h > 0 and h < 3000])
    unhealthy_count = total_checks - healthy_count
    uptime_pct = (healthy_count / total_checks * 100) if total_checks > 0 else 0
    avg_lat = sum(valid_latency) / len(valid_latency) if valid_latency else 0
    max_lat = max(valid_latency) if valid_latency else 0
    min_lat = min(valid_latency) if valid_latency else 0
    
    is_down = "DOWN" in status or "ERROR" in status or "REFUSED" in status or "404" in status
    is_slow = "WARNING" in status or "TIMEOUT" in status or avg_lat > 1500
    is_healthy = not is_down and not is_slow
    short_url = target.replace("https://", "").replace("http://", "")
    
    if is_down:
        desc = (f"<b>Critical Alert:</b> <font color='#dc2626'><b>{short_url}</b></font> is <b>DOWN</b>. "
                f"Last check: <i>{status}</i>. {unhealthy_count} failures.")
        status_color = STATUS_RED
        status_label = "CRITICAL"
    elif is_slow:
        desc = (f"<b>Performance Warning:</b> <font color='#d97706'><b>{short_url}</b></font> high latency. "
                f"Avg: <b>{avg_lat:.0f}ms</b>.")
        status_color = STATUS_ORANGE
        status_label = "WARNING"
    else:
        desc = (f"<b>Operational:</b> <font color='#059669'><b>{short_url}</b></font> is healthy. "
                f"Uptime: <b>{uptime_pct:.1f}%</b>, Avg: <b>{avg_lat:.0f}ms</b>.")
        status_color = STATUS_GREEN
        status_label = "OPERATIONAL"

    return {
        "desc": desc, "uptime": uptime_pct, "avg": avg_lat, "min": min_lat, "max": max_lat,
        "healthy": healthy_count, "unhealthy": unhealthy_count,
        "status_color": status_color, "status_label": status_label
    }

def generate_global_monitoring_pdf(password: str, state_data: dict):
    """Generates a secure, detailed PDF report for Uptime Monitoring."""
    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=20, encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER, spaceAfter=10)
    subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=10, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER)
    header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=16, textColor=WHITE, backColor=DARK_BG, borderPadding=10, spaceBefore=15, spaceAfter=10)
    analysis_style = ParagraphStyle('Analysis', parent=styles['Normal'], fontSize=9, textColor=PDF_TEXT_COLOR, alignment=TA_JUSTIFY, spaceBefore=10, spaceAfter=15, leading=14)
    
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph(f"Global Monitoring Report | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    elements.append(Paragraph(f"<font color='red'><b>SECURED DOCUMENT - PASSWORD PROTECTED</b></font>", ParagraphStyle('Secure', fontSize=9, alignment=TA_CENTER, spaceAfter=20)))

    targets = state_data.get("targets", [])
    current_statuses = state_data.get("current_statuses", {})
    histories = state_data.get("histories", {})

    up_count = 0; down_count = 0; warning_count = 0
    analysis_results = []

    for target in targets:
        status = current_statuses.get(target, "Unknown")
        history = histories.get(target, [])
        res = analyze_subdomain(target, status, history)
        analysis_results.append({"target": target, "data": res})
        if res['status_label'] == "OPERATIONAL": up_count += 1
        elif res['status_label'] == "CRITICAL": down_count += 1
        else: warning_count += 1

    elements.append(Paragraph("Executive Summary", header_style))
    summary_data = [["Total Targets", "Operational", "Down", "Warnings"], [str(len(targets)), str(up_count), str(down_count), str(warning_count)]]
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
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b"))
    ]))
    elements.append(t_summary)
    elements.append(Spacer(1, 20))

    pie_data = {'up': up_count, 'down': down_count, 'warning': warning_count}
    if any(v > 0 for v in pie_data.values()): elements.append(create_global_pie_chart(pie_data))
    elements.append(PageBreak())

    elements.append(Paragraph("Detailed Subdomain Analysis", header_style))
    elements.append(Spacer(1, 10))

    for item in analysis_results:
        target = item['target']
        res = item['data']
        subdomain_elements = []
        header_table = Table([[Paragraph(f"{res['status_label']}", ParagraphStyle('H', fontSize=10, textColor=WHITE, alignment=TA_CENTER)), Paragraph(f"<b>{target}</b>", ParagraphStyle('Url', fontSize=10, textColor=WHITE))]], colWidths=[1*inch, 5.5*inch])
        
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), res['status_color']),
            ('BACKGROUND', (1, 0), (1, 0), LIGHT_BG),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8)
        ]))
        subdomain_elements.append(header_table)
        subdomain_elements.append(Spacer(1, 5))
        subdomain_elements.append(Paragraph(res['desc'], analysis_style))
        mini_chart = create_mini_pie(res['healthy'], res['unhealthy'])
        metric_data = [["Uptime", f"{res['uptime']:.1f}%"], ["Avg Latency", f"{res['avg']:.0f} ms"], ["Max Latency", f"{res['max']:.0f} ms"], ["Checks", f"{res['healthy'] + res['unhealthy']}"]]
        t_metrics = Table(metric_data, colWidths=[1.5*inch, 1*inch])
        
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f3f4f6")),
            ('TEXTCOLOR', (0, 0), (0, -1), PDF_MUTED_COLOR),
            ('TEXTCOLOR', (1, 0), (1, -1), PDF_TEXT_COLOR),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('GRID', (0, 0), (-1, -1), 0.2, colors.HexColor("#d1d5db")),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5)
        ]))
        content_layout = Table([[t_metrics, mini_chart]], colWidths=[3*inch, 3.5*inch])
        
        content_layout.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ALIGN', (1, 0), (1, 0), 'CENTER'),
            ('LEFTPADDING', (0,0), (0,0), 0),
            ('RIGHTPADDING', (1,0), (1,0), 0)
        ]))
        subdomain_elements.append(content_layout)
        subdomain_elements.append(Spacer(1, 20))
        line = Table([['']], colWidths=[6.5*inch])
        line.setStyle(TableStyle([('LINEABOVE', (0, 0), (-1, 0), 0.5, colors.HexColor("#e5e7eb"))]))
        subdomain_elements.append(line)
        subdomain_elements.append(Spacer(1, 10))
        elements.append(KeepTogether(subdomain_elements))

    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/monitoring/global-report")
async def download_global_monitoring_report(data: GlobalReportRequest, current_user: User = Depends(auth.get_current_user)):
    try:
        state_data = {
            "targets": list(state.targets),
            "current_statuses": dict(state.current_statuses),
            "histories": {k: list(v) for k, v in state.histories.items()}
        }
        pdf_buffer = generate_global_monitoring_pdf(data.password, state_data)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=cyberguard_monitoring_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Failed to generate report: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= SINGLE DOMAIN REPORT GENERATION =================

def generate_single_domain_pdf(domain_id: int, db: Session, password: str):
    """Generates a detailed PDF for a single specific domain."""
    d = db.query(Domain).filter(Domain.id == domain_id).first()
    if not d: raise HTTPException(status_code=404, detail="Domain not found")

    # Robust JSON parsing
    try:
        ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
        whois_data = json.loads(d.whois_data) if d.whois_data else {}
        manual_data = json.loads(d.manual_data) if d.manual_data else {}
        dns_data = json.loads(d.dns_data) if d.dns_data else {}
    except (json.JSONDecodeError, TypeError):
        ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    
    doc = SimpleDocTemplate(buffer, pagesize=A4, 
                            rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72, 
                            encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=32, textColor=CYBER_CYAN, alignment=TA_CENTER, spaceAfter=6)
    subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=30)
    header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=20, textColor=WHITE, backColor=DARK_BG, spaceBefore=20, spaceAfter=15, 
                                  borderPadding=12, alignment=TA_CENTER, borderWidth=1, borderColor=CYBER_CYAN, borderRadius=6)
    section_title_style = ParagraphStyle('SectionTitle', parent=styles['Heading3'], fontSize=16, textColor=PDF_TITLE_COLOR, spaceBefore=25, spaceAfter=12, leading=20)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=11, textColor=PDF_TEXT_COLOR, leading=16, spaceAfter=12)
    label_style = ParagraphStyle('Label', parent=styles['Normal'], fontSize=11, textColor=PDF_MUTED_COLOR, fontName='Helvetica-Bold')

    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph(f"<b>Domain Intelligence Report</b>", subtitle_style))
    
    status_color = STATUS_GREEN if ssl_data.get("status") == "Valid" else STATUS_RED
    status_txt = ssl_data.get("status", "Unknown").upper()
    
    exp_date_str = whois_data.get("expires") or manual_data.get("expirationDate")
    risk_txt = "Low"
    if exp_date_str:
        try:
            exp_dt = datetime.strptime(exp_date_str.split('T')[0], "%Y-%m-%d")
            days = (exp_dt - datetime.utcnow()).days
            if days < 0: risk_txt = "Expired"
            elif days < 30: risk_txt = "Critical"
        except: pass

    domain_header_data = [
        [Paragraph(f"<b>{d.domain_name}</b>", ParagraphStyle('DH', fontSize=18, textColor=WHITE)), 
         Paragraph(f"<b>{status_txt}</b>", ParagraphStyle('DHS', fontSize=14, textColor=WHITE, alignment=TA_RIGHT))]
    ]
    dh_table = Table(domain_header_data, colWidths=[4*inch, 2*inch])
    dh_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), status_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 15),
        ('RIGHTPADDING', (0,0), (-1,-1), 15),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
    ]))
    elements.append(dh_table)
    elements.append(Spacer(1, 20))

    vital_data = [
        [Paragraph("Registrar", label_style), Paragraph(whois_data.get("registrar", "Unknown"), body_style)],
        [Paragraph("Risk Level", label_style), Paragraph(f"<font color='{status_color.hexval() if hasattr(status_color, 'hexval') else '#000'}'><b>{risk_txt}</b></font>", body_style)],
        [Paragraph("Expiration", label_style), Paragraph(formatDate(exp_date_str) if exp_date_str else "Unknown", body_style)],
        [Paragraph("SSL Issuer", label_style), Paragraph(ssl_data.get("issuer", "Unknown"), body_style)]
    ]
    vital_table = Table(vital_data, colWidths=[1.8*inch, 4*inch])
    vital_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LINEABOVE', (0,1), (-1,1), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,2), (-1,2), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,3), (-1,3), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(vital_table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("Ownership & Infrastructure", section_title_style))
    owner_data = [
        [Paragraph("Primary Owner", label_style), Paragraph(manual_data.get("primaryOwner", "Not Set"), body_style)],
        [Paragraph("Department", label_style), Paragraph(manual_data.get("department", "Not Set"), body_style)],
        [Paragraph("Purpose", label_style), Paragraph(manual_data.get("purpose", "Unknown").upper(), body_style)],
        [Paragraph("DNS Provider", label_style), Paragraph(manual_data.get("dnsProvider", "Not Set"), body_style)],
        [Paragraph("Hosting Provider", label_style), Paragraph(manual_data.get("hostingProvider", "Not Set"), body_style)]
    ]
    owner_table = Table(owner_data, colWidths=[1.8*inch, 4*inch])
    owner_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LINEABOVE', (0,1), (-1,1), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,2), (-1,2), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,3), (-1,3), 0.5, colors.HexColor("#e5e7eb")),
        ('LINEABOVE', (0,4), (-1,4), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(owner_table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("Security Compliance", section_title_style))
    sec_checklist = manual_data.get("security", {})
    sec_data = [
        [Paragraph("Registrar Lock", label_style), Paragraph("Active" if sec_checklist.get('lock') else "Inactive", body_style)],
        [Paragraph("MFA Enabled", label_style), Paragraph("Yes" if sec_checklist.get('mfa') else "No", body_style)],
        [Paragraph("DNSSEC Enabled", label_style), Paragraph("Yes" if sec_checklist.get('dnssec') else "No", body_style)],
    ]
    sec_table = Table(sec_data, colWidths=[1.8*inch, 4*inch])
    sec_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(sec_table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("DNS Infrastructure", section_title_style))
    if dns_data:
        for r_type, records in dns_data.items():
            if records:
                elements.append(Paragraph(f"<b>{r_type} Records ({len(records)})</b>", ParagraphStyle('DNSHead', fontSize=12, textColor=CYBER_CYAN, spaceAfter=6)))
                for rec in records:
                    elements.append(Paragraph(f"• {rec}", body_style))
                elements.append(Spacer(1, 10))
    else:
        elements.append(Paragraph("No DNS records found.", body_style))
    
    elements.append(Spacer(1, 30))
    
    elements.append(Paragraph("Audit Log", section_title_style))
    notes = manual_data.get("notes", [])
    if notes:
        for note in notes:
            date = note.get('date', '')[:10]
            txt = note.get('text', '')
            elements.append(Paragraph(f"<b>{date}:</b> {txt}", body_style))
            elements.append(Spacer(1, 6))
    else:
        elements.append(Paragraph("No audit logs available.", body_style))

    elements.append(Spacer(1, 40))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by CyberGuard AI", ParagraphStyle('Footer', fontSize=9, textColor=GRAY_TEXT, alignment=TA_CENTER)))

    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/domain/report/{id}")
async def download_single_domain_report(
    id: int, 
    data: GlobalReportRequest, 
    current_user: User = Depends(auth.get_current_user), 
    db: Session = Depends(get_db)
):
    try:
        pdf_buffer = generate_single_domain_pdf(id, db, data.password)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=domain_report_{datetime.now().strftime('%Y%m%d')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Single Domain Report Failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= OLD GLOBAL DOMAIN REPORT (Kept for backward compatibility if needed) =================
def generate_global_domain_report(user_id: int, db: Session, password: str):
    """Generates a secure, detailed PDF report for Domains with manual data integration."""
    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    doc = SimpleDocTemplate(buffer, pagesize=A4, encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER)
    section_header = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=18, textColor=PDF_TITLE_COLOR, spaceBefore=20, spaceAfter=10, borderPadding=5, borderColor=CYBER_CYAN, border=1, borderRadius=5)
    
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph("Domain Intelligence Inventory", ParagraphStyle('Sub', fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=20)))

    domains = db.query(Domain).filter(Domain.user_id == user_id).all()
    
    if not domains:
        elements.append(Paragraph("No domains tracked.", styles['Normal']))
    else:
        total = len(domains)
        critical = 0
        valid_ssl = 0
        domain_data_list = []
        
        for d in domains:
            try:
                ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
                whois_data = json.loads(d.whois_data) if d.whois_data else {}
                manual_data = json.loads(d.manual_data) if d.manual_data else {}
                dns_data = json.loads(d.dns_data) if d.dns_data else {}
            except (json.JSONDecodeError, TypeError):
                ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

            if ssl_data.get("status") == "Valid": valid_ssl += 1
            
            exp_date_str = whois_data.get("expires") or manual_data.get("expirationDate")
            if exp_date_str:
                try:
                    if "T" in exp_date_str: exp_date_str = exp_date_str.split("T")[0]
                    exp_date = datetime.strptime(exp_date_str, "%Y-%m-%d")
                    if (exp_date - datetime.utcnow()).days < 30: critical += 1
                except: pass

            domain_data_list.append({
                "domain": d,
                "ssl": ssl_data,
                "whois": whois_data,
                "manual": manual_data,
                "dns": dns_data
            })

        summary_data = [
            ["Total Domains", "Valid SSL", "Expiring Soon (Critical)", "Risk Level"],
            [str(total), str(valid_ssl), str(critical), "Low" if critical == 0 else "High"]
        ]
        t_summary = Table(summary_data, colWidths=[1.5*inch, 1.5*inch, 2.0*inch, 1.5*inch])
        
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), CYBER_CYAN),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
            ('TEXTCOLOR', (0, 1), (-1, -1), PDF_TEXT_COLOR),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ]))
        elements.append(t_summary)
        elements.append(Spacer(1, 20))

        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Domain Analysis", section_header))

        for item in domain_data_list:
            d = item["domain"]
            ssl = item["ssl"]
            whois = item["whois"]
            manual = item["manual"]
            dns = item["dns"]

            card_elements = []

            header_color = STATUS_GREEN if ssl.get("status") == "Valid" else STATUS_RED
            header_text = f"<font color='white'><b>{d.domain_name}</b></font>"
            status_text = f"<font color='white'>{ssl.get('status', 'Unknown')}</font>"
            
            h_tbl = Table([
                [Paragraph(header_text, ParagraphStyle('DomainHead', fontSize=16, textColor=WHITE, backColor=header_color, alignment=TA_LEFT, padding=10)), 
                 Paragraph(status_text, ParagraphStyle('StatusHead', fontSize=12, textColor=WHITE, backColor=header_color, alignment=TA_RIGHT, padding=10))]
            ], colWidths=[4*inch, 2*inch])
            
            h_tbl.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
            ]))
            card_elements.append(h_tbl)
            card_elements.append(Spacer(1, 10))

            infra_data = [
                ["Registrar", whois.get("registrar", "Unknown")],
                ["Primary Owner", manual.get("primaryOwner", manual.get("owner", "Not Set"))],
                ["Department", manual.get("department", "Not Set")],
                ["Purpose", manual.get("purpose", "Unknown").upper()],
            ]
            
            t_infra = Table(infra_data, colWidths=[1.5*inch, 4.5*inch])
            
            t_infra.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('TEXTCOLOR', (0, 0), (0, -1), PDF_MUTED_COLOR),
                ('TEXTCOLOR', (1, 0), (1, -1), PDF_TEXT_COLOR),
                ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5)
            ]))
            card_elements.append(t_infra)
            card_elements.append(Spacer(1, 15))

            exp_str = whois.get("expires") or manual.get("expirationDate") or "N/A"
            if "T" in exp_str: exp_str = exp_str.split("T")[0]
            
            risk_color = STATUS_GREEN
            risk_txt = "Good"
            try:
                if exp_str != "N/A":
                    exp_dt = datetime.strptime(exp_str, "%Y-%m-%d")
                    days = (exp_dt - datetime.utcnow()).days
                    if days < 0: risk_color, risk_txt = STATUS_RED, "Expired"
                    elif days < 30: risk_color, risk_txt = STATUS_ORANGE, "Critical"
            except: pass

            risk_box = Paragraph(
                f"<b>Expiration Risk:</b> <font color='{risk_color.hexval() if hasattr(risk_color, 'hexval') else '#000'}'>{risk_txt} ({exp_str})</font>", 
                ParagraphStyle('Risk', fontSize=10, backColor=colors.HexColor("#f3f4f6"), padding=5, border=1, borderColor=colors.HexColor("#e5e7eb"))
            )
            card_elements.append(risk_box)
            card_elements.append(Spacer(1, 15))

            if dns:
                dns_text = "<b>DNS Records:</b> "
                for r_type, records in dns.items():
                    if records:
                        count = len(records)
                        dns_text += f"{r_type}({count}) "
                card_elements.append(Paragraph(dns_text, ParagraphStyle('DNS', fontSize=9, textColor=PDF_MUTED_COLOR)))
                card_elements.append(Spacer(1, 5))

            notes = manual.get("notes", [])
            if notes and len(notes) > 0:
                card_elements.append(Paragraph("<b>Audit Log / Notes:</b>", ParagraphStyle('NoteHead', fontSize=10, textColor=PDF_TITLE_COLOR)))
                for note in notes[:3]: 
                    date = note.get('date', '')[:10]
                    txt = note.get('text', '')
                    card_elements.append(Paragraph(f"• <i>{date}:</i> {txt}", ParagraphStyle('NoteBody', fontSize=8, textColor=PDF_TEXT_COLOR, leftIndent=10)))
                card_elements.append(Spacer(1, 10))

            line = Table([['']], colWidths=[6.5*inch])
            line.setStyle(TableStyle([('LINEABOVE', (0, 0), (-1, 0), 1, colors.HexColor("#e5e7eb"))]))
            card_elements.append(line)
            card_elements.append(Spacer(1, 20))

            elements.append(KeepTogether(card_elements))

    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/domain/global-report")
async def download_global_domain_report(data: GlobalReportRequest, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    try:
        pdf_buffer = generate_global_domain_report(current_user.id, db, data.password)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=domain_intel_report_{datetime.now().strftime('%Y%m%d')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Domain Report Failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= HYBRID SUBDOMAIN DISCOVERY =================
SAFE_SUBDOMAIN_LIST = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'imap', 'admin', 'api', 'dev', 'staging', 'test', 'beta', 'portal', 'shop', 'secure', 'vpn', 'remote', 'blog', 'forum', 'cdn', 'static', 'media', 'assets', 'img', 'images', 'video', 'app', 'apps', 'mobile', 'm', 'store', 'support', 'help', 'wiki', 'docs', 'status', 'panel', 'cpanel', 'webdisk', 'autodiscover', 'autoconfig', 'owa', 'exchange', 'email', 'relay', 'mx', 'mx1', 'mx2', 'news', 'tv', 'radio', 'chat', 'sip', 'proxy', 'gateway', 'monitor', 'jenkins', 'git', 'gitlab', 'svn']

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
                        if name.endswith(domain): subdomains.add(name)
            except Exception: pass
    except Exception: pass
    return list(subdomains)

# ================= WEBSITE MONITORING ROUTES =================
@app.post("/start")
async def start_monitoring(request: StartRequest, background_tasks: BackgroundTasks, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    if state.is_monitoring: raise HTTPException(status_code=400, detail="Already monitoring")
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

# FIXED: Robust SSL Extraction with IPv4 Fallback (Specifically for Google)
def _get_cert_via_ssl_module(domain_name):
    # Helper to perform the socket handshake
    def _fetch_cert(target_ip_or_domain):
        context = ssl.create_default_context()
        # Short timeout is crucial to prevent hanging on IPv6 dead-ends
        with socket.create_connection((target_ip_or_domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None

                # Extract Issuer
                issuer = "Unknown"
                for item in cert.get('issuer', []):
                    for sub_item in item:
                        if sub_item[0] == 'organizationName':
                            issuer = sub_item[1]
                            break
                    if issuer != "Unknown": break
                
                if issuer == "Unknown":
                    for item in cert.get('issuer', []):
                         for sub_item in item:
                            if sub_item[0] == 'commonName':
                                issuer = sub_item[1]
                                break
                         if issuer != "Unknown": break

                not_after = cert.get('notAfter')
                return {
                    "status": "Valid",
                    "issuer": issuer,
                    "expires": not_after
                }

    # 1. Try Default Connection (System Preferred, often IPv6)
    try:
        return _fetch_cert(domain_name)
    except Exception as e:
        # 2. Force IPv4 Fallback (Critical for Google/Facebook on dev networks)
        try:
            # Explicitly get IPv4 address
            ip = socket.gethostbyname(domain_name)
            # If IP is the same as domain (no lookup happened) or distinct, we try the IP
            return _fetch_cert(ip)
        except Exception:
            # If both fail, we return None
            return None

def _perform_scan(domain: Domain, db: Session):
    domain_name = domain.domain_name
    score = 0
    ssl_info = {"status": "Unknown", "expires": None, "issuer": "Unknown"}
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
    
    # Use the robust SSL function
    ssl_result = _get_cert_via_ssl_module(domain_name)
    if ssl_result:
        ssl_info["status"] = ssl_result["status"]
        ssl_info["expires"] = ssl_result["expires"]
        ssl_info["issuer"] = ssl_result["issuer"]
        score += 10
    else:
        # Fallback if SSL socket fails completely
        try: 
            r = requests.head(f"https://{domain_name}", timeout=5, verify=False)
            if r.status_code < 500: 
                ssl_info["status"] = "Valid (Connection OK)"
                score += 5
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
    if not domain: raise HTTPException(status_code=404, detail="Domain not found")
    
    # Parse Data Safely
    ssl_data = json.loads(domain.ssl_data) if domain.ssl_data else {}
    whois_data = json.loads(domain.whois_data) if domain.whois_data else {}
    dns_data = json.loads(domain.dns_data) if domain.dns_data else {}
    
    manual_data = {}
    try:
        if domain.manual_data:
            manual_data = json.loads(domain.manual_data)
    except (json.JSONDecodeError, TypeError):
        manual_data = {}

    return {
        "id": domain.id, "domain_name": domain.domain_name, "security_score": domain.security_score,
        "last_scanned": domain.last_scanned, "ssl_status": ssl_data.get("status", "Unknown"),
        "ssl_expires": ssl_data.get("expires"), "ssl_issuer": ssl_data.get("issuer", "Unknown"),
        "registrar": whois_data.get("registrar", "Unknown"), "creation_date": whois_data.get("created"),
        "expiration_date": whois_data.get("expires"), 
        "dns_records": dns_data,
        "manual_data": manual_data
    }

@app.post("/domain/update-manual/{id}")
def update_domain_manual(id: int, payload: dict, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    domain = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not domain: raise HTTPException(status_code=404, detail="Domain not found")
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

# Helper for formatting dates in PDF
def formatDate(dateStr):
    if not dateStr: return "Unknown"
    try:
        if "T" in dateStr: dateStr = dateStr.split("T")[0]
        date = datetime.strptime(dateStr, "%Y-%m-%d")
        return date.strftime('%B %d, %Y')
    except:
        return "Invalid Date"