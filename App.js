import React, { useState, useEffect, useRef, useCallback } from "react";
import "./App.css";

// ================= HELPER FUNCTIONS =================
const formatDate = (dateStr) => {
  if (!dateStr) return "Unknown";
  try {
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return "Invalid Date";
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  } catch (e) {
    return "Unknown";
  }
};

// ================= PASSWORD MODAL COMPONENT =================
const PasswordModal = ({ isOpen, onClose, onSubmit, title }) => {
  const [pwd, setPwd] = useState("");
  const [confirm, setConfirm] = useState("");

  if (!isOpen) return null;

  const handleSubmit = () => {
    if (!pwd) {
      alert("Password cannot be empty.");
      return;
    }
    if (pwd !== confirm) {
      alert("Passwords do not match!");
      return;
    }
    onSubmit(pwd);
    // Reset and close
    setPwd("");
    setConfirm("");
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h3>{title || "Secure PDF Report"}</h3>
        <p style={{fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "15px"}}>
          Enter a password to encrypt the PDF. You will need this password to open the file.
        </p>
        <div className="modal-input-group">
          <input 
            type="password" 
            placeholder="Enter Password" 
            value={pwd} 
            onChange={(e) => setPwd(e.target.value)} 
            autoFocus
          />
          <input 
            type="password" 
            placeholder="Confirm Password" 
            value={confirm} 
            onChange={(e) => setConfirm(e.target.value)} 
          />
        </div>
        <div className="modal-actions">
          <button onClick={onClose} className="btn-cancel">Cancel</button>
          <button onClick={handleSubmit} className="btn-submit">Generate PDF</button>
        </div>
      </div>
    </div>
  );
};

// ================= LANDING PAGE COMPONENT =================
const LandingPage = ({ onLogin }) => {
  return (
    <div className="landing-page">
      <div className="glow-orb orb-1"></div>
      <div className="glow-orb orb-2"></div>

      <nav className="landing-nav">
        <div className="brand">
          Cyber<span>Guard</span>
        </div>
        <div className="nav-actions">
          <a href="#contact" className="btn-nav contact">
            Contact Us
          </a>
          <button onClick={onLogin} className="btn-nav login">
            Login
          </button>
        </div>
      </nav>

      <header className="hero-section">
        <h1 className="hero-title">
          Next-Generation Domain
          <br /> Monitoring & Detection
        </h1>
        <p className="hero-subtitle">
          Track, analyze, and secure your web infrastructure in real-time.
          Real-time website and system monitoring, plus domain tracking.
        </p>
        <div className="cta-group">
          <button onClick={onLogin} className="btn-large btn-primary-large">
            Get Started
          </button>
        </div>
      </header>

      <section className="features-section">
        <div className="section-header">
          <h2>System Capabilities</h2>
          <p>Everything you need to manage your digital presence.</p>
        </div>
        <div className="cards-grid">
          <div className="feature-card">
            <div className="card-icon">📡</div>
            <h3>Real-time Tracking</h3>
            <p>
              Instant updates on domain status, DNS propagation, and uptime
              metrics.
            </p>
          </div>
          <div className="feature-card">
            <div className="card-icon">⚠️</div>
            <h3>Threat & Anomaly Detection</h3>
            <p>
              Identify potential security threats and system anomalies instantly
              to keep your infrastructure safe.
            </p>
          </div>
          <div className="feature-card">
            <div className="card-icon">📊</div>
            <h3>Detailed Analytics</h3>
            <p>
              Visual reports on latency, traffic spikes, and historical
              performance data.
            </p>
          </div>
        </div>
      </section>

      <section id="contact" className="contact-section">
        <div className="section-header">
          <h2>Contact Our Developers</h2>
          <p>Get support from our expert engineering team.</p>
        </div>
        <div className="team-grid">
          <div className="team-card">
            <div className="avatar">HC</div>
            <div className="dev-name">Henon Chare</div>
            <div className="dev-role">Lead Developer</div>
            <a href="mailto:henonchare21@gmail.com" className="contact-link email-link">
              📧 henonchare21@gmail.com
            </a>
            <a href="tel:+251982049520" className="contact-link phone-link">
              📞 +251 98 204 9520
            </a>
            <a href="https://github.com/henon-chare" target="_blank" rel="noopener noreferrer" className="contact-link github-link">
              💻 henon-chare
            </a>
          </div>
          <div className="team-card">
            <div className="avatar">BT</div>
            <div className="dev-name">Biniyam Temesgen</div>
            <div className="dev-role">Backend Engineer</div>
            <a href="mailto:biniyamtemesgen40@gmail.com" className="contact-link email-link">
              📧 biniyamtemesgen40@gmail.com
            </a>
            <a href="tel:+251985957185" className="contact-link phone-link">
              📞 +251 98 595 7185
            </a>
            <a href="https://github.com/Bi-ni-yam" target="_blank" rel="noopener noreferrer" className="contact-link github-link">
              💻 Bi-ni-yam
            </a>
          </div>
          <div className="team-card">
            <div className="avatar">MK</div>
            <div className="dev-name">Mikiyas Kindie</div>
            <div className="dev-role">Frontend Specialist</div>
            <a href="mailto:mikiyaskindie6@gmail.com" className="contact-link email-link">
              📧 mikiyaskindie6@gmail.com
            </a>
            <a href="tel:+251948010770" className="contact-link phone-link">
              📞 +251 94 801 0770
            </a>
            <a href="https://github.com/mikii122129" target="_blank" rel="noopener noreferrer" className="contact-link github-link">
              💻 mikii122129
            </a>
          </div>
          <div className="team-card">
            <div className="avatar">AM</div>
            <div className="dev-name">Abinet Melkamu</div>
            <div className="dev-role">System Architect</div>
            <a href="mailto:instaman2124@gmail.com" className="contact-link email-link">
              📧 instaman2124@gmail.com
            </a>
            <a href="tel:+251923248825" className="contact-link phone-link">
              📞 +251 92 324 8825
            </a>
            <a href="https://github.com/abinetbdu" target="_blank" rel="noopener noreferrer" className="contact-link github-link">
              💻 abinetbdu
            </a>
          </div>
        </div>
      </section>

      <footer className="landing-footer">
        &copy; 2026 Domain Monitoring System. All rights reserved.
      </footer>
    </div>
  );
};

// ================= SPARKLINE COMPONENT =================
const Sparkline = ({ history, width = 200, height = 40, isDegraded }) => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    const w = width;
    const h = height;
    
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, w, h);
    
    if (!history || history.length < 2) return;

    const minVal = Math.min(...history);
    const maxVal = Math.max(...history, minVal + 50);
    const range = maxVal - minVal;
    const stepX = w / (history.length - 1);

    const currentVal = history[history.length - 1];
    const isBad = currentVal > 3000 || currentVal === 0 || isDegraded;
    
    const lineColor = isBad ? "#ef4444" : (currentVal > 1000 ? "#f59e0b" : "#00eaff");

    const gradient = ctx.createLinearGradient(0, 0, 0, h);
    if (isBad) {
      gradient.addColorStop(0, "rgba(239, 68, 68, 0.5)");
      gradient.addColorStop(1, "rgba(239, 68, 68, 0)");
    } else {
      gradient.addColorStop(0, "rgba(0, 234, 255, 0.4)");
      gradient.addColorStop(1, "rgba(0, 234, 255, 0)");
    }

    ctx.beginPath();
    history.forEach((val, i) => {
      const x = i * stepX;
      const normalizedY = (val - minVal) / (range || 1); 
      const y = h - (normalizedY * h);
      if (i === 0) ctx.moveTo(x, y);
      else {
        const prevX = (i - 1) * stepX;
        const prevVal = history[i - 1];
        const prevNormalizedY = (prevVal - minVal) / (range || 1);
        const prevY = h - (prevNormalizedY * h);
        const cp1x = prevX + (x - prevX) / 2;
        const cp1y = prevY;
        const cp2x = prevX + (x - prevX) / 2;
        const cp2y = y;
        ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, x, y);
      }
    });

    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    ctx.shadowBlur = 10;
    ctx.shadowColor = lineColor;
    ctx.stroke();
    ctx.shadowBlur = 0;

  }, [history, width, height, isDegraded]);

  return (
    <div className="chart-container">
      <canvas 
        ref={canvasRef} 
        width={width} 
        height={height} 
        style={{ width: "100%", height: "100%", display: "block" }} 
      />
    </div>
  );
};

// ================= UPGRADED DOMAIN TRACKING COMPONENT =================

const ExpiryCountdown = ({ label, dateStr }) => {
  if (!dateStr) return <div className="expiry-badge">N/A</div>;

  const targetDate = new Date(dateStr);
  const now = new Date();
  const diffTime = targetDate - now;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

  let statusClass = "status-green"; 
  if (diffDays <= 7) statusClass = "status-red";
  else if (diffDays <= 30) statusClass = "status-yellow";

  return (
    <div className={`expiry-info ${statusClass}`}>
      <span className="expiry-label">{label}</span>
      <span className="expiry-days">
        {diffDays < 0 ? "Expired" : `${diffDays} Days`}
      </span>
      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px' }}>
        ({formatDate(dateStr)})
      </span>
    </div>
  );
};

const DataDisplayBadge = ({ label, value, isDate = false, icon }) => {
  if (!value) return <div className="reg-date-badge">N/A</div>;
  
  const displayValue = isDate ? formatDate(value) : value;

  return (
    <div className="reg-date-badge interactive-chip">
      <span className="reg-label">
        {icon && <span className="chip-icon">{icon}</span>}
        {label}
      </span>
      <span className="reg-date-text">
        {displayValue}
      </span>
    </div>
  );
};

const DomainTrackingComponent = ({ onBack, token }) => {
  const [domains, setDomains] = useState([]);
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [detailData, setDetailData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [newDomainInput, setNewDomainInput] = useState("");
  const [isAdding, setIsAdding] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  
  const [expandedDns, setExpandedDns] = useState({});
  
  // NEW: State for Modal
  const [isPwdModalOpen, setIsPwdModalOpen] = useState(false);

  const fetchDomains = useCallback(async () => {
    try {
      const res = await fetch("http://localhost:8000/domain/list", {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) {
        if (res.status === 401) {
            alert("Session expired. Please login again.");
            window.location.reload();
        }
        setDomains([]);
        setLoading(false);
        return;
      }
      const data = await res.json();
      setDomains(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Failed to fetch domains", err);
      setDomains([]);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchDomains();
    const interval = setInterval(fetchDomains, 60000);
    return () => clearInterval(interval);
  }, [token, fetchDomains]);

  // UPDATED: Trigger Modal
  const handleGlobalDomainReport = () => {
    setIsPwdModalOpen(true);
  };

  // NEW: Actual Download Function
  const downloadReportWithPassword = async (password) => {
    try {
        const res = await fetch("http://localhost:8000/domain/global-report", {
            method: "POST",
            headers: { "Content-Type": "application/json", 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ password: password }) // Send user password
        });

        if (!res.ok) throw new Error("Failed to generate report");

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `global_domain_inventory.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (err) {
        console.error(err);
        alert("Error generating report");
    }
  };

  const handleAdd = async (e) => {
    e.preventDefault();
    if (!newDomainInput) return;
    setIsAdding(true);
    try {
      const res = await fetch("http://localhost:8000/domain/add", {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(newDomainInput),
      });
      if (res.ok) {
        const data = await res.json();
        setNewDomainInput("");
        alert(`${data.message}`);
        await fetchDomains();
      } else {
        const errorData = await res.json().catch(() => ({}));
        alert("Failed to add domain: " + (errorData.detail || "Unknown error"));
      }
    } catch (err) {
      alert("Error adding domain");
    } finally {
      setIsAdding(false);
    }
  };

  const handleDelete = async (e, id) => {
    e.stopPropagation();
    if (!window.confirm("Are you sure? This cannot be undone.")) return;

    try {
      const res = await fetch(`http://localhost:8000/domain/${id}`, {
        method: "DELETE",
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (res.ok || res.status === 204) {
        if (selectedDomain?.id === id) {
          setSelectedDomain(null);
          setDetailData(null);
        }
        await fetchDomains();
      } else {
        let errorText = "Failed to delete domain.";
        try {
            const errData = await res.json();
            if (errData.detail) errorText += ` Server says: ${errData.detail}`;
        } catch (e) {
            errorText += ` Server status: ${res.status} ${res.statusText}`;
        }
        alert(errorText);
      }
    } catch (err) {
      console.error(err);
      alert("Network error while deleting. Please check console.");
    }
  };

  const handleSelect = async (domainId) => {
    const domain = domains.find((d) => d.id === domainId);
    setSelectedDomain(domain);
    setExpandedDns({});
    setDetailData(null); 

    try {
      const res = await fetch(`http://localhost:8000/domain/detail/${domainId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error("Failed to fetch details");
      const data = await res.json();
      setTimeout(() => setDetailData(data), 100);
    } catch (err) {
      console.error(err);
      alert("Could not load details.");
      setDetailData(null);
    }
  };

  const handleRescan = async () => {
    if (!selectedDomain) return;
    setIsScanning(true);
    try {
      const res = await fetch(`http://localhost:8000/domain/scan/${selectedDomain.id}`, {
        method: "POST",
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        await handleSelect(selectedDomain.id);
        await fetchDomains();
      } else {
        throw new Error("Scan failed");
      }
    } catch (err) {
      console.error(err);
      alert("❌ Scan failed.");
    } finally {
      setTimeout(() => setIsScanning(false), 1500);
    }
  };

  const getCleanIssuer = (issuer) => {
    if (!issuer || issuer === "N/A" || issuer === "Unknown") return "Unknown / Not Detected";
    return issuer;
  };

  const getDaysRemaining = (dateStr) => {
    if (!dateStr) return null;
    const target = new Date(dateStr);
    const now = new Date();
    const diff = Math.ceil((target - now) / (1000 * 60 * 60 * 24));
    return diff;
  }

  const toggleDns = (type) => {
    setExpandedDns(prev => ({ ...prev, [type]: !prev[type] }));
  };

  return (
    <div className="up-dashboard dashboard-atmosphere" style={{ gridTemplateColumns: "350px 1fr" }}>
      <div className="glow-orb orb-dashboard-1"></div>
      <div className="glow-orb orb-dashboard-2"></div>

      <aside className="up-sidebar">
        <div className="up-sidebar-header" style={{ flexDirection: "column", alignItems: "flex-start", gap: "10px" }}>
            <div style={{ display: "flex", width: "100%", justifyContent: "space-between", alignItems: "center" }}>
                <h2 style={{margin: 0}}>Domain Intel</h2>
                <div className="up-status-badge live">Live Tracking</div>
            </div>
            <button onClick={handleGlobalDomainReport} className="up-btn-gray" style={{ width: "100%", fontSize: "0.75rem", padding: "6px" }}>
                📊 Download Inventory Report
            </button>
        </div>

        <div style={{ marginTop: "20px" }}>
          <form onSubmit={handleAdd} className="up-input-group">
            <input
              type="text"
              placeholder="example.com"
              value={newDomainInput}
              onChange={(e) => setNewDomainInput(e.target.value)}
              disabled={isAdding}
              autoComplete="off"
            />
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                type="submit"
                className="up-btn-green glow-effect"
                disabled={isAdding || !newDomainInput.trim()}
                style={{ flex: 1 }}
              >
                {isAdding ? "Adding..." : "Track"}
              </button>
            </div>
          </form>
        </div>

        <div className="up-nav" style={{ marginTop: "20px", padding: 0 }}>
          {domains.map((d) => (
            <div
              key={d.id}
              className={`nav-item domain-card-item interactive-card ${
                selectedDomain?.id === d.id ? "active-glow" : ""
              }`}
              onClick={() => handleSelect(d.id)}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "12px", width: "100%" }}>
                
                <div className="health-ring-container" title={`Score: ${d.security_score}`}>
                  <div 
                    className="health-ring"
                    style={{
                      background: `conic-gradient(var(--status-blue) ${d.security_score}%, rgba(255,255,255,0.1) 0)`,
                      borderColor: d.security_score > 50 ? "rgba(255,255,255,0.1)" : "var(--status-red)"
                    }}
                  ></div>
                  <div className="health-dot"></div>
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: "bold", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {d.domain_name}
                  </div>
                </div>

                <button
                  onClick={(e) => handleDelete(e, d.id)}
                  className="icon-btn-delete"
                  title="Delete"
                >
                  ✕
                </button>
              </div>
            </div>
          ))}
          {domains.length === 0 && !loading && (
            <div className="up-empty-state" style={{border: "none", background: "transparent"}}>
              <p>No domains tracked yet.</p>
            </div>
          )}
        </div>

        <div className="up-footer-nav">
          <button onClick={onBack} className="back-btn">← Back to Dashboard</button>
        </div>
      </aside>

      <main className="up-main">
        {detailData ? (
          <div className="fade-in-content">
            <header className="up-header">
              <div>
                <div style={{display: "flex", alignItems: "center", gap: "15px"}}>
                  <h3 style={{ margin: 0 }}>{detailData.domain_name}</h3>
                </div>
                <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
                  Last Scanned: {new Date(detailData.last_scanned).toLocaleString()}
                </span>
              </div>
              
              <button 
                onClick={handleRescan} 
                className={`up-btn-blue ${isScanning ? 'scanning-btn' : ''}`} 
                disabled={isScanning}
              >
                {isScanning ? "Scanning..." : "🔄 Refresh Scan"}
              </button>
            </header>

            {isScanning && <div className="scan-overlay"><div className="scan-line"></div></div>}

            <div className="analytics-grid">
                <div className="analytics-card glass-card-hover">
                    <div className="card-header">
                        <span className="card-icon">🔒</span>
                        <h4>SSL Certificate</h4>
                    </div>
                    <div className="card-body">
                        <div className="status-row">
                            <span>Status:</span>
                            <span className={detailData.ssl_status === 'Valid' ? 'text-green' : 'text-red'}>
                                {detailData.ssl_status}
                            </span>
                        </div>
                        <div className="status-row">
                            <span>Issuer:</span>
                            <span className="text-glow">
                                {getCleanIssuer(detailData.ssl_issuer)}
                            </span>
                        </div>
                        <div style={{marginTop: "15px"}}>
                            <ExpiryCountdown label="Expires In" dateStr={detailData.ssl_expires} />
                        </div>
                    </div>
                </div>

                <div className="analytics-card glass-card-hover">
                    <div className="card-header">
                        <span className="card-icon">📅</span>
                        <h4>Domain Registration</h4>
                    </div>
                    <div className="card-body">
                         <DataDisplayBadge label="Registrar" value={detailData.registrar} isDate={false} icon="🏢" />
                         <DataDisplayBadge label="Registered On" value={detailData.creation_date} isDate={true} icon="🎂" />
                         <DataDisplayBadge label="Expiration Date" value={detailData.expiration_date} isDate={true} icon="⏳" />
                        
                        <div style={{marginTop: "10px"}}>
                             <ExpiryCountdown label="Renew In" dateStr={detailData.expiration_date} />
                        </div>
                    </div>
                </div>

                <div className="analytics-card glass-card-hover">
                    <div className="card-header">
                         <span className="card-icon">🩺</span>
                        <h4>Health Checklist</h4>
                    </div>
                    <div className="card-body" style={{flexDirection: "column", gap: "12px"}}>
                        <div className="health-item interactive-item">
                            <span className="health-icon">
                                {detailData.ssl_status === 'Valid' ? '✅' : '⛔'}
                            </span>
                            <div className="health-text">
                                <strong>SSL Valid</strong>
                                <div style={{fontSize: "0.75rem", color: "var(--text-muted)"}}>
                                    {detailData.ssl_status === 'Valid' ? 'Certificate is trusted' : 'Invalid or missing cert'}
                                </div>
                            </div>
                        </div>

                        <div className="health-item interactive-item">
                            {(() => {
                                const days = getDaysRemaining(detailData.expiration_date);
                                let icon = '✅';
                                let text = 'Safe for renewal';
                                if (days <= 30 && days > 0) { icon = '⚠️'; text = 'Expiring soon'; }
                                else if (days <= 0) { icon = '⛔'; text = 'Expired'; }
                                
                                return (
                                    <>
                                        <span className="health-icon">{icon}</span>
                                        <div className="health-text">
                                            <strong>Domain Expiry</strong>
                                            <div style={{fontSize: "0.75rem", color: "var(--text-muted)"}}>
                                                {text}
                                            </div>
                                        </div>
                                    </>
                                )
                            })()}
                        </div>

                        <div className="health-item interactive-item">
                             <span className="health-icon">
                                {detailData.dns_records && detailData.dns_records['A'] && detailData.dns_records['A'].length > 0 ? '✅' : '⚠️'}
                            </span>
                            <div className="health-text">
                                <strong>DNS Resolution</strong>
                                <div style={{fontSize: "0.75rem", color: "var(--text-muted)"}}>
                                    {detailData.dns_records && detailData.dns_records['A'] && detailData.dns_records['A'].length > 0 
                                        ? 'A Records found' : 'No A Records detected'}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div className="up-widget glass-widget" style={{marginTop: "20px"}}>
              <h4>DNS Infrastructure</h4>
              {detailData.dns_records && Object.keys(detailData.dns_records).length > 0 ? (
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "15px" }}>
                  {Object.entries(detailData.dns_records).map(([type, records]) => (
                    records.length > 0 && (
                      <div key={type} className="dns-box interactive-dns-box">
                        <div className="dns-type">{type} Records ({records.length})</div>
                        <div className="dns-list">
                            {records.slice(0, expandedDns[type] ? records.length : 3).map((rec, i) => (
                                <div key={i} className="dns-item interactive-dns-item">{rec}</div>
                            ))}
                            {records.length > 3 && (
                                <div 
                                    className="dns-more-btn" 
                                    onClick={() => toggleDns(type)}
                                >
                                    {expandedDns[type] ? `Show less` : `+ ${records.length - 3} more`}
                                </div>
                            )}
                        </div>
                      </div>
                    )
                  ))}
                </div>
              ) : (
                <div className="up-empty-state">
                  No DNS records detected.
                </div>
              )}
            </div>

          </div>
        ) : (
          <div className="up-empty-state fade-in-content">
            <div style={{fontSize: "3rem", marginBottom: "20px"}}>🔍</div>
            <h3>Select a domain</h3>
            <p>Choose a domain from sidebar to view detailed analytics.</p>
          </div>
        )}
      </main>
      
      {/* RENDER MODAL */}
      <PasswordModal 
        isOpen={isPwdModalOpen} 
        onClose={() => setIsPwdModalOpen(false)} 
        onSubmit={downloadReportWithPassword}
        title="Secure Domain Report"
      />
    </div>
  );
};

// ================= MONITORING COMPONENT =================
const MonitoringComponent = ({ onBack, token }) => {
  const [url, setUrl] = useState("");
  const [lastStartedUrl, setLastStartedUrl] = useState("");
  
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("monitoring");
  const [searchTerm, setSearchTerm] = useState("");
  const [filterStatus, setFilterStatus] = useState("all");
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  
  const [selectedMonitor, setSelectedMonitor] = useState(null);
  
  // NEW: State for Modal
  const [isPwdModalOpen, setIsPwdModalOpen] = useState(false);

  const [data, setData] = useState({
    targets: [],
    current_latencies: {},
    baseline_avgs: {},
    status_messages: {},
    histories: {},
    timestamps: {},
  });

  const isTargetDown = (status, latency) => {
    if (!status) return false;
    const backendDown = 
           status.includes("CRITICAL") || 
           status.includes("ERROR") || 
           status.includes("SERVER DOWN") ||
           status.includes("CONNECTION REFUSED") ||
           status.includes("NOT FOUND (404)") || 
           status.includes("TIMEOUT");           
    return backendDown;
  };

  // Sync Backend State
  useEffect(() => {
      const syncBackendState = async () => {
          try {
              const response = await fetch("http://localhost:8000/status", {
                  headers: { 'Authorization': `Bearer ${token}` }
              });
              if (response.ok) {
                  const data = await response.json();
                  if (data.is_monitoring) {
                      setIsMonitoring(true);
                      const activeUrl = data.target_url || (data.targets.length > 0 ? data.targets[0] : "");
                      setUrl(activeUrl);
                      setLastStartedUrl(activeUrl);
                  }
              }
          } catch (error) {
              console.error("Failed to sync with backend:", error);
          }
      };
      syncBackendState();
  }, [token]);

  useEffect(() => {
    let interval;
    if (isMonitoring) {
      interval = setInterval(async () => {
        try {
          const response = await fetch("http://localhost:8000/status", {
              headers: { 'Authorization': `Bearer ${token}` }
          });
          if (response.status === 401) {
              clearInterval(interval);
              alert("Session expired");
              window.location.reload();
              return;
          }
          const jsonData = await response.json();
          setData(jsonData);
        } catch (error) {
          console.error("Backend connection lost", error);
        }
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isMonitoring, token]);

  // UPDATED: Trigger Modal
  const handleGlobalMonitoringReport = () => {
    setIsPwdModalOpen(true);
  };

  // NEW: Actual Download Function
  const downloadReportWithPassword = async (password) => {
    try {
        const res = await fetch("http://localhost:8000/monitoring/global-report", {
            method: "POST",
            headers: { "Content-Type": "application/json", 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ password: password }) // Send user password
        });

        if (!res.ok) throw new Error("Failed to generate report");

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `global_session_report.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (err) {
        console.error(err);
        alert("Error generating report");
    }
  };

  const handleStart = async () => {
    if (!url || !url.startsWith("http")) {
      alert("Please enter a valid URL starting with http/https");
      return;
    }
    setIsLoading(true); 
    const payload = { url: url.trim() };
    try {
      const response = await fetch("http://localhost:8000/start", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json", 
          Accept: "application/json",
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
          if (response.status === 401) {
              alert("Unauthorized");
              return;
          }
          const errorBody = await response.json().catch(() => ({ detail: "No details" }));
          throw new Error(`Backend rejected request (${response.status}): ${errorBody.detail || "Validation error"}`);
      }
      await response.json();
      setIsMonitoring(true);
      setLastStartedUrl(url.trim()); 
    } catch (err) {
      console.error(err);
      alert("Start failed:\n" + (err.message || "Unknown error"));
    } finally {
      setIsLoading(false); 
    }
  };

  const handleResume = () => {
      setUrl(lastStartedUrl); 
      handleStart();           
  };

  const handleStop = async () => {
    try {
      const res = await fetch("http://localhost:8000/stop", { 
          method: "POST",
          headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error(res.statusText);
      setIsMonitoring(false);
    } catch (error) {
      console.error(error);
      alert("Failed to stop: " + error.message);
    }
  };

  const handleClear = () => {
    setData({
      targets: [],
      current_latencies: {},
      baseline_avgs: {},
      status_messages: {},
      histories: {},
      timestamps: {},
    });
    setIsMonitoring(false);
    setSelectedMonitor(null);
    setLastStartedUrl(""); 
  };

  const getFilteredTargets = () => {
    return data.targets.filter((target) => {
      const matchesSearch = target.toLowerCase().includes(searchTerm.toLowerCase());
      const latency = data.current_latencies[target] || 0;
      const status = data.status_messages[target] || "";
      const down = isTargetDown(status, latency);
      
      let matchesFilter = true;
      if (filterStatus === "up") matchesFilter = !down;
      if (filterStatus === "down") matchesFilter = down;

      return matchesSearch && matchesFilter;
    });
  };

  // ================= MONITOR DETAIL SUB-COMPONENT =================
  const MonitorDetailView = ({ target }) => {
      const history = data.histories[target] || [];
      const status = data.status_messages[target] || "Idle";
      
      const SLOW_THRESHOLD = 2000;
      const validHistory = history.filter(h => h > 0);
      const validCount = validHistory.length;
      const totalCount = history.length;
      const healthyCount = history.filter(h => h > 0 && h < SLOW_THRESHOLD).length;
      
      const uptimePercent = totalCount > 0 ? ((healthyCount / totalCount) * 100).toFixed(2) : "0.00";
      const avg = validHistory.length ? (validHistory.reduce((a, b) => a + b, 0) / validHistory.length).toFixed(0) : 0;
      const min = validHistory.length ? Math.min(...validHistory).toFixed(0) : 0;
      const max = validHistory.length ? Math.max(...validHistory).toFixed(0) : 0;
      
      const is404 = status.includes("NOT FOUND");
      const down = isTargetDown(status, history[history.length - 1]);
      const isSlow = status.includes("WARNING") || (history.length > 0 && history[history.length-1] > 2000);
      const lastCheck = new Date().toLocaleTimeString();

      return (
          <div className="monitor-detail-container fade-in-content">
              <button onClick={() => setSelectedMonitor(null)} className="back-btn" style={{marginBottom: "20px"}}>
                  ← Back to Dashboard
              </button>

              <div className="up-widget" style={{borderLeft: "5px solid", borderLeftColor: down ? (is404 ? "var(--status-red)" : "var(--status-red)") : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                  <div style={{display: "flex", justifyContent: "space-between", alignItems: "center"}}>
                      <div>
                          <h1 style={{fontSize: "2rem", margin: "0 0 10px 0"}}>{target.replace(/^https?:\/\//, '')}</h1>
                          <div style={{display: "flex", alignItems: "center", gap: "20px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: down ? (is404 ? "var(--status-red)" : "var(--status-red)") : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                                  {is404 ? "404 Not Found" : (down ? "DOWN" : (isSlow ? "SLOW RESPONSE" : "UP"))}
                              </div>
                              <div style={{color: "var(--text-muted)", fontSize: "0.9rem"}}>
                                  HTTP/S monitor for {target}
                              </div>
                          </div>
                      </div>
                  </div>
                  
                  <div style={{textAlign: "right", color: "var(--text-muted)", marginTop: "10px"}}>
                      <div>Last check: {lastCheck}</div>
                      <div>Checked every 1.5s</div>
                  </div>
              </div>

              {/* Response Time Stats */}
              <div className="analytics-grid" style={{marginTop: "20px"}}>
                  <div className="analytics-card glass-card-hover" style={{gridColumn: "span 3"}}>
                      <div className="card-header">
                          <span className="card-icon">⚡</span>
                          <h4>Response Time (Last Session)</h4>
                      </div>
                      <div style={{display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "20px", marginTop: "10px"}}>
                          <div style={{textAlign: "center", padding: "15px", background: "rgba(0,0,0,0.2)", borderRadius: "4px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: "var(--status-blue)"}}>{avg} ms</div>
                              <div style={{color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem"}}>Average</div>
                          </div>
                          <div style={{textAlign: "center", padding: "15px", background: "rgba(0,0,0,0.2)", borderRadius: "4px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: "var(--status-green)"}}>{min} ms</div>
                              <div style={{color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem"}}>Minimum</div>
                          </div>
                          <div style={{textAlign: "center", padding: "15px", background: "rgba(0,0,0,0.2)", borderRadius: "4px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: "var(--status-red)"}}>{max} ms</div>
                              <div style={{color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem"}}>Maximum</div>
                          </div>
                      </div>
                  </div>
              </div>

              {/* Uptime Grid */}
              <div className="analytics-grid" style={{marginTop: "20px", gridTemplateColumns: "repeat(4, 1fr)"}}>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Current Session</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Last 24h (Est.)</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Last 30 Days (Est.)</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Last 365 Days (Est.)</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
              </div>

              {/* Large Chart */}
              <div className="up-widget glass-widget" style={{marginTop: "20px"}}>
                  <div className="card-header">
                      <h4>Response Time History</h4>
                      <span className="text-muted" style={{fontSize: "0.8rem"}}>Last {history.length} checks</span>
                  </div>
                  <div style={{padding: "20px", display: "flex", justifyContent: "center"}}>
                       <Sparkline history={history} width={800} height={200} isDegraded={down} />
                  </div>
              </div>

              {/* Latest Incidents */}
              <div className="up-widget glass-widget" style={{marginTop: "20px"}}>
                  <h4>Latest Incidents</h4>
                  {down ? (
                      <table style={{width: "100%", textAlign: "left", borderCollapse: "collapse", marginTop: "10px"}}>
                          <thead>
                              <tr style={{borderBottom: "1px solid rgba(255,255,255,0.1)"}}>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem"}}>Status</th>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem"}}>Root Cause</th>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem"}}>Started</th>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem"}}>Duration</th>
                              </tr>
                          </thead>
                          <tbody>
                              <tr>
                                  <td style={{padding: "10px", color: down ? (is404 ? "var(--status-red)" : "var(--status-red)") : "var(--status-green)", fontWeight: "bold"}}>
                                      {is404 ? "404 Error" : "Down"}
                                  </td>
                                  <td style={{padding: "10px"}}>{status}</td>
                                  <td style={{padding: "10px"}}>{lastCheck}</td>
                                  <td style={{padding: "10px", color: "var(--status-red)"}}>Ongoing...</td>
                              </tr>
                          </tbody>
                      </table>
                  ) : isSlow ? (
                      <div className="up-empty-state" style={{border: "none", background: "transparent", padding: "20px"}}>
                          <p style={{color: "var(--status-orange)"}}>⚠️ High latency detected. Site is responding but slowly.</p>
                      </div>
                  ) : (
                      <div className="up-empty-state" style={{border: "none", background: "transparent", padding: "20px"}}>
                          <p style={{color: "var(--status-green)"}}>✅ No active incidents in the current session.</p>
                      </div>
                  )}
              </div>
          </div>
      );
  };

  const renderContent = () => {
    if (selectedMonitor) {
        return <MonitorDetailView target={selectedMonitor} />;
    }

    if (activeTab === "monitoring") {
      const displayTargets = getFilteredTargets();
      return (
        <div className="up-monitors-list hud-grid">
          {displayTargets.length === 0 ? (
            <div className="up-empty-state">
              <p>No monitors found matching your criteria.</p>
            </div>
          ) : (
            displayTargets.map((target) => {
              const history = data.histories[target] || [];
              let latency = data.current_latencies[target] || 0;
              if (latency === 0 && history.length > 0) {
                  latency = history[history.length - 1];
              }

              const status = data.status_messages[target] || "Idle";
              const down = isTargetDown(status, latency);
              
              const is404 = status.includes("NOT FOUND");
              const isSlow = !down && (status.includes("WARNING") || latency > 2000);

              let statusLabel = "Operational";
              let statusClass = "status-up";
              let rowClass = "up"; 
              
              if (is404) {
                  statusLabel = "404 Not Found";
                  statusClass = "status-404";
                  rowClass = "down"; 
              } else if (down) {
                  rowClass = "down";
                  if (status.includes("TIMEOUT")) { 
                      statusLabel = "TIMEOUT"; 
                      statusClass = "status-timeout"; 
                  }
                  else if (status.includes("CRITICAL")) {
                      statusLabel = "CRITICAL"; 
                      statusClass = "status-down"; 
                  }
                  else { 
                      statusLabel = "DOWN"; 
                      statusClass = "status-down"; 
                  }
              } else {
                  if (isSlow) {
                      statusLabel = "SLOW RESPONSE";
                      statusClass = "status-slow"; 
                  } else if (status.includes("Learning")) {
                      statusLabel = "Learning Baseline";
                      statusClass = "status-slow";
                  } else if (status.includes("Unstable")) {
                      statusLabel = "Unstable";
                      statusClass = "status-slow";
                  }
              }

              return (
                <div 
                  key={target} 
                  className={`up-monitor-row ${rowClass}`} 
                  onClick={() => setSelectedMonitor(target)} 
                  style={{cursor: "pointer"}}
                >
                  <div className="hud-corner tl"></div>
                  <div className="hud-corner tr"></div>
                  <div className="hud-corner bl"></div>
                  <div className="hud-corner br"></div>

                  <div className="up-status-icon">
                    <div className={`indicator ${is404 ? "red" : (down ? "red" : (isSlow ? "orange" : "green"))}`}></div>
                  </div>
                  
                  <div className="up-monitor-info">
                    <div className="up-url">{target.replace(/^https?:\/\//, '')}</div>
                    <div className={`up-type ${statusClass}`}>{statusLabel}</div>
                  </div>

                  <div className="up-monitor-chart">
                    <Sparkline history={history} width={200} height={40} isDegraded={down} />
                  </div>

                  <div className="up-monitor-latency">
                    <span className={`badge ${latency > 5000 ? "bad" : "good"}`}>
                      {latency.toFixed(0)} ms
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      );
    } else if (activeTab === "incidents") {
      const incidents = data.targets.filter(t => {
           const latency = data.current_latencies[t] || 0;
           return isTargetDown(data.status_messages[t], latency);
      });

      return (
        <div className="up-monitors-list">
          {incidents.length === 0 ? (
            <div className="up-empty-state" style={{borderColor: "var(--status-blue)"}}>
              <p>Great! No incidents detected.</p>
            </div>
          ) : (
            <>
              <div className="up-widget" style={{marginBottom: "20px", borderLeft: "4px solid var(--status-red)"}}>
                <h4 style={{color: "white", marginBottom: "5px"}}>Active Incidents</h4>
                <p style={{fontSize: "0.9rem", color: "var(--text-muted)"}}>
                  {incidents.length} monitor(s) are currently reporting issues.
                </p>
              </div>
              {incidents.map((target) => {
                const status = data.status_messages[target];
                const latency = data.current_latencies[target] || 0;
                const is404 = status && status.includes("NOT FOUND");
                
                return (
                  <div key={target} className={`up-monitor-row down ${is404 ? 'row-404' : ''}`}>
                    <div className="up-status-icon">
                      <div className={`indicator ${is404 ? "red" : "red"}`}></div>
                    </div>
                    <div className="up-monitor-info">
                      <div className="up-url">{target}</div>
                      <div className="up-type" style={{color: is404 ? "var(--status-red)" : "var(--status-red)"}}>
                          {is404 ? "404 Page Not Found" : (latency > 3000 ? `CRITICAL LAG (${latency.toFixed(0)}ms)` : status)}
                      </div>
                    </div>
                    <div className="up-monitor-uptime">
                      <span className="time-ago">Ongoing</span>
                    </div>
                  </div>
                );
              })}
            </>
          )}
        </div>
      );
    } else if (activeTab === "settings") {
      return (
        <div className="up-monitors-list">
          <div className="up-widget">
            <h4>Account Settings</h4>
            <div style={{display: "grid", gap: "15px"}}>
              <div>
                <label style={{display: "block", color: "var(--text-muted)", marginBottom: "5px", fontSize: "0.85rem"}}>API Key</label>
                <input type="text" value="ur123456789" readOnly style={{width: "100%", padding: "10px", background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "white", borderRadius: "4px"}} />
              </div>
              <div>
                <label style={{display: "block", color: "var(--text-muted)", marginBottom: "5px", fontSize: "0.85rem"}}>Timezone</label>
                <select style={{width: "100%", padding: "10px", background: "var(--bg-dark)", border: "1px solid var(--border-color)", color: "white", borderRadius: "4px"}}>
                  <option>UTC</option>
                  <option>GMT+3 (Addis Ababa)</option>
                </select>
              </div>
            </div>
          </div>
          <div className="up-widget">
            <h4>Notifications</h4>
            <div style={{display: "flex", alignItems: "center", gap: "10px", marginBottom: "10px"}}>
               <input type="checkbox" defaultChecked />
               <span>Email Alerts</span>
            </div>
          </div>
        </div>
      );
    }
  };

  const getOverallUptime = () => {
      let totalChecks = 0;
      let upChecks = 0;

      Object.values(data.histories).forEach(history => {
          totalChecks += history.length;
          upChecks += history.filter(h => h > 0).length;
      });

      if (totalChecks === 0) return "N/A";
      return ((upChecks / totalChecks) * 100).toFixed(2) + "%";
  };

  return (
    <div className="up-dashboard">
      <aside className="up-sidebar">
        <div className="up-sidebar-header">
          <h2>ServerPulse</h2>
          <div className={`up-status-badge ${isMonitoring ? "live" : "idle"}`}>
            {isMonitoring ? "● System Active" : "○ System Idle"}
          </div>
        </div>

        <nav className="up-nav">
          <div 
            className={`nav-item ${activeTab === "monitoring" ? "active" : ""}`}
            onClick={() => { setActiveTab("monitoring"); setSelectedMonitor(null); }}
          >
            Monitoring
          </div>
          <div 
            className={`nav-item ${activeTab === "incidents" ? "active" : ""}`}
            onClick={() => setActiveTab("incidents")}
          >
            Incidents
          </div>
          <div 
            className={`nav-item ${activeTab === "settings" ? "active" : ""}`}
            onClick={() => setActiveTab("settings")}
          >
            Settings
          </div>
        </nav>

     <div className="up-add-monitor">
        <label>Add New Monitor</label>
        <div className="up-input-group">
         <input 
            type="text" 
            value={url} 
            onChange={(e) => setUrl(e.target.value)} 
            disabled={isMonitoring || isLoading} 
            placeholder="https://example.com"
            autoComplete="off"
          />
        
        {!isMonitoring ? (
          <>
              {data.targets.length > 0 ? (
                   <button className="up-btn-resume" onClick={handleResume} disabled={isLoading}>Resume Monitoring</button>
              ) : (
                  <button className="up-btn-green" onClick={handleStart} disabled={isLoading || !url}>
                      {isLoading ? "Starting..." : "Start Monitoring"}
                  </button>
              )}
              <button className="up-btn-gray" onClick={handleClear}>Clear</button>
          </>
        ) : (
            <button className="up-btn-red" onClick={handleStop}>Stop</button>
        )}
    </div>
</div>
      </aside>

      <main className="up-main">
        <header className="up-header">
          <div style={{ display: "flex", alignItems: "center", gap: "15px" }}>
              <h3 style={{textTransform: "capitalize", margin: 0}}>{selectedMonitor ? "Monitor Details" : activeTab.replace("_", " ")}</h3>
              {!selectedMonitor && activeTab === "monitoring" && (
                  <span style={{fontSize: "0.8rem", color: "var(--text-muted)"}}>({data.targets.length})</span>
              )}
          </div>
          
          <div className="up-actions">
            {!selectedMonitor && activeTab === "monitoring" && data.targets.length > 0 && (
                <button onClick={handleGlobalMonitoringReport} className="up-btn-blue" style={{marginRight: "10px"}}>
                    📊 Global Report
                </button>
            )}

            {activeTab === "monitoring" && !selectedMonitor && (
              <>
                <input 
                  type="text" 
                  placeholder="Search monitors..." 
                  className="up-search" 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  autoComplete="off"
                />
                <div style={{ position: "relative" }}>
                  <button 
                    className="up-filter-btn" 
                    onClick={() => setShowFilterDropdown(!showFilterDropdown)}
                  >
                    {filterStatus === "all" ? "Filter" : filterStatus} ▼
                  </button>
                  {showFilterDropdown && (
                    <div style={{
                      position: "absolute", top: "100%", right: 0, marginTop: "5px", 
                      background: "var(--bg-panel)", border: "1px solid var(--border-color)", 
                      borderRadius: "6px", width: "120px", boxShadow: "0 4px 12px rgba(0,0,0,0.8)",
                      zIndex: 9999, color: "var(--text-main)"
                    }}>
                      <div onClick={() => { setFilterStatus("all"); setShowFilterDropdown(false); }} style={{padding: "8px 12px", cursor: "pointer", color: filterStatus === "all" ? "var(--status-blue)" : "var(--text-main)", fontSize: "0.9rem"}}>All</div>
                      <div onClick={() => { setFilterStatus("up"); setShowFilterDropdown(false); }} style={{padding: "8px 12px", cursor: "pointer", color: filterStatus === "up" ? "var(--status-blue)" : "var(--text-main)", fontSize: "0.9rem"}}>Up</div>
                      <div onClick={() => { setFilterStatus("down"); setShowFilterDropdown(false); }} style={{padding: "8px 12px", cursor: "pointer", color: filterStatus === "down" ? "var(--status-blue)" : "var(--text-main)", fontSize: "0.9rem"}}>Down</div>
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </header>

        {renderContent()}
      </main>

      {activeTab === "monitoring" && !selectedMonitor && (
        <aside className="up-right-panel">
          <div className="up-widget current-status">
            <h4>Current status</h4>
            <div className="status-grid">
              {(() => {
                  let down = 0;
                  let up = 0;
                  data.targets.forEach(t => {
                      if(isTargetDown(data.status_messages[t], data.current_latencies[t])) down++;
                      else up++;
                  });
                  return (
                      <>
                          <div className="status-item">
                              <span className="label">Down</span>
                              <span className="val red">{down}</span>
                          </div>
                          <div className="status-item">
                              <span className="label">Up</span>
                              <span className="val green">{up}</span>
                          </div>
                          <div className="status-item">
                              <span className="label">Paused</span>
                              <span className="val gray">{0}</span>
                          </div>
                      </>
                  )
              })()}
            </div>
          </div>

          <div className="up-widget last-hours">
            <h4>Last 24 hours</h4>
            <div className="stat-row">
              <span className="lbl">Overall uptime</span>
              <span className="val">{getOverallUptime()}</span>
            </div>
            <div className="stat-row">
              <span className="lbl">Incidents</span>
              <span className="val">{data.targets.filter(t => isTargetDown(data.status_messages[t], data.current_latencies[t])).length}</span>
            </div>
            <div className="stat-row">
              <span className="lbl">Without incid.</span>
              <span className="val">{data.targets.length - data.targets.filter(t => isTargetDown(data.status_messages[t], data.current_latencies[t])).length}</span>
            </div>
            <div className="stat-row">
              <span className="lbl">Affected mon.</span>
              <span className="val">{data.targets.filter(t => isTargetDown(data.status_messages[t], data.current_latencies[t])).length}</span>
            </div>
          </div>
          
          <div className="up-footer-nav">
            <button onClick={onBack} className="back-btn">← Back to Dashboard</button>
          </div>
        </aside>
      )}

      {/* RENDER MODAL */}
      <PasswordModal 
        isOpen={isPwdModalOpen} 
        onClose={() => setIsPwdModalOpen(false)} 
        onSubmit={downloadReportWithPassword}
        title="Secure Monitoring Report"
      />
    </div>
  );
};

// ================= MAIN APP COMPONENT =================
function App() {
  const [showLanding, setShowLanding] = useState(true);
  const [page, setPage] = useState("login");
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    token: "",
  });
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [message, setMessage] = useState("");
  const [userLoggedIn, setUserLoggedIn] = useState(false);
  const [authToken, setAuthToken] = useState(null); 
  const [selectedCard, setSelectedCard] = useState(null);
  
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const profileRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (profileRef.current && !profileRef.current.contains(event.target)) {
        setIsProfileOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    const path = window.location.pathname;
    if (path.startsWith("/reset-password/")) {
      const tokenFromUrl = path.split("/")[2];
      if (tokenFromUrl) {
        setFormData(prev => ({ ...prev, token: tokenFromUrl }));
        setPage("reset");
        setShowLanding(false);
      }
    }
  }, []);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("");
    if (page === "register" || page === "reset") {
      if (formData.password !== confirmPassword) {
        setMessage("Passwords do not match.");
        return;
      }
    }
    let url = "";
    let body = {};
    if (page === "login") {
      url = "http://localhost:8000/login";
      body = { username: formData.username, password: formData.password };
    } else if (page === "register") {
      url = "http://localhost:8000/register";
      body = { username: formData.username, email: formData.email, password: formData.password };
    } else if (page === "forgot") {
      url = "http://localhost:8000/forgot-password";
      body = { email: formData.email };
    } else if (page === "reset") {
      url = "http://localhost:8000/reset-password";
      body = { token: formData.token, new_password: formData.password, username: formData.username };
    }
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.ok) {
        setMessage(data.message);
        if (page === "login") {
          if (data.access_token) {
            setAuthToken(data.access_token);
            localStorage.setItem('auth_token', data.access_token);
          }
          setUserLoggedIn(true);
          setSelectedCard(null);
          setShowLanding(false);
        } else if (page === "register") {
          setTimeout(() => { setPage("login"); setMessage("Registration successful! Please login."); }, 1500);
        } else if (page === "reset") {
          setTimeout(() => { setPage("login"); setMessage("Password reset successful! Please login."); }, 2000);
        }
      } else {
        let errorMessage = "Error occurred";
        if (data.detail) {
          if (Array.isArray(data.detail)) {
            errorMessage = data.detail.map((err) => err.msg).join(", ");
          } else {
            errorMessage = data.detail;
          }
        } else {
          errorMessage = JSON.stringify(data);
        }
        setMessage(errorMessage);
      }
    } catch (err) {
      setMessage("Server not reachable");
    }
  };

  const HomePage = () => {
    if (selectedCard === "monitoring") {
      return <MonitoringComponent onBack={() => setSelectedCard(null)} token={authToken} />;
    }
    if (selectedCard === "domains") {
      return <DomainTrackingComponent onBack={() => setSelectedCard(null)} token={authToken} />;
    }
    return (
      <div className="dashboard">
        <header className="dashboard-header">
          <h1>CyberGuard</h1>
          
          <div className="profile-wrapper" ref={profileRef}>
            <div className="profile-trigger" onClick={() => setIsProfileOpen(!isProfileOpen)}>
                <div className="profile-icon-circle">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                        <circle cx="12" cy="7" r="4"></circle>
                    </svg>
                </div>
                <span className="profile-label">Profile</span>
                <span className="chevron">▼</span>
            </div>

            {isProfileOpen && (
                <div className="profile-dropdown">
                    <div className="profile-header">
                        <div className="avatar-large">
                           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                                <circle cx="12" cy="7" r="4"></circle>
                            </svg>
                        </div>
                        <div className="user-info">
                            <h3>{formData.username || "User"}</h3>
                            <p>{formData.email || formData.username || "user@cyberguard.ai"}</p>
                        </div>
                    </div>
                    <div className="profile-divider"></div>
                    <div className="profile-stats">
                        <div className="stat-item">
                            <span className="stat-label">Status</span>
                            <span className="stat-value text-green">Active</span>
                        </div>
                        <div className="stat-item">
                            <span className="stat-label">Role</span>
                            <span className="stat-value">Admin</span>
                        </div>
                    </div>
                    <div className="profile-divider"></div>
                    <button className="profile-logout-btn" onClick={() => { 
                        setUserLoggedIn(false); 
                        setShowLanding(true);
                        setAuthToken(null);
                        localStorage.removeItem('auth_token');
                        setIsProfileOpen(false);
                    }}>
                        Logout
                    </button>
                </div>
            )}
          </div>
        </header>
        <section className="hero">
          <h2>Security Operations Center</h2>
          <p>Monitor • Detect • Protect • Respond</p>
        </section>
        <section className="cards">
          <div className="card" onClick={() => setSelectedCard("monitoring")}>
            <span className="icon">🌐</span>
            <h3>Website Monitoring</h3>
            <p>Track uptime, response time, and anomalies in real time.</p>
          </div>
          <div className="card" onClick={() => setSelectedCard("domains")}>
            <span className="icon">🔍</span>
            <h3>Domain Tracking</h3>
            <p>Deep DNS inspection, SSL monitoring, and domain reputation.</p>
          </div>
          <div className="card">
            <span className="icon">🛡️</span>
            <h3>Threat Detection</h3>
            <p>Identify vulnerabilities and suspicious activities.</p>
          </div>
          <div className="card">
            <span className="icon">🚨</span>
            <h3>Alert Dashboard</h3>
            <p>Instant alerts for critical security events.</p>
          </div>
        </section>
      </div>
    );
  };

  if (showLanding) return <LandingPage onLogin={() => setShowLanding(false)} />;

  if (userLoggedIn) return <HomePage />;

  return (
    <div className="app-auth">
      <div className="container">
        <h1>CyberGuard</h1>
        <div style={{ marginBottom: "20px", color: "#94a3b8", cursor: "pointer", textDecoration: "underline" }} onClick={() => setShowLanding(true)}>
          &larr; Back to Home
        </div>
        {message && <div className="message">{message}</div>}
        <form onSubmit={handleSubmit} className="form" autoComplete="off">
          {(page === "register" || page === "login") && (
            <input 
              type="text" 
              name="username" 
              placeholder="Username" 
              value={formData.username} 
              onChange={handleChange} 
              required 
              autoComplete="off" 
            />
          )}
          {(page === "register" || page === "forgot") && (
            <input 
              type="email" 
              name="email" 
              placeholder="Email" 
              value={formData.email} 
              onChange={handleChange} 
              required 
              autoComplete="off" 
            />
          )}
          {(page === "login" || page === "register" || page === "reset") && (
            <div className="password-wrapper">
              <input 
                type={showPassword ? "text" : "password"} 
                name="password" 
                placeholder={page === "reset" ? "New Password" : "Password"} 
                value={formData.password} 
                onChange={handleChange} 
                required 
                autoComplete="new-password" 
              />
              <span className="eye-icon" onClick={() => setShowPassword(!showPassword)} role="button" tabIndex="0">{showPassword ? "🔐" : "🔓"}</span>
            </div>
          )}
          {(page === "register" || page === "reset") && (
            <div className="password-wrapper">
              <input 
                type={showPassword ? "text" : "password"} 
                name="confirmPassword" 
                placeholder="Confirm Password" 
                value={confirmPassword} 
                onChange={(e) => setConfirmPassword(e.target.value)} 
                required 
                autoComplete="new-password" 
              />
              <span className="eye-icon" onClick={() => setShowPassword(!showPassword)} role="button" tabIndex="0">{showPassword ? "🔐" : "🔓"}</span>
            </div>
          )}
          {page === "reset" && (
            <>
              <input type="text" name="username" placeholder="Username" value={formData.username} onChange={handleChange} required autoComplete="off" />
              <input type="text" name="token" placeholder="Reset Token (Check Email)" value={formData.token} onChange={handleChange} required autoComplete="off" />
            </>
          )}
          <button type="submit">{page === "login" && "Login"}{page === "register" && "Register"}{page === "forgot" && "Send Reset Email"}{page === "reset" && "Reset Password"}</button>
        </form>
        <div className="links">
          {page !== "login" && <p onClick={() => { setPage("login"); setMessage(""); setConfirmPassword(""); }}>Login</p>}
          {page !== "register" && <p onClick={() => { setPage("register"); setMessage(""); setConfirmPassword(""); }}>Register</p>}
          {page !== "forgot" && <p onClick={() => { setPage("forgot"); setMessage(""); setConfirmPassword(""); }}>Forgot Password</p>}
          {page !== "reset" && page === "forgot" && <p onClick={() => { setPage("reset"); setMessage(""); setConfirmPassword(""); }}>Reset Password</p>}
        </div>
      </div>
    </div>
  );
}

export default App;