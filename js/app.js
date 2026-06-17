const SECURITY_EXPLANATIONS = {
  // Headers
  "Content-Security-Policy": "Prevents XSS attacks by restricting allowed origins for executable scripts.",
  "Strict-Transport-Security": "Forces encrypted HTTPS connections to prevent protocol downgrade attacks.",
  "X-Frame-Options": "Prevents the site from being rendered inside an iframe to stop clickjacking.",
  "X-Content-Type-Options": "Disables MIME-type sniffing to prevent unexpected script execution.",
  
  // Sanitization
  "database_sanitization": "Audits entry parameters to prevent unauthorized SQL commands from manipulating backend storage matrices.",
  "parameter_validation": "Evaluates endpoint input arguments to ensure payload encoding blocks reflected script execution vectors.",
  
  // Session Armor
  "HttpOnly Flag": "Mitigates session hijacking by blocking JavaScript access to security cookies.",
  "Secure Flag": "Restricting session cookie transmission exclusively over encrypted HTTPS connections.",
  "SameSite Attribute": "Controls cross-site cookie behavior to protect the session against Cross-Site Request Forgery (CSRF) riding attacks.",
  
  // Malware & Cross-Origin
  "Access-Control-Allow-Origin": "Verifies that cross-origin sharing isn't wide open to unauthorized third-party domains.",
  "Malicious External Scripts": "Scans all referenced CDN and third-party script paths against known malware distribution blacklists.",
  "21": "FTP: Plaintext file transfer protocol.",
  "22": "SSH: Encrypted remote administrative access.",
  "80": "HTTP: Unencrypted web traffic.",
  "443": "HTTPS: Secure encrypted web traffic.",
  "8080": "Alt-HTTP: Common alternative web administration port.",
  
  // Exposed Resources
  "/.git/": "Source control repository exposing internal application logic.",
  "/.env": "Environment file exposing raw production secrets and tokens.",
  "/robots.txt": "Public indexing file directing search engine crawlers."
};

document.addEventListener("DOMContentLoaded", async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const target = urlParams.get('target');
  if (target) {
    document.getElementById('target-input').value = target;
    startScan();
  }
  loadHistory();
});

async function startScan() {
  const target = document.getElementById("target-input").value;
  if (!target) return;

  const overlay = document.getElementById("loading-overlay");
  const logFeed = document.getElementById("log-feed");
  const content = document.getElementById("dashboard-content");
  
  overlay.style.display = "flex";
  content.style.display = "none";
  logFeed.innerHTML = "";
  
  const logs = [
    "[➔] Initializing core pipeline security handshake matrices...",
    "[➔] Resolving target infrastructure network IP profiles...",
    "[➔] Testing transport layer redirection integrity models...",
    "[➔] Auditing passive configuration HTTP header parameters...",
    "[➔] Executing Deep Subsystem Telemetry..."
  ];
  
  let logIndex = 0;
  let charIndex = 0;
  let currentLineDiv = null;
  
  const typeWriter = () => {
    if (logIndex >= logs.length) return;
    if (charIndex === 0) {
        currentLineDiv = document.createElement("div");
        logFeed.appendChild(currentLineDiv);
    }
    currentLineDiv.innerHTML += logs[logIndex].charAt(charIndex);
    logFeed.scrollTop = logFeed.scrollHeight;
    charIndex++;
    if (charIndex >= logs[logIndex].length) {
        charIndex = 0;
        logIndex++;
        setTimeout(typeWriter, 400);
    } else {
        setTimeout(typeWriter, 15);
    }
  };
  
  typeWriter();

  try {
    const res = await fetch("http://127.0.0.1:8002/api/v1/compliance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target })
    });
    
    if (!res.ok) {
      const data = await res.json();
      alert(`Pipeline Interrupted: ${data.detail || "Server Error"}`);
      overlay.style.display = "none";
      return;
    }

    const data = await res.json();
    overlay.style.display = "none";
    content.style.display = "block";
    renderDashboard(data);
    loadHistory();
    
  } catch (error) {
    alert("Execution Pipeline Interrupted: Failed to fetch. Ensure backend is live.");
    overlay.style.display = "none";
  }
}

let lastScanData = null;

function renderDashboard(data) {
  lastScanData = data;
  const isPro = true; // Temporary override for testing: window.currentUser && window.currentUser.is_pro === 1;

  const username = window.currentUser ? window.currentUser.username : "Guest User";
  const roleName = isPro ? "Professional Auditor" : "Compliance Basics (Free)";
  const sessionTextEl = document.getElementById('active-session-text');
  if(sessionTextEl) sessionTextEl.innerText = `Active Session: ${username} / Profile: ${roleName}`;

  document.getElementById('meta-domain').innerText = data.target;
  document.getElementById('meta-ip').innerText = `[${data.resolved_ip}]`;
  document.getElementById('meta-duration').innerText = `[${data.execution_duration_seconds}s]`;
  document.getElementById('meta-time').innerText = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  const score = data.compliance_score.score;
  document.getElementById('gauge-score').innerHTML = `${score}<span>/100</span>`;
  document.getElementById('gauge-grade').innerText = data.compliance_score.grade;
  
  let color = 'var(--brand-rose)';
  if(score >= 90) color = 'var(--brand-emerald)';
  else if(score >= 70) color = 'var(--brand-amber)';
  
  const turns = (score / 100) * 0.5;
  setTimeout(() => {
      document.getElementById('gauge-fill').style.transform = `rotate(${turns}turn)`;
      document.getElementById('gauge-fill').style.backgroundColor = color;
  }, 50);
  document.getElementById('gauge-grade').style.color = color;

  // Session Management Armor
  let sessionHtml = '';
  for(const [key, val] of Object.entries(data.session_cookies.checks)) {
      const exp = SECURITY_EXPLANATIONS[key] || "";
      sessionHtml += `<div class="data-row" style="flex-direction:column; align-items:flex-start;">
        <div style="display:flex; justify-content:space-between; width:100%;">
          <span class="data-label">${key}</span>
          <span class="badge badge-${val.status}">${val.status}</span>
        </div>
        <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">${exp}</div>
      </div>`;
  }
  applyTierTriage('session-content', 'session-card', 'session-lock', sessionHtml, isPro);

  // Malware & Cross-Origin Security
  let malwareHtml = '';
  for(const [key, val] of Object.entries(data.cross_origin_security.checks)) {
      const exp = SECURITY_EXPLANATIONS[key] || "";
      malwareHtml += `<div class="data-row" style="flex-direction:column; align-items:flex-start;">
        <div style="display:flex; justify-content:space-between; width:100%;">
          <span class="data-label">${key}</span>
          <span class="badge badge-${val.status}">${val.status}</span>
        </div>
        <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">${exp}</div>
      </div>`;
  }
  applyTierTriage('malware-content', 'malware-card', 'malware-lock', malwareHtml, isPro);

  // Network Ports
  let portsHtml = '';
  data.port_metrics.forEach(p => {
    if (!isPro && p.port !== 80 && p.port !== 443) return;
    const exp = SECURITY_EXPLANATIONS[p.port.toString()] || "";
    portsHtml += `<div class="data-row" style="flex-direction:column; align-items:flex-start;">
      <div style="display:flex; justify-content:space-between; width:100%;">
        <span class="data-label" style="${p.status==='OPEN' ? 'color:var(--brand-amber);' : ''}">${p.port}</span>
        <span class="badge badge-${p.status}">${p.status}</span>
      </div>
      <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">${exp}</div>
    </div>`;
  });
  if (!isPro) {
      portsHtml += `<div class="pro-lock-overlay" style="position:relative; height:60px; border-radius:6px; margin-top:0.5rem;"><span style="font-size:0.85rem; border: 1px solid rgba(16, 185, 129, 0.4); background: rgba(15,23,42,0.9);"><svg style="color:var(--brand-emerald);" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> <strong style="color:var(--brand-emerald);">Full Perimeter Map Locked.</strong> <a href="pricing.html" style="color:white; margin-left:4px;">Upgrade to Pro</a></span></div>`;
  }
  document.getElementById('port-map-content').innerHTML = portsHtml;

  // Sanitization
  let sanHtml = '';
  for(const [key, val] of Object.entries(data.input_validation)) {
      const exp = SECURITY_EXPLANATIONS[key] || "";
      sanHtml += `<div class="data-row" style="flex-direction:column; align-items:flex-start;">
        <div style="display:flex; justify-content:space-between; width:100%;">
          <span class="data-label">${key}</span>
          <span class="badge badge-${val.status}">${val.status}</span>
        </div>
        <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">${exp}</div>
      </div>`;
  }
  
  if (isPro) {
      document.getElementById('sanitization-content').innerHTML = sanHtml;
      document.getElementById('sanitization-content').style.filter = "none";
      const lock = document.getElementById('sanitization-lock');
      if(lock) lock.style.display = "none";
  } else {
      document.getElementById('sanitization-content').innerHTML = sanHtml;
      document.getElementById('sanitization-content').style.filter = "blur(5px)";
      let lock = document.getElementById('sanitization-lock');
      if(!lock) {
          document.getElementById('sanitization-card').innerHTML += `
          <div class="pro-lock-overlay" id="sanitization-lock">
            <span style="border-image: linear-gradient(to right, var(--brand-emerald), var(--brand-blue)) 1; background: rgba(15, 23, 42, 0.95); padding: 1.5rem; flex-direction: column; align-items: center; gap: 0.5rem; text-align: center; border-width: 2px;">
              <svg style="color: var(--brand-emerald);" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
              <strong style="color: transparent; background-clip: text; -webkit-background-clip: text; background-image: linear-gradient(90deg, var(--brand-emerald), var(--brand-blue)); font-size: 1.1rem; letter-spacing: 0.5px;">Premium Security Feature</strong>
              <div style="font-size: 0.85rem; color: var(--text-muted); max-width: 250px;">Unlock detailed active vulnerability reports and remediation rules.</div>
              <a href="pricing.html" class="btn btn-emerald" style="margin-top: 0.5rem; font-size: 0.8rem; padding: 0.25rem 0.75rem;">Upgrade to Pro</a>
            </span>
          </div>`;
      } else {
          lock.style.display = "flex";
      }
  }

  // Exposed Resources
  let expHtml = '';
  data.exposed_directories.forEach(d => {
    const exp = SECURITY_EXPLANATIONS[d.path] || "";
    expHtml += `<div style="margin-bottom:1rem;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
        <div>${d.path}</div>
        ${(isPro || d.status !== 'EXPOSED') ? `<span class="badge badge-${d.status}">${d.status}</span>` : ''}
      </div>
      <div style="font-size:0.75rem; color:var(--text-muted); margin-bottom:0.25rem;">${exp}</div>`;
      
    if(!isPro && d.status === 'EXPOSED') {
        expHtml += `<div class="pro-lock-overlay" style="position:relative; height:60px; border-radius:6px; margin-top:0.5rem;">
            <span style="font-size:0.85rem; border: 1px solid rgba(16, 185, 129, 0.4); background: rgba(15,23,42,0.9);"><svg style="color:var(--brand-emerald);" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> <strong style="color:var(--brand-emerald); font-weight:500;">Premium Feature.</strong> <a href="pricing.html" style="color:white; margin-left:4px;">Upgrade to Pro</a></span>
        </div></div>`;
    } else {
        expHtml += `<div style="font-size:0.8rem; color:var(--text-muted); margin-top:0.25rem;">${d.details}</div></div>`;
    }
  });
  document.getElementById('exposed-resources-content').innerHTML = expHtml;

  // Headers
  let headersHtml = '';
  for(const [key, val] of Object.entries(data.headers.headers)) {
    const status = val.present ? "PASS" : "MISSING";
    const exp = SECURITY_EXPLANATIONS[key] || "";
    headersHtml += `<div class="data-row" style="flex-direction:column; align-items:stretch;">
      <div style="display:flex; justify-content:space-between; width:100%;">
        <span class="data-label">${key}</span>
        <span class="badge badge-${status === 'PASS' ? 'PASS' : 'FAIL'}">${status}</span>
      </div>
      <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem; margin-bottom:0.5rem;">${exp}</div>`;
        if(!val.present) {
            if(isPro) {
                headersHtml += `<details open><summary><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px; vertical-align:text-bottom;"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg> View Architecture Hardening Blueprint</summary><pre class="blueprint">${val.mitigation}</pre></details>`;
            }
        }  headersHtml += `</div>`;
  }
  document.getElementById('headers-content').innerHTML = headersHtml;
}

function applyTierTriage(contentId, cardId, lockId, htmlContent, isPro) {
  const contentEl = document.getElementById(contentId);
  const cardEl = document.getElementById(cardId);
  if(!contentEl || !cardEl) return;
  
  contentEl.innerHTML = htmlContent;
  
  if (isPro) {
      contentEl.style.filter = "none";
      const lock = document.getElementById(lockId);
      if(lock) lock.style.display = "none";
  } else {
      contentEl.style.filter = "blur(5px)";
      let lock = document.getElementById(lockId);
      if(!lock) {
          cardEl.innerHTML += `
          <div class="pro-lock-overlay" id="${lockId}">
            <span style="border-image: linear-gradient(to right, var(--brand-emerald), var(--brand-blue)) 1; background: rgba(15, 23, 42, 0.95); padding: 1.5rem; flex-direction: column; align-items: center; gap: 0.5rem; text-align: center; border-width: 2px;">
              <svg style="color: var(--brand-emerald);" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
              <strong style="color: transparent; background-clip: text; -webkit-background-clip: text; background-image: linear-gradient(90deg, var(--brand-emerald), var(--brand-blue)); font-size: 1.1rem; letter-spacing: 0.5px;">Premium Security Feature</strong>
              <div style="font-size: 0.85rem; color: var(--text-muted); max-width: 250px;">Upgrade to Pro to view active vulnerability metrics.</div>
              <a href="pricing.html" class="btn btn-emerald" style="margin-top: 0.5rem; font-size: 0.8rem; padding: 0.25rem 0.75rem;">Upgrade to Pro</a>
            </span>
          </div>`;
      } else {
          lock.style.display = "flex";
      }
  }
}

async function loadHistory() {
  try {
    const res = await fetch("http://127.0.0.1:8002/api/v1/history");
    if(res.ok) {
      const data = await res.json();
      let html = '';
      data.forEach(row => {
         const dt = new Date(row.timestamp).toISOString().replace('T', ' ').substring(0, 19);
         html += `<tr>
           <td>${dt} UTC</td>
           <td>${row.target_domain}</td>
           <td>${row.compliance_score}</td>
           <td><span class="badge badge-${row.performance_grade}">${row.performance_grade}</span></td>
         </tr>`;
      });
      document.getElementById('history-table-body').innerHTML = html;
    }
  } catch (e) { console.error(e); }
}

function exportJSON(e) {
  e.preventDefault();
  const isPro = true; // window.currentUser && window.currentUser.is_pro === 1;
  if(!isPro) return alert("Raw JSON Export is a Premium feature.");
  if(!lastScanData) return alert("No scan data to export.");
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(lastScanData, null, 2));
  const el = document.createElement('a');
  el.setAttribute("href", dataStr);
  el.setAttribute("download", `scan_${lastScanData.target}.json`);
  document.body.appendChild(el);
  el.click();
  el.remove();
}

async function exportPNG(e) {
  e.preventDefault();
  const isPro = true; // window.currentUser && window.currentUser.is_pro === 1;
  if(!isPro) return alert("PNG Snapshot Export is a Premium feature.");
  if(!lastScanData) return alert("No scan data to export.");
  const content = document.getElementById('dashboard-content');
  try {
    const canvas = await html2canvas(content, { backgroundColor: '#0f172a' });
    const imgData = canvas.toDataURL("image/png");
    const el = document.createElement('a');
    el.setAttribute("href", imgData);
    el.setAttribute("download", `dashboard_${lastScanData.target}.png`);
    document.body.appendChild(el);
    el.click();
    el.remove();
  } catch (err) { console.error(err); alert("Failed to generate PNG"); }
}

async function exportPDF(e) {
  e.preventDefault();
  if(!lastScanData) return alert("No scan data to export.");
  
  const isPro = true; // window.currentUser && window.currentUser.is_pro === 1;
  const container = document.createElement('div');
  container.style.position = 'absolute';
  container.style.left = '-9999px';
  container.style.top = '0';
  container.style.width = '800px';
  container.style.backgroundColor = '#ffffff';
  container.style.color = '#1e293b'; 
  container.style.padding = '40px';
  container.style.fontFamily = 'Arial, sans-serif';
  
  const username = window.currentUser ? window.currentUser.username : "Guest User";
  const dt = new Date().toLocaleString();
  
  let gradeColor = '#ef4444';
  if (lastScanData.compliance_score.score >= 90) gradeColor = '#10b981';
  else if (lastScanData.compliance_score.score >= 70) gradeColor = '#f59e0b';
  
  let html = `
    <h1 style="color:#0f172a; border-bottom:2px solid #e2e8f0; padding-bottom:10px; margin-bottom:20px;">Sentinel DAST Security Report</h1>
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:30px;">
      <div style="font-size:14px;">
        <p style="margin:5px 0;"><strong>Generated By:</strong> ${username}</p>
        <p style="margin:5px 0;"><strong>Date / Time:</strong> ${dt}</p>
        <p style="margin:5px 0;"><strong>Tier:</strong> ${isPro ? "Professional Auditor" : "Compliance Basics (Free)"}</p>
      </div>
      <div style="text-align:right;">
        <div style="font-size:12px; color:#64748b; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">Overall Grade</div>
        <div style="font-size:48px; font-weight:800; line-height:1; color:${gradeColor};">${lastScanData.compliance_score.grade}</div>
      </div>
    </div>
    
    <h2 style="color:#0f172a; margin-top:30px;">Target Assessment</h2>
    <table style="width:100%; border-collapse:collapse; margin-bottom:30px; font-size:14px;">
      <tr><td style="padding:8px; border-bottom:1px solid #e2e8f0;"><strong>Target Domain:</strong></td><td style="padding:8px; border-bottom:1px solid #e2e8f0;">${lastScanData.target}</td></tr>
      <tr><td style="padding:8px; border-bottom:1px solid #e2e8f0;"><strong>Resolved IP:</strong></td><td style="padding:8px; border-bottom:1px solid #e2e8f0;">${lastScanData.resolved_ip}</td></tr>
      <tr><td style="padding:8px; border-bottom:1px solid #e2e8f0;"><strong>Compliance Score:</strong></td><td style="padding:8px; border-bottom:1px solid #e2e8f0;">${lastScanData.compliance_score.score}/100</td></tr>
      <tr><td style="padding:8px; border-bottom:1px solid #e2e8f0;"><strong>Execution Duration:</strong></td><td style="padding:8px; border-bottom:1px solid #e2e8f0;">${lastScanData.execution_duration_seconds}s</td></tr>
    </table>
    
    <h3 style="color:#0f172a; border-bottom:1px solid #e2e8f0; padding-bottom:5px;">HTTP Compliance Headers</h3>
    <ul style="font-size:14px; margin-bottom:30px;">
  `;
  for(const [key, val] of Object.entries(lastScanData.headers.headers)) {
     const exp = SECURITY_EXPLANATIONS[key] || "";
     html += `<li style="margin-bottom:8px;"><strong>${key}</strong>: ${val.present ? 'Present' : '<span style="color:#ef4444;">Missing</span>'}<br/><span style="color:#64748b; font-size:12px;">${exp}</span></li>`;
  }
  html += `</ul>`;

  // Always include Robots.txt and Transport Check since those are part of free logic, but here we will just bundle them into Exposed Directories logic or basic if present
  
  if (isPro) {
      html += `
        <h3 style="color:#0f172a; border-bottom:1px solid #e2e8f0; padding-bottom:5px;">Session Management Armor</h3>
        <ul style="font-size:14px; margin-bottom:30px;">
      `;
      for(const [key, val] of Object.entries(lastScanData.session_cookies.checks)) {
         const exp = SECURITY_EXPLANATIONS[key] || "";
         html += `<li style="margin-bottom:8px;">${key} - <strong>${val.status}</strong><br/><span style="color:#64748b; font-size:12px;">${exp}</span></li>`;
      }
      html += `</ul>

        <h3 style="color:#0f172a; border-bottom:1px solid #e2e8f0; padding-bottom:5px;">Malware & Cross-Origin Security</h3>
        <ul style="font-size:14px; margin-bottom:30px;">
      `;
      for(const [key, val] of Object.entries(lastScanData.cross_origin_security.checks)) {
         const exp = SECURITY_EXPLANATIONS[key] || "";
         html += `<li style="margin-bottom:8px;">${key} - <strong>${val.status}</strong><br/><span style="color:#64748b; font-size:12px;">${exp}</span></li>`;
      }
      html += `</ul>
        
        <h3 style="color:#0f172a; border-bottom:1px solid #e2e8f0; padding-bottom:5px;">Network Port Map</h3>
        <ul style="font-size:14px; margin-bottom:30px;">
      `;
      lastScanData.port_metrics.forEach(p => {
         const exp = SECURITY_EXPLANATIONS[p.port.toString()] || "";
         html += `<li style="margin-bottom:8px;">Port ${p.port} - <strong>${p.status}</strong><br/><span style="color:#64748b; font-size:12px;">${exp}</span></li>`;
      });
      html += `</ul>
        
        <h3 style="color:#0f172a; border-bottom:1px solid #e2e8f0; padding-bottom:5px;">Database & Input Sanitization</h3>
        <ul style="font-size:14px; margin-bottom:30px;">
      `;
      for(const [key, val] of Object.entries(lastScanData.input_validation)) {
         const exp = SECURITY_EXPLANATIONS[key] || "";
         html += `<li style="margin-bottom:8px;">${key} - <strong>${val.status}</strong><br/><span style="color:#64748b; font-size:12px;">${exp}</span></li>`;
      }
      html += `</ul>
      
        <h3 style="color:#0f172a; border-bottom:1px solid #e2e8f0; padding-bottom:5px;">Exposed Resource Inventory</h3>
        <ul style="font-size:14px; margin-bottom:30px;">
      `;
      lastScanData.exposed_directories.forEach(d => {
         const exp = SECURITY_EXPLANATIONS[d.path] || "";
         html += `<li style="margin-bottom:8px;"><strong>${d.path}</strong> (${d.status})<br/><span style="color:#64748b; font-size:12px;">${exp}</span><br/><span style="color:#0f172a; font-size:12px;">${d.details}</span></li>`;
      });
      html += `</ul>`;
  } else {
      // Free User Output for locked advanced features
      html += `<div style="background-color:#f1f5f9; border:1px dashed #cbd5e1; border-radius:8px; padding:20px; text-align:center; color:#475569; font-size:14px; margin-top:30px;">
        <strong style="display:block; margin-bottom:5px; color:#0f172a;">[<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px; vertical-align:text-bottom;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> Perimeter Map & Dynamic Vulnerability Assesment Unlocked on Pro Plan]</strong>
        Advanced technical telemetry including Port Maps, SQLi Matrices, Hidden Repositories, and Cross-Origin Diagnostics have been omitted from this report.
      </div>`;
  }
  
  container.innerHTML = html;
  document.body.appendChild(container);
  
  try {
    const canvas = await html2canvas(container, { backgroundColor: '#ffffff', scale: 2 });
    const imgData = canvas.toDataURL("image/jpeg", 1.0);
    const { jsPDF } = window.jspdf;
    
    const pdf = new jsPDF('p', 'pt', [canvas.width / 2, canvas.height / 2]); 
    pdf.addImage(imgData, 'JPEG', 0, 0, canvas.width / 2, canvas.height / 2);
    pdf.save(`report_${lastScanData.target}.pdf`);
  } catch (err) { 
    console.error(err); 
    alert("Failed to generate PDF"); 
  } finally {
    container.remove();
  }
}
