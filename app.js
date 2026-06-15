document.addEventListener('DOMContentLoaded', () => {
  let activeAuditData = null;
  let targetDomainStr = "target";
  
  const execButton = document.getElementById('btn-execute');
  const targetInput = document.querySelector('.target-input');
  
  const errorBanner = document.getElementById('error-banner');
  const loadingState = document.getElementById('loading-state');
  const dashboardGrid = document.getElementById('dashboard-grid');

  // DOM Elements - Executive Summary
  const statDomain = document.getElementById('stat-domain');
  const statIp = document.getElementById('stat-ip');
  const statDuration = document.getElementById('stat-duration');
  const statTimestamp = document.getElementById('stat-timestamp');
  const progressScore = document.querySelector('.progress-score');
  const progressGrade = document.querySelector('.progress-grade');
  const progressValueCircle = document.querySelector('.progress-value');
  
  // DOM Elements - SSL
  const sslCard = document.getElementById('card-ssl');
  const sslDot = document.getElementById('ssl-dot');
  const sslBadge = document.getElementById('ssl-badge');
  const sslItem = document.getElementById('ssl-item');
  const sslText = document.getElementById('ssl-text');
  const sslStatusBadge = document.getElementById('ssl-status-badge');
  
  // DOM Elements - Paths
  const pathsCard = document.getElementById('card-paths');
  const pathsDot = document.getElementById('paths-dot');
  const pathsBadge = document.getElementById('paths-badge');
  const pathsItem = document.getElementById('paths-item');
  const pathsText = document.getElementById('paths-text');
  const pathsStatusBadge = document.getElementById('paths-status-badge');
  
  // DOM Elements - Headers
  const headersContainer = document.getElementById('headers-container');
  const headersCountBadge = document.getElementById('headers-count-badge');

  const animateProgress = (targetScore) => {
    let currentScore = 0;
    const duration = 1000;
    const intervalTime = 20;
    const steps = duration / intervalTime;
    const increment = targetScore / steps;

    const timer = setInterval(() => {
      currentScore += increment;
      if (currentScore >= targetScore) {
        currentScore = targetScore;
        clearInterval(timer);
      }
      progressScore.textContent = Math.round(currentScore);
    }, intervalTime);
    
    setTimeout(() => {
      progressValueCircle.style.strokeDashoffset = `calc(283 - (283 * ${targetScore}) / 100)`;
      
      // Color logic
      let colorVar = 'var(--rose-500)';
      if (targetScore >= 90) colorVar = 'var(--emerald-500)';
      else if (targetScore >= 75) colorVar = 'var(--blue-500)';
      else if (targetScore >= 60) colorVar = 'var(--amber-500)';
      
      progressValueCircle.style.stroke = colorVar;
      progressGrade.style.color = colorVar;
    }, 100);
  };

  const setupAccordionListeners = () => {
    const accordions = document.querySelectorAll('.accordion-header');
    accordions.forEach(header => {
      header.addEventListener('click', () => {
        const content = header.nextElementSibling;
        const icon = header.querySelector('svg');
        if (content.classList.contains('open')) {
          content.classList.remove('open');
          icon.style.transform = 'rotate(0deg)';
        } else {
          content.classList.add('open');
          icon.style.transform = 'rotate(180deg)';
        }
      });
    });
  };

  if (execButton && targetInput) {
    execButton.addEventListener('click', async () => {
      let url = targetInput.value.trim();
      if (!url) return;
      
      // Auto-prepend https://
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
        targetInput.value = url;
      }
      
      targetDomainStr = new URL(url).hostname;

      // UI Reset State
      errorBanner.classList.add('hidden');
      dashboardGrid.classList.add('hidden');
      loadingState.style.display = 'flex';
      execButton.disabled = true;
      execButton.style.opacity = '0.7';

      const startTime = performance.now();

      try {
        const response = await fetch('http://127.0.0.1:8001/api/v1/compliance', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target_url: url })
        });
        
        if (!response.ok) throw new Error("Non-200 Response");
        
        const data = await response.json();
        const endTime = performance.now();
        const durationSec = ((endTime - startTime) / 1000).toFixed(3);
        
        // Full object construction for export
        activeAuditData = {
          target_metadata: {
            url: url,
            domain: targetDomainStr,
            resolved_ip: "N/A", // Backend doesn't resolve IP currently
            timestamp: new Date().toISOString(),
            scan_duration_seconds: parseFloat(durationSec)
          },
          compliance_metrics: {
            score: data.compliance_score.score,
            grade: data.compliance_score.grade,
          },
          raw_response: data
        };

        // Render Executive Summary
        statDomain.textContent = targetDomainStr;
        statIp.textContent = "N/A";
        statDuration.textContent = `${durationSec}s`;
        statTimestamp.textContent = new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
        
        progressGrade.textContent = `Grade: ${data.compliance_score.grade}`;
        animateProgress(data.compliance_score.score);

        // Render SSL Status
        if (data.ssl && data.ssl.valid) {
          sslDot.className = 'status-dot dot-pass animate-pulse-glow';
          sslBadge.className = 'badge badge-pass';
          sslBadge.textContent = 'Valid';
          sslItem.style.borderLeft = '3px solid var(--emerald-500)';
          sslText.textContent = `Certificate valid for ${data.ssl.days_remaining} more days.`;
          sslStatusBadge.className = 'badge badge-pass';
          sslStatusBadge.textContent = 'Secure';
        } else {
          sslDot.className = 'status-dot dot-fail animate-pulse-glow';
          sslBadge.className = 'badge badge-fail';
          sslBadge.textContent = 'Invalid / Error';
          sslItem.style.borderLeft = '3px solid var(--rose-500)';
          sslText.textContent = data.ssl.error || 'SSL validation failed.';
          sslStatusBadge.className = 'badge badge-fail';
          sslStatusBadge.textContent = 'Critical';
        }

        // Render Paths Check
        if (data.paths) {
          const isOk = data.paths.present || data.paths.status_code === 200;
          pathsText.textContent = `HTTP Status: ${data.paths.status_code}`;
          
          if (isOk) {
            pathsDot.className = 'status-dot dot-warn';
            pathsBadge.className = 'badge badge-warn';
            pathsBadge.textContent = 'Exposed';
            pathsItem.style.borderLeft = '3px solid var(--amber-500)';
            pathsStatusBadge.className = 'badge badge-warn';
            pathsStatusBadge.textContent = 'Public';
          } else {
            pathsDot.className = 'status-dot dot-pass';
            pathsBadge.className = 'badge badge-pass';
            pathsBadge.textContent = 'Secure';
            pathsItem.style.borderLeft = '3px solid var(--emerald-500)';
            pathsStatusBadge.className = 'badge badge-pass';
            pathsStatusBadge.textContent = 'Protected / 404';
          }
        }

        // Render Headers
        headersContainer.innerHTML = '';
        const headers = data.headers.headers;
        let missingCount = 0;
        
        for (const [headerName, headerData] of Object.entries(headers)) {
          if (headerData.present) {
            headersContainer.innerHTML += `
              <div class="data-item" style="border-left: 3px solid var(--emerald-500);">
                <div>
                  <div style="font-weight: 500;">${headerName}</div>
                  <div class="text-sm text-muted">Configured correctly.</div>
                </div>
                <span class="badge badge-pass">Present</span>
              </div>
            `;
          } else {
            missingCount++;
            headersContainer.innerHTML += `
              <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-left: 3px solid var(--rose-500); border-radius: var(--radius-md); padding: var(--space-3) var(--space-4); margin-bottom: var(--space-3);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                  <div>
                    <div style="font-weight: 500;">${headerName}</div>
                    <div class="text-sm text-rose">Missing security header</div>
                  </div>
                  <span class="badge badge-fail">Fail</span>
                </div>
                
                <div class="accordion">
                  <div class="accordion-header">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="transition: transform 0.3s;">
                      <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                    View Remediation Directive
                  </div>
                  <div class="accordion-content">
                    <div class="text-sm text-muted mb-2">Apply this Nginx directive to your server block:</div>
                    <div class="code-block">
${headerData.mitigation}
                    </div>
                  </div>
                </div>
              </div>
            `;
          }
        }
        
        headersCountBadge.textContent = missingCount === 0 ? "All Secure" : `${missingCount} Issues`;
        headersCountBadge.className = missingCount === 0 ? "badge badge-pass" : "badge badge-fail";

        setupAccordionListeners();

        // Switch UI back
        loadingState.style.display = 'none';
        dashboardGrid.classList.remove('hidden');

      } catch (error) {
        console.error("Scan Failed:", error);
        loadingState.style.display = 'none';
        errorBanner.classList.remove('hidden');
      } finally {
        execButton.disabled = false;
        execButton.style.opacity = '1';
      }
    });
  }

  // Download Report Logic
  const downloadBtn = document.getElementById('btn-download');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', () => {
      if (!activeAuditData) {
        alert("Please execute the audit suite first to generate a report.");
        return;
      }
      
      const jsonString = JSON.stringify(activeAuditData, null, 2);
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(jsonString);
      
      const downloadAnchorNode = document.createElement('a');
      downloadAnchorNode.setAttribute("href", dataStr);
      downloadAnchorNode.setAttribute("download", `Compliance_Report_${targetDomainStr.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.json`);
      document.body.appendChild(downloadAnchorNode);
      downloadAnchorNode.click();
      downloadAnchorNode.remove();
    });
  }
});
