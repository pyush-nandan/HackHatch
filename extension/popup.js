// Global error boundary - catch unhandled errors
window.addEventListener('error', (event) => {
  console.error('Global error caught:', event.error);
  showError('An unexpected error occurred. Please reload the extension.');
  event.preventDefault();
});

// Catch unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
  showError('Failed to load security data. Please try again.');
  event.preventDefault();
});

document.addEventListener('DOMContentLoaded', async () => {
  try {
    // Get current tab to ensure we show correct data
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (!tabs || tabs.length === 0) {
        showError('No active tab found');
        return;
      }
      
      const currentTab = tabs[0];
      const currentUrl = currentTab.url;
      
      // Send message with current tab info
      chrome.runtime.sendMessage({ 
        action: 'getScanData',
        currentUrl: currentUrl,
        tabId: currentTab.id
      }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('Message error:', chrome.runtime.lastError);
          showError('Failed to connect to extension background');
          return;
        }
        
        if (response && !response.error) {
          updateUI(response);
        } else {
          showError(response?.error || 'Failed to load data');
        }
      });
    });
  } catch (error) {
    console.error('Popup initialization error:', error);
    showError('Extension initialization failed');
  }
});

function showError(message) {
  const loading = document.getElementById('loading');
  if (loading) {
    loading.innerHTML = `
      <div class="error-state">
        <p style="color: #ef4444;">⚠️ ${escapeHtml(message)}</p>
        <button onclick="location.reload()" style="margin-top: 12px; padding: 8px 16px; background: #38bdf8; color: #020617; border: none; border-radius: 6px; cursor: pointer;">
          Retry
        </button>
      </div>
    `;
  }
}

// Security: Escape HTML to prevent XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function updateUI(data) {
  if (!data || typeof data !== 'object') {
    showError('Invalid data received');
    return;
  }
  
  const { score, extensionRisks, siteScan } = data;
  
  const loading = document.getElementById('loading');
  const content = document.getElementById('content');
  
  if (loading) loading.style.display = 'none';
  if (content) content.style.display = 'block';
  
  updateSecurityScore(score || 0);
  updateSiteInfo(siteScan || {});
  updateExtensions(extensionRisks || []);
}

function updateSecurityScore(score) {
  // Validate score
  score = typeof score === 'number' ? Math.max(0, Math.min(100, score)) : 0;
  
  const scoreValue = document.getElementById('scoreValue');
  const scoreLabel = document.getElementById('scoreLabel');
  const scoreCircle = document.getElementById('scoreCircle');
  const scoreBar = document.getElementById('scoreBar');
  
  if (!scoreValue || !scoreLabel || !scoreCircle || !scoreBar) {
    console.error('Required DOM elements not found');
    return;
  }
  
  scoreValue.textContent = Math.round(score);
  
  if (score >= 70) {
    scoreLabel.textContent = 'Safe';
    scoreLabel.style.color = '#22c55e';
  } else if (score >= 40) {
    scoreLabel.textContent = 'Moderate';
    scoreLabel.style.color = '#facc15';
  } else {
    scoreLabel.textContent = 'High Risk';
    scoreLabel.style.color = '#ef4444';
  }
  
  const circumference = 339.292;
  const offset = circumference - (score / 100) * circumference;
  scoreCircle.style.strokeDashoffset = offset;
  
  if (score >= 70) {
    scoreCircle.style.stroke = '#22c55e';
  } else if (score >= 40) {
    scoreCircle.style.stroke = '#facc15';
  } else {
    scoreCircle.style.stroke = '#ef4444';
  }
  
  scoreBar.style.width = score + '%';
}

function updateSiteInfo(siteScan) {
  const siteDomain = document.getElementById('siteDomain');
  const siteUrl = document.getElementById('siteUrl');
  const protocolBadge = document.getElementById('protocolBadge');
  const thirdPartyCount = document.getElementById('thirdPartyCount');
  const trackerCount = document.getElementById('trackerCount');
  const siteWarnings = document.getElementById('siteWarnings');
  
  if (!siteScan || !siteScan.domain) {
    if (siteDomain) siteDomain.textContent = 'No active site';
    if (siteUrl) siteUrl.textContent = 'Navigate to a website';
    if (protocolBadge) protocolBadge.textContent = '--';
    if (thirdPartyCount) thirdPartyCount.textContent = '0';
    if (trackerCount) trackerCount.textContent = '0';
    return;
  }
  
  // Security: Escape user-controlled content
  if (siteDomain) siteDomain.textContent = siteScan.domain;
  if (siteUrl) siteUrl.textContent = siteScan.url || '';
  
  // Display website safety rating (Malwarebytes/WOT/McAfee style)
  if (siteScan.websiteSafety) {
    const safety = siteScan.websiteSafety;
    const safetyBadge = document.createElement('div');
    safetyBadge.style.cssText = 'margin-top: 10px; padding: 10px; border-radius: 8px; font-weight: bold;';
    
    if (safety.safetyRating === 'SAFE') {
      safetyBadge.style.background = 'linear-gradient(135deg, #22c55e, #16a34a)';
      safetyBadge.style.color = 'white';
      safetyBadge.innerHTML = `✅ SAFE WEBSITE (Score: ${safety.safetyScore}/100)`;
    } else if (safety.safetyRating === 'SUSPICIOUS') {
      safetyBadge.style.background = 'linear-gradient(135deg, #f59e0b, #d97706)';
      safetyBadge.style.color = 'white';
      safetyBadge.innerHTML = `⚠️ SUSPICIOUS (Score: ${safety.safetyScore}/100)`;
    } else if (safety.safetyRating === 'UNSAFE') {
      safetyBadge.style.background = 'linear-gradient(135deg, #ef4444, #dc2626)';
      safetyBadge.style.color = 'white';
      safetyBadge.innerHTML = `🚨 UNSAFE WEBSITE (Score: ${safety.safetyScore}/100)`;
    }
    
    if (siteDomain && siteDomain.parentElement) {
      siteDomain.parentElement.insertBefore(safetyBadge, siteDomain.nextSibling);
    }
  }
  
  if (protocolBadge) {
    if (siteScan.protocol === 'https') {
      protocolBadge.textContent = 'HTTPS';
      protocolBadge.className = 'badge https';
    } else {
      protocolBadge.textContent = 'HTTP';
      protocolBadge.className = 'badge http';
    }
  }
  
  if (thirdPartyCount) thirdPartyCount.textContent = siteScan.thirdPartyCount || 0;
  
  // Fix: Use privacy impact total if available, otherwise use trackerCount
  if (trackerCount) {
    const totalTrackers = (siteScan.privacyImpact && siteScan.privacyImpact.totalTrackers) 
      ? siteScan.privacyImpact.totalTrackers 
      : (siteScan.trackerCount || 0);
    trackerCount.textContent = totalTrackers;
  }
  
  if (siteWarnings) {
    siteWarnings.innerHTML = '';
    const warnings = [];
    
    // Display privacy impact (Ghostery/Privacy Badger style)
    if (siteScan.privacyImpact) {
      const privacy = siteScan.privacyImpact;
      
      // Privacy Score Badge
      const privacyBadge = document.createElement('div');
      privacyBadge.style.cssText = `
        margin: 10px 0;
        padding: 12px;
        border-radius: 8px;
        background: linear-gradient(135deg, #8b5cf6, #6366f1);
        color: white;
        font-weight: bold;
      `;
      const scoreText = document.createTextNode(`${parseInt(privacy.privacyScore)}/100`);
      const scoreSpan = document.createElement('span');
      scoreSpan.style.fontSize = '18px';
      scoreSpan.appendChild(scoreText);
      
      const labelSpan = document.createElement('span');
      labelSpan.textContent = '🔒 Privacy Score';
      
      const container = document.createElement('div');
      container.style.cssText = 'display: flex; justify-content: space-between; align-items: center;';
      container.appendChild(labelSpan);
      container.appendChild(scoreSpan);
      
      privacyBadge.appendChild(container);
      siteWarnings.appendChild(privacyBadge);
      
      // Tracker Breakdown
      if (privacy.totalTrackers > 0) {
        const trackerBreakdown = document.createElement('div');
        trackerBreakdown.style.cssText = 'margin: 10px 0; padding: 10px; background: #f3f4f6; border-radius: 6px;';
        
        const header = document.createElement('strong');
        header.style.cssText = 'display: block; margin-bottom: 8px;';
        header.textContent = `📊 ${parseInt(privacy.totalTrackers)} Trackers Detected`;
        trackerBreakdown.appendChild(header);
        
        const categoryDiv = document.createElement('div');
        categoryDiv.style.cssText = 'font-size: 12px; color: #374151;';
        
        // Show category breakdown (sanitized)
        Object.entries(privacy.categoryCounts).forEach(([category, count]) => {
          if (count > 0 && typeof count === 'number') {
            const icon = {
              'Analytics': '📈',
              'Advertising': '🎯',
              'Social Tracking': '👁️',
              'Data Broker': '💰',
              'Marketing': '📧',
              'CDN/Security': '🛡️'
            }[category] || '📌';
            
            const catDiv = document.createElement('div');
            catDiv.style.cssText = 'margin: 4px 0;';
            catDiv.textContent = `${icon} ${category}: ${parseInt(count)}`;
            categoryDiv.appendChild(catDiv);
          }
        });
        
        trackerBreakdown.appendChild(categoryDiv);
        
        // Show what data is collected (sanitized)
        if (privacy.dataCollected && Array.isArray(privacy.dataCollected) && privacy.dataCollected.length > 0) {
          const dataDiv = document.createElement('div');
          dataDiv.style.cssText = 'margin-top: 10px; padding-top: 10px; border-top: 1px solid #d1d5db;';
          
          const dataHeader = document.createElement('strong');
          dataHeader.style.cssText = 'display: block; margin-bottom: 4px; font-size: 11px; color: #6b7280;';
          dataHeader.textContent = 'Data Being Collected:';
          dataDiv.appendChild(dataHeader);
          
          const dataList = document.createElement('div');
          dataList.style.cssText = 'font-size: 11px; color: #ef4444;';
          privacy.dataCollected.slice(0, 5).forEach(d => {
            const item = document.createElement('div');
            item.textContent = `• ${String(d).substring(0, 100)}`; // Sanitize and limit length
            dataList.appendChild(item);
          });
          dataDiv.appendChild(dataList);
          trackerBreakdown.appendChild(dataDiv);
        }
        siteWarnings.appendChild(trackerBreakdown);
        
        // Show detailed tracker info
        if (siteScan.trackerDetails && siteScan.trackerDetails.length > 0) {
          const detailsDiv = document.createElement('details');
          detailsDiv.style.cssText = 'margin: 10px 0; padding: 10px; background: #fef3c7; border-radius: 6px;';
          
          const summary = document.createElement('summary');
          summary.style.cssText = 'cursor: pointer; font-weight: bold; margin-bottom: 8px;';
          summary.textContent = `🔍 View Tracker Details (${parseInt(siteScan.trackerDetails.length)})`;
          detailsDiv.appendChild(summary);
          
          siteScan.trackerDetails.slice(0, 8).forEach(tracker => {
            // Validate tracker data
            if (!tracker || typeof tracker !== 'object') return;
            
            const allowedRisks = ['HIGH', 'MEDIUM', 'LOW'];
            const risk = allowedRisks.includes(tracker.risk) ? tracker.risk : 'MEDIUM';
            
            const riskColor = {
              'HIGH': '#ef4444',
              'MEDIUM': '#f59e0b',
              'LOW': '#10b981'
            }[risk];
            
            const trackerCard = document.createElement('div');
            trackerCard.style.cssText = `margin: 8px 0; padding: 8px; background: white; border-radius: 4px; border-left: 3px solid ${riskColor};`;
            
            const nameDiv = document.createElement('div');
            nameDiv.style.cssText = 'font-weight: bold; font-size: 12px; color: #111827;';
            nameDiv.textContent = String(tracker.name || 'Unknown').substring(0, 50);
            trackerCard.appendChild(nameDiv);
            
            const metaDiv = document.createElement('div');
            metaDiv.style.cssText = 'font-size: 11px; color: #6b7280; margin: 2px 0;';
            
            const riskBadge = document.createElement('span');
            riskBadge.style.cssText = `background: ${riskColor}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px;`;
            riskBadge.textContent = `${risk} RISK`;
            metaDiv.appendChild(riskBadge);
            
            const categorySpan = document.createElement('span');
            categorySpan.style.marginLeft = '6px';
            categorySpan.textContent = String(tracker.category || 'Other').substring(0, 30);
            metaDiv.appendChild(categorySpan);
            trackerCard.appendChild(metaDiv);
            
            const purposeDiv = document.createElement('div');
            purposeDiv.style.cssText = 'font-size: 11px; color: #374151; margin-top: 4px;';
            const purposeLabel = document.createElement('strong');
            purposeLabel.textContent = 'Purpose: ';
            purposeDiv.appendChild(purposeLabel);
            purposeDiv.appendChild(document.createTextNode(String(tracker.purpose || 'Unknown').substring(0, 150)));
            trackerCard.appendChild(purposeDiv);
            
            detailsDiv.appendChild(trackerCard);
          });
          siteWarnings.appendChild(detailsDiv);
        }
      }
      
      // Privacy recommendations
      if (privacy.recommendations.length > 0) {
        privacy.recommendations.forEach(rec => {
          warnings.push(rec);
        });
      }
    }
    
    // Add website safety threats (Malwarebytes style)
    if (siteScan.websiteSafety && siteScan.websiteSafety.threats.length > 0) {
      siteScan.websiteSafety.threats.forEach(threat => {
        const severityIcon = {
          'CRITICAL': '🚨',
          'HIGH': '⚠️',
          'MEDIUM': '⚡',
          'LOW': 'ℹ️'
        }[threat.severity] || '⚠️';
        
        warnings.push(`${severityIcon} ${threat.description}`);
      });
    }
    
    if (siteScan.protocol !== 'https') {
      warnings.push('⚠️ Unencrypted connection (HTTP)');
    }
    if (siteScan.mixedContent) {
      warnings.push('⚠️ Mixed content detected');
    }
    if (siteScan.trackerCount > 5) {
      warnings.push(`⚠️ High tracker count (${siteScan.trackerCount})`);
    }
    
    warnings.forEach(warning => {
      const div = document.createElement('div');
      div.className = 'warning';
      div.textContent = warning; // textContent prevents XSS
      siteWarnings.appendChild(div);
    });
  }
}

function updateExtensions(extensionRisks) {
  // Validate input
  if (!Array.isArray(extensionRisks)) {
    console.error('Invalid extensionRisks data');
    extensionRisks = [];
  }
  
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let disabledCount = 0;
  
  extensionRisks.forEach(ext => {
    if (!ext || typeof ext !== 'object') return;
    
    if (!ext.enabled) {
      disabledCount++;
    } else if (ext.riskLevel === 'CRITICAL') {
      criticalCount++;
    } else if (ext.riskLevel === 'HIGH') {
      highCount++;
    } else if (ext.riskLevel === 'MEDIUM') {
      mediumCount++;
    } else {
      lowCount++;
    }
  });
  
  const highCountEl = document.getElementById('highCount');
  const mediumCountEl = document.getElementById('mediumCount');
  const lowCountEl = document.getElementById('lowCount');
  const disabledCountEl = document.getElementById('disabledCount');
  
  // Show critical count in high count element (combine threats)
  if (highCountEl) highCountEl.textContent = criticalCount + highCount;
  if (mediumCountEl) mediumCountEl.textContent = mediumCount;
  if (lowCountEl) lowCountEl.textContent = lowCount;
  if (disabledCountEl) disabledCountEl.textContent = disabledCount;
  
  const extensionsList = document.getElementById('extensionsList');
  if (!extensionsList) return;
  
  extensionsList.innerHTML = '';
  
  if (extensionRisks.length === 0) {
    const emptyMsg = document.createElement('p');
    emptyMsg.style.cssText = 'color: #9ca3af; text-align: center; padding: 20px;';
    emptyMsg.textContent = 'No extensions installed';
    extensionsList.appendChild(emptyMsg);
    return;
  }
  
  const sorted = [...extensionRisks].sort((a, b) => {
    if (!a.enabled && b.enabled) return 1;
    if (a.enabled && !b.enabled) return -1;
    
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (order[a.riskLevel] || 4) - (order[b.riskLevel] || 4);
  });
  
  sorted.forEach(ext => {
    if (!ext || !ext.name) return;
    
    const item = document.createElement('div');
    item.className = 'ext-item' + (ext.enabled ? '' : ' disabled');
    item.style.cursor = 'pointer';
    
    // Create elements safely to prevent XSS
    const info = document.createElement('div');
    info.className = 'ext-info';
    
    const name = document.createElement('div');
    name.className = 'ext-name';
    name.textContent = ext.name;
    
    const version = document.createElement('div');
    version.className = 'ext-version';
    version.textContent = `v${ext.version || '0.0.0'} • Score: ${ext.riskScore || 0}${ext.enabled ? '' : ' (Disabled)'}`;
    
    info.appendChild(name);
    info.appendChild(version);
    
    const risk = document.createElement('div');
    risk.className = `ext-risk ${(ext.riskLevel || 'LOW').toLowerCase()}`;
    risk.textContent = ext.riskLevel || 'UNKNOWN';
    
    item.appendChild(info);
    item.appendChild(risk);
    
    // Add click handler to show detailed threats
    item.addEventListener('click', () => {
      showExtensionDetails(ext);
    });
    
    extensionsList.appendChild(item);
  });
}

// Show detailed threat analysis for an extension with FLAGS (Traceability)
function showExtensionDetails(ext) {
  const modal = document.createElement('div');
  modal.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0,0,0,0.95);
    z-index: 1000;
    overflow-y: auto;
    padding: 20px;
  `;
  
  const content = document.createElement('div');
  content.style.cssText = `
    background: #1e293b;
    border-radius: 12px;
    padding: 24px;
    max-width: 600px;
    margin: 0 auto;
    border: 2px solid #38bdf8;
  `;
  
  // Header
  const title = document.createElement('h3');
  title.style.cssText = 'color: #38bdf8; margin: 0 0 8px 0; font-size: 18px;';
  title.textContent = ext.name;
  
  const version = document.createElement('div');
  version.style.cssText = 'color: #64748b; font-size: 12px; margin-bottom: 16px;';
  version.textContent = `Version ${ext.version} • Extension ID: ${ext.id.substring(0, 16)}...`;
  
  // Risk Badge
  const riskBadge = document.createElement('div');
  riskBadge.style.cssText = `
    display: inline-block;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: bold;
    margin-bottom: 20px;
    background: ${ext.riskLevel === 'CRITICAL' ? '#dc2626' : ext.riskLevel === 'HIGH' ? '#ef4444' : ext.riskLevel === 'MEDIUM' ? '#f59e0b' : '#22c55e'};
    color: white;
    font-size: 14px;
  `;
  riskBadge.textContent = `${ext.riskLevel} RISK - Score: ${ext.riskScore}/100`;
  
  // ===== NEW: RISK FLAGS (The "WHY") =====
  const flagsSection = document.createElement('div');
  flagsSection.style.cssText = 'margin: 20px 0;';
  
  if (ext.flags && ext.flags.length > 0) {
    const flagsHeader = document.createElement('h4');
    flagsHeader.style.cssText = 'color: #ef4444; font-size: 14px; margin-bottom: 12px; font-weight: bold;';
    flagsHeader.innerHTML = '🚩 RISK FLAGS - WHY THIS SCORE IS HIGH';
    flagsSection.appendChild(flagsHeader);
    
    ext.flags.forEach((flag, index) => {
      const flagCard = document.createElement('div');
      flagCard.style.cssText = `
        background: #0f172a;
        border: 2px solid ${flag.severity === 'CRITICAL' ? '#dc2626' : flag.severity === 'HIGH' ? '#ef4444' : '#f59e0b'};
        border-radius: 8px;
        padding: 12px;
        margin: 10px 0;
      `;
      
      // Flag ID and Title
      const flagHeader = document.createElement('div');
      flagHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;';
      
      const flagTitle = document.createElement('div');
      flagTitle.style.cssText = 'font-weight: bold; color: #f8fafc; font-size: 13px;';
      flagTitle.textContent = `${flag.id}: ${flag.title}`;
      
      const flagSeverity = document.createElement('span');
      flagSeverity.style.cssText = `
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 10px;
        font-weight: bold;
        background: ${flag.severity === 'CRITICAL' ? '#dc2626' : flag.severity === 'HIGH' ? '#ef4444' : '#f59e0b'};
        color: white;
      `;
      flagSeverity.textContent = flag.severity;
      
      flagHeader.appendChild(flagTitle);
      flagHeader.appendChild(flagSeverity);
      
      // Flag Reason (The KEY info)
      const flagReason = document.createElement('div');
      flagReason.style.cssText = 'color: #fbbf24; font-size: 12px; margin: 6px 0; font-weight: 500;';
      flagReason.innerHTML = `<strong>Reason:</strong> ${flag.reason}`;
      
      // Policy Violation
      const flagPolicy = document.createElement('div');
      flagPolicy.style.cssText = 'color: #94a3b8; font-size: 11px; margin: 4px 0;';
      flagPolicy.innerHTML = `<strong>Policy:</strong> ${flag.policy_violation}`;
      
      // Permissions Involved
      if (flag.permissions && flag.permissions.length > 0) {
        const flagPerms = document.createElement('div');
        flagPerms.style.cssText = 'color: #cbd5e1; font-size: 11px; margin: 4px 0;';
        flagPerms.innerHTML = `<strong>Permissions:</strong> <code style="background: #334155; padding: 2px 6px; border-radius: 3px;">${flag.permissions.join(', ')}</code>`;
        flagCard.appendChild(flagPerms);
      }
      
      // Host Permissions
      if (flag.host_permissions && flag.host_permissions.length > 0) {
        const flagHosts = document.createElement('div');
        flagHosts.style.cssText = 'color: #cbd5e1; font-size: 11px; margin: 4px 0;';
        flagHosts.innerHTML = `<strong>Host Access:</strong> <code style="background: #334155; padding: 2px 6px; border-radius: 3px;">${flag.host_permissions.slice(0, 3).join(', ')}${flag.host_permissions.length > 3 ? '...' : ''}</code>`;
        flagCard.appendChild(flagHosts);
      }
      
      // Remediation
      if (flag.remediation) {
        const flagRemediation = document.createElement('div');
        flagRemediation.style.cssText = 'color: #22c55e; font-size: 11px; margin-top: 8px; padding-top: 8px; border-top: 1px solid #334155;';
        flagRemediation.innerHTML = `<strong>✓ Remediation:</strong> ${flag.remediation}`;
        flagCard.appendChild(flagRemediation);
      }
      
      flagCard.appendChild(flagHeader);
      flagCard.appendChild(flagReason);
      flagCard.appendChild(flagPolicy);
      
      flagsSection.appendChild(flagCard);
    });
  }
  
  // Threats List (existing)
  const threatsList = document.createElement('div');
  threatsList.style.cssText = 'margin: 16px 0;';
  
  if (ext.threats && ext.threats.length > 0) {
    const threatsTitle = document.createElement('h4');
    threatsTitle.style.cssText = 'color: #f59e0b; font-size: 14px; margin-bottom: 8px;';
    threatsTitle.textContent = '⚠️ Detailed Security Threats:';
    threatsList.appendChild(threatsTitle);
    
    ext.threats.slice(0, 5).forEach(threat => {
      const threatItem = document.createElement('div');
      threatItem.style.cssText = `
        background: #0f172a;
        padding: 8px 12px;
        margin: 6px 0;
        border-radius: 6px;
        font-size: 11px;
        color: #cbd5e1;
        border-left: 3px solid #ef4444;
      `;
      
      // Handle both string and object threats
      if (typeof threat === 'string') {
        threatItem.textContent = threat;
      } else if (typeof threat === 'object' && threat !== null) {
        // Extract meaningful info from threat object
        const threatText = threat.description || threat.threat || threat.message || JSON.stringify(threat);
        threatItem.textContent = String(threatText).substring(0, 200);
      } else {
        threatItem.textContent = 'Unknown threat detected';
      }
      
      threatsList.appendChild(threatItem);
    });
    
    if (ext.threats.length > 5) {
      const moreThreats = document.createElement('div');
      moreThreats.style.cssText = 'color: #64748b; font-size: 11px; margin-top: 8px;';
      moreThreats.textContent = `+ ${ext.threats.length - 5} more threats detected`;
      threatsList.appendChild(moreThreats);
    }
  }
  
  // Close Button
  const closeBtn = document.createElement('button');
  closeBtn.textContent = 'Close';
  closeBtn.style.cssText = `
    margin-top: 20px;
    padding: 10px 20px;
    background: #38bdf8;
    color: #020617;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-weight: bold;
    width: 100%;
    font-size: 14px;
  `;
  closeBtn.onclick = () => document.body.removeChild(modal);
  
  content.appendChild(title);
  content.appendChild(version);
  content.appendChild(riskBadge);
  content.appendChild(flagsSection); // NEW: Risk flags
  content.appendChild(threatsList);
  content.appendChild(closeBtn);
  modal.appendChild(content);
  document.body.appendChild(modal);
}
