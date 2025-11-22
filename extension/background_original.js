// Web Security Guardian - Background Service Worker
// Security: Use environment variable or configuration for API URL in production
const API_BASE_URL = 'http://localhost:5000/api';

// Generate persistent employee ID
let EMPLOYEE_ID = null;

// Initialize employee ID from storage or create new one
async function initEmployeeId() {
  try {
    const result = await chrome.storage.local.get(['employeeId']);
    if (result.employeeId) {
      EMPLOYEE_ID = result.employeeId;
    } else {
      EMPLOYEE_ID = 'EMP-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
      await chrome.storage.local.set({ employeeId: EMPLOYEE_ID });
    }
  } catch (error) {
    console.error('Failed to initialize employee ID:', error);
    EMPLOYEE_ID = 'EMP-FALLBACK-' + Math.floor(Math.random() * 1000);
  }
}

// Advanced Security Threat Detection System
// Based on OWASP, CVE databases, and Chrome Extension Security Best Practices
const SECURITY_INDICATORS = {
  // Critical: Can steal data, modify pages, track everything
  CRITICAL_PERMISSIONS: {
    'webRequest': { score: 25, reason: 'Can intercept & modify ALL network traffic' },
    'webRequestBlocking': { score: 25, reason: 'Can block/alter ANY HTTP request' },
    'proxy': { score: 30, reason: 'Can redirect ALL traffic through attacker server' },
    'debugger': { score: 30, reason: 'Can inject code into ANY page' },
    'management': { score: 20, reason: 'Can disable security extensions' },
    'browsingData': { score: 20, reason: 'Can access passwords & browsing history' },
    'cookies': { score: 18, reason: 'Can steal session tokens & login credentials' },
    'declarativeNetRequestWithHostAccess': { score: 22, reason: 'Can modify network requests with host access' }
  },
  
  // High: Sensitive data access
  HIGH_RISK_PERMISSIONS: {
    'history': { score: 15, reason: 'Full browsing history access' },
    'tabs': { score: 12, reason: 'Can see all URLs you visit' },
    'clipboardRead': { score: 15, reason: 'Can steal copied passwords/data' },
    'clipboardWrite': { score: 10, reason: 'Can inject malicious clipboard content' },
    'downloads': { score: 12, reason: 'Can download malware silently' },
    'geolocation': { score: 15, reason: 'Physical location tracking' },
    'nativeMessaging': { score: 18, reason: 'Can execute native applications' }
  },
  
  // Medium: Annoying or privacy concerns
  MEDIUM_RISK_PERMISSIONS: {
    'notifications': { score: 5, reason: 'Can spam notifications' },
    'bookmarks': { score: 7, reason: 'Can access saved bookmarks' },
    'contextMenus': { score: 5, reason: 'Adds context menu entries' },
    'idle': { score: 6, reason: 'Tracks user activity patterns' },
    'topSites': { score: 8, reason: 'Knows your most visited sites' }
  },
  
  // Host permission red flags
  HOST_PATTERNS: {
    ALL_URLS: { score: 35, reason: 'Access to EVERY website (huge attack surface)' },
    BANKING: { score: 25, reason: 'Can steal banking credentials' },
    EMAIL: { score: 25, reason: 'Can read emails & steal accounts' },
    SOCIAL_MEDIA: { score: 20, reason: 'Can hijack social accounts' },
    SHOPPING: { score: 22, reason: 'Can steal payment info' },
    CORPORATE: { score: 20, reason: 'Can access company data' },
    GOVERNMENT: { score: 25, reason: 'Can access sensitive gov data' },
    WILDCARD: { score: 15, reason: 'Too broad domain access' }
  },
  
  // Suspicious patterns (malware indicators)
  SUSPICIOUS_PATTERNS: {
    OBFUSCATED_NAME: { score: 15, reason: 'Suspicious random name (possible malware)' },
    NO_DESCRIPTION: { score: 8, reason: 'No description (unprofessional/suspicious)' },
    EXCESSIVE_PERMISSIONS: { score: 20, reason: 'Requests far more permissions than needed' },
    NEW_EXTENSION: { score: 5, reason: 'Recently installed (monitor behavior)' },
    UNKNOWN_PUBLISHER: { score: 10, reason: 'Unknown/unverified developer' }
  }
};

// Sensitive domain patterns for enhanced detection
const SENSITIVE_DOMAINS = {
  BANKING: ['bank', 'chase', 'wellsfargo', 'bofa', 'citi', 'paypal', 'venmo', 'stripe', 'square'],
  EMAIL: ['mail', 'gmail', 'outlook', 'yahoo', 'proton', 'icloud'],
  SOCIAL: ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'reddit'],
  SHOPPING: ['amazon', 'ebay', 'shop', 'store', 'checkout', 'cart'],
  CORPORATE: ['corp', 'company', 'enterprise', 'intranet', 'internal', 'office'],
  GOVERNMENT: ['.gov', 'irs', 'federal', 'state']
};

async function scanExtensions() {
  try {
    const extensions = await chrome.management.getAll();
    const extensionRisks = extensions
      .filter(ext => ext.type === 'extension' && ext.id !== chrome.runtime.id)
      .map(ext => calculateExtensionRisk(ext));
    
    await chrome.storage.local.set({ extensionRisks });
    
    const highRisk = extensionRisks.filter(ext => ext.riskLevel === 'HIGH');
    if (highRisk.length > 0) {
      await reportToBackend(highRisk);
    }
    
    return extensionRisks;
  } catch (error) {
    console.error('Extension scan error:', error);
    return [];
  }
}

function calculateExtensionRisk(extension) {
  let riskScore = 0;
  const threats = []; // Track specific threats found
  const permissions = extension.permissions || [];
  const hostPermissions = extension.hostPermissions || [];
  
  // ====== PHASE 1: Critical Permission Analysis ======
  permissions.forEach(perm => {
    // Check critical permissions
    if (SECURITY_INDICATORS.CRITICAL_PERMISSIONS[perm]) {
      const threat = SECURITY_INDICATORS.CRITICAL_PERMISSIONS[perm];
      riskScore += threat.score;
      threats.push(`🔴 CRITICAL: ${perm} - ${threat.reason}`);
    }
    // Check high-risk permissions
    else if (SECURITY_INDICATORS.HIGH_RISK_PERMISSIONS[perm]) {
      const threat = SECURITY_INDICATORS.HIGH_RISK_PERMISSIONS[perm];
      riskScore += threat.score;
      threats.push(`🟠 HIGH: ${perm} - ${threat.reason}`);
    }
    // Check medium-risk permissions
    else if (SECURITY_INDICATORS.MEDIUM_RISK_PERMISSIONS[perm]) {
      const threat = SECURITY_INDICATORS.MEDIUM_RISK_PERMISSIONS[perm];
      riskScore += threat.score;
      threats.push(`🟡 MEDIUM: ${perm} - ${threat.reason}`);
    }
  });
  
  // ====== PHASE 2: Host Permission Analysis (Most Critical) ======
  let hasAllUrls = false;
  let sensitiveDomainAccess = [];
  
  hostPermissions.forEach(host => {
    const hostLower = host.toLowerCase();
    
    // Check for ALL URLs access (major red flag)
    if (hostLower.includes('<all_urls>') || host === '*://*/*') {
      hasAllUrls = true;
      riskScore += SECURITY_INDICATORS.HOST_PATTERNS.ALL_URLS.score;
      threats.push(`🔴 CRITICAL: ${SECURITY_INDICATORS.HOST_PATTERNS.ALL_URLS.reason}`);
    }
    
    // Check for wildcards (overly broad)
    if (host.startsWith('*://') || host.includes('*.')) {
      riskScore += SECURITY_INDICATORS.HOST_PATTERNS.WILDCARD.score;
      threats.push(`🟠 Wildcard host: ${host} - ${SECURITY_INDICATORS.HOST_PATTERNS.WILDCARD.reason}`);
    }
    
    // Check for sensitive domains
    Object.keys(SENSITIVE_DOMAINS).forEach(category => {
      SENSITIVE_DOMAINS[category].forEach(keyword => {
        if (hostLower.includes(keyword)) {
          sensitiveDomainAccess.push(category);
          const indicator = SECURITY_INDICATORS.HOST_PATTERNS[category];
          if (indicator) {
            riskScore += indicator.score;
            threats.push(`🔴 ${category}: ${host} - ${indicator.reason}`);
          }
        }
      });
    });
  });
  
  // ====== PHASE 3: Suspicious Pattern Detection ======
  
  // Check for obfuscated/random name (malware indicator)
  const namePattern = /^[a-z]{8,}$/i; // Random lowercase letters
  if (namePattern.test(extension.name) || extension.name.length < 3) {
    riskScore += SECURITY_INDICATORS.SUSPICIOUS_PATTERNS.OBFUSCATED_NAME.score;
    threats.push(`⚠️ ${SECURITY_INDICATORS.SUSPICIOUS_PATTERNS.OBFUSCATED_NAME.reason}`);
  }
  
  // Check for missing description
  if (!extension.description || extension.description.length < 10) {
    riskScore += SECURITY_INDICATORS.SUSPICIOUS_PATTERNS.NO_DESCRIPTION.score;
    threats.push(`⚠️ ${SECURITY_INDICATORS.SUSPICIOUS_PATTERNS.NO_DESCRIPTION.reason}`);
  }
  
  // Check for excessive permissions (wants more than 5 critical/high permissions)
  const criticalCount = permissions.filter(p => 
    SECURITY_INDICATORS.CRITICAL_PERMISSIONS[p] || SECURITY_INDICATORS.HIGH_RISK_PERMISSIONS[p]
  ).length;
  
  if (criticalCount >= 5) {
    riskScore += SECURITY_INDICATORS.SUSPICIOUS_PATTERNS.EXCESSIVE_PERMISSIONS.score;
    threats.push(`⚠️ ${SECURITY_INDICATORS.SUSPICIOUS_PATTERNS.EXCESSIVE_PERMISSIONS.reason} (${criticalCount} dangerous permissions)`);
  }
  
  // Check if recently installed (within 7 days)
  if (extension.installType === 'development' || extension.installType === 'admin') {
    // Developer mode extensions get extra scrutiny
    riskScore += 10;
    threats.push(`⚠️ Developer mode extension (unreviewed by Chrome Web Store)`);
  }
  
  // ====== PHASE 4: Combination Attack Detection ======
  
  // Dangerous combination: webRequest + cookies + all URLs = credential theft
  if (permissions.includes('webRequest') && permissions.includes('cookies') && hasAllUrls) {
    riskScore += 25;
    threats.push(`🔴 CRITICAL COMBO: Can intercept & steal login credentials from ALL sites`);
  }
  
  // Dangerous combination: tabs + history = complete tracking profile
  if (permissions.includes('tabs') && permissions.includes('history')) {
    riskScore += 15;
    threats.push(`🟠 PRIVACY RISK: Complete browsing surveillance capability`);
  }
  
  // Dangerous combination: proxy + webRequest = MITM attack
  if (permissions.includes('proxy') && permissions.includes('webRequest')) {
    riskScore += 30;
    threats.push(`🔴 CRITICAL COMBO: Man-in-the-middle attack capability`);
  }
  
  // ====== PHASE 5: Risk Level Determination ======
  
  let riskLevel = 'LOW';
  if (riskScore >= 60) {
    riskLevel = 'CRITICAL';
  } else if (riskScore >= 40) {
    riskLevel = 'HIGH';
  } else if (riskScore >= 20) {
    riskLevel = 'MEDIUM';
  }
  
  // ====== PHASE 6: Generate Risk Flags (Traceability) ======
  const flags = [];
  
  // Flag 1: Permission overreach detected
  if (criticalCount >= 3) {
    flags.push({
      id: 'P-1',
      severity: 'CRITICAL',
      title: 'Permission Overreach Detected',
      reason: `Requests ${criticalCount} dangerous permissions simultaneously`,
      permissions: permissions.filter(p => 
        SECURITY_INDICATORS.CRITICAL_PERMISSIONS[p] || SECURITY_INDICATORS.HIGH_RISK_PERMISSIONS[p]
      ),
      policy_violation: 'Policy P-1: Principle of Least Privilege',
      remediation: 'Review if extension truly needs all these permissions'
    });
  }
  
  // Flag 2: Universal site access (all_urls)
  if (hasAllUrls) {
    flags.push({
      id: 'P-2',
      severity: 'CRITICAL',
      title: 'Universal Site Access Violation',
      reason: 'Extension can access EVERY website you visit',
      permissions: ['<all_urls>'],
      policy_violation: 'Policy P-2: Scope Minimization Required',
      attack_surface: 'Entire browsing history + credentials',
      remediation: 'Restrict to specific domains only'
    });
  }
  
  // Flag 3: Session hijacking capability
  if (permissions.includes('cookies') && (permissions.includes('webRequest') || hasAllUrls)) {
    flags.push({
      id: 'P-3',
      severity: 'CRITICAL',
      title: 'Session Hijacking Capability',
      reason: 'Can steal authentication cookies + intercept login requests',
      permissions: ['cookies', permissions.includes('webRequest') ? 'webRequest' : '<all_urls>'],
      policy_violation: 'Policy P-3: Authentication Security',
      mitre_attack: 'T1539 - Steal Web Session Cookie',
      remediation: 'Disable extension or restrict cookie access'
    });
  }
  
  // Flag 4: Financial data access
  if (sensitiveDomainAccess.includes('BANKING') || sensitiveDomainAccess.includes('SHOPPING')) {
    flags.push({
      id: 'P-4',
      severity: 'HIGH',
      title: 'Financial Data Access Detected',
      reason: 'Extension accesses banking/payment sites',
      host_permissions: hostPermissions.filter(h => 
        /bank|paypal|stripe|shop|checkout/i.test(h)
      ),
      policy_violation: 'Policy P-4: PCI-DSS Data Protection',
      compliance_risk: 'PCI-DSS Level 1',
      remediation: 'Verify extension legitimacy + vendor security audit'
    });
  }
  
  // Flag 5: Management API abuse risk
  if (permissions.includes('management')) {
    flags.push({
      id: 'P-5',
      severity: 'HIGH',
      title: 'Extension Management Control',
      reason: 'Can disable security extensions or install malware',
      permissions: ['management'],
      policy_violation: 'Policy P-5: Security Tool Protection',
      attack_scenario: 'Disable antivirus extensions, enable attacker extensions',
      remediation: 'Only allow trusted system tools'
    });
  }
  
  // Flag 6: Developer mode (unverified)
  if (extension.installType === 'development' || extension.installType === 'admin') {
    flags.push({
      id: 'P-6',
      severity: 'MEDIUM',
      title: 'Unverified Extension Source',
      reason: 'Loaded from local files, not Chrome Web Store',
      policy_violation: 'Policy P-6: Approved Software Only',
      security_gap: 'Bypasses Chrome security review process',
      remediation: 'Require Chrome Web Store installations only'
    });
  }
  
  return {
    name: extension.name,
    id: extension.id,
    enabled: extension.enabled,
    permissions: permissions,
    hostPermissions: hostPermissions,
    riskScore: Math.min(riskScore, 100),
    riskLevel: riskLevel,
    threats: threats, // Detailed threat list
    flags: flags, // NEW: Traceability flags showing WHY score is high
    version: extension.version,
    installType: extension.installType,
    sensitiveDomains: [...new Set(sensitiveDomainAccess)] // Unique sensitive domains
  };
}

async function reportToBackend(risks) {
  // Don't report if no employee ID yet
  if (!EMPLOYEE_ID) {
    await initEmployeeId();
  }
  
  try {
    const payload = {
      employee_id: EMPLOYEE_ID,
      timestamp: new Date().toISOString(),
      extensions: risks.map(ext => ({
        extension_name: ext.name || 'Unknown',
        permissions_requested: ext.permissions || [],
        host_access: ext.hostPermissions || [],
        risk_score: ext.riskScore || 0,
        risk_level: ext.riskLevel || 'UNKNOWN',
        enabled: ext.enabled || false
      }))
    };
    
    // Add timeout to prevent hanging requests
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch(`${API_BASE_URL}/report_risk`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
  } catch (error) {
    if (error.name === 'AbortError') {
      console.warn('Backend request timeout - server may be offline');
    } else {
      console.error('Backend report error:', error);
    }
    // Fail silently to not break extension functionality
  }
}

async function calculateSecurityScore() {
  const stored = await chrome.storage.local.get(['extensionRisks', 'currentSiteScan']);
  const extensionRisks = stored.extensionRisks || [];
  const siteScan = stored.currentSiteScan || {};
  
  let score = 100;
  
  if (siteScan.protocol === 'http') score -= 25;
  score -= (siteScan.trackerCount || 0) * 5;
  score -= (siteScan.thirdPartyCount || 0) * 2;
  
  extensionRisks.forEach(ext => {
    if (ext.enabled) {
      if (ext.riskLevel === 'HIGH') score -= 15;
      else if (ext.riskLevel === 'MEDIUM') score -= 7;
    }
  });
  
  return Math.max(0, Math.min(100, score));
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!request || typeof request.action !== 'string') {
    sendResponse({ error: 'Invalid request' });
    return false;
  }
  
  if (request.action === 'getScanData') {
    (async () => {
      try {
        const extensionRisks = await scanExtensions();
        const score = await calculateSecurityScore();
        const stored = await chrome.storage.local.get(['currentSiteScan']);
        
        sendResponse({
          score: score,
          extensionRisks: extensionRisks,
          siteScan: stored.currentSiteScan || {}
        });
      } catch (error) {
        console.error('Error getting scan data:', error);
        sendResponse({
          error: error.message,
          score: 0,
          extensionRisks: [],
          siteScan: {}
        });
      }
    })();
    return true; // Keep message channel open for async response
  }
  
  return false;
});

// Initialize on install
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('Web Security Guardian installed:', details.reason);
  await initEmployeeId();
  await scanExtensions();
});

// Initialize on startup
chrome.runtime.onStartup.addListener(async () => {
  console.log('Web Security Guardian starting up');
  await initEmployeeId();
  await scanExtensions();
});

// Use alarms API only if available
if (typeof chrome !== 'undefined' && chrome.alarms && typeof chrome.alarms.create === 'function') {
  try {
    chrome.alarms.create('periodicScan', { periodInMinutes: 5 });
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm && alarm.name === 'periodicScan') {
        scanExtensions().catch(err => console.error('Periodic scan failed:', err));
      }
    });
  } catch (error) {
    console.warn('Alarms API initialization failed:', error);
  }
} else {
  console.warn('Chrome alarms API not available - periodic scanning disabled');
}

// Initialize employee ID on load
initEmployeeId().then(() => {
  console.log('Web Security Guardian - Background worker initialized');
}).catch(err => {
  console.error('Initialization error:', err);
});
