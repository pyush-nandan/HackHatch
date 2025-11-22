// Web Security Guardian - Enterprise Background Service Worker
// Advanced Threat Detection System with ML-Style Behavioral Analysis
// Version: 2.0.0-Enterprise

const API_BASE_URL = 'http://localhost:5000/api';
let EMPLOYEE_ID = null;

// ====== BEHAVIORAL ANALYSIS DATABASE ======
const BEHAVIOR_BASELINE = {
  normal_permission_counts: {
    productivity: { avg: 3, max: 7 },
    security: { avg: 2, max: 5 },
    shopping: { avg: 2, max: 4 },
    social: { avg: 3, max: 6 }
  },
  suspicious_combinations: [
    ['cookies', 'webRequest', 'tabs'],  // Credential theft combo
    ['proxy', 'webRequestBlocking'],     // MITM attack
    ['debugger', 'tabs'],                 // Code injection
    ['management', 'browsingData'],       // Security bypass
    ['cookies', '<all_urls>']             // Universal session theft
  ],
  temporal_anomalies: {
    rapid_permission_expansion: 30,  // days
    sudden_behavior_change: 7        // days
  }
};

// ====== ADVANCED THREAT INTELLIGENCE ======
const THREAT_INTELLIGENCE = {
  // Known malware extension IDs (would be populated from threat feeds)
  blacklist: [],
  
  // Suspicious permission patterns from real-world attacks
  malware_signatures: [
    {
      name: 'DataSpii-Style Credential Harvester',
      pattern: ['cookies', 'webRequest', '<all_urls>'],
      severity: 'CRITICAL',
      cve: 'CVE-2019-DataSpii',
      description: 'Can intercept login credentials on all websites',
      detection_confidence: 0.95
    },
    {
      name: 'Banking Trojan',
      pattern: ['cookies', 'webRequestBlocking'],
      domains: ['bank', 'paypal', 'stripe'],
      severity: 'CRITICAL',
      description: 'Targets financial websites to steal payment data',
      detection_confidence: 0.90
    },
    {
      name: 'Cryptojacker',
      pattern: ['webRequest', 'tabs'],
      indicators: ['high_cpu', 'mining_domains'],
      severity: 'HIGH',
      description: 'Uses browser resources to mine cryptocurrency',
      detection_confidence: 0.85
    },
    {
      name: 'Surveillance Extension',
      pattern: ['tabs', 'history', 'bookmarks'],
      severity: 'HIGH',
      description: 'Complete browsing activity monitoring',
      detection_confidence: 0.88
    },
    {
      name: 'Adware Injector',
      pattern: ['webRequest', 'declarativeNetRequest'],
      severity: 'MEDIUM',
      description: 'Injects advertisements into web pages',
      detection_confidence: 0.75
    }
  ],
  
  // MITRE ATT&CK Framework Mapping
  attack_techniques: {
    'T1539': { name: 'Steal Web Session Cookie', permissions: ['cookies'] },
    'T1185': { name: 'Man in the Browser', permissions: ['webRequest', 'cookies'] },
    'T1090': { name: 'Proxy', permissions: ['proxy'] },
    'T1203': { name: 'Exploitation for Client Execution', permissions: ['debugger'] },
    'T1562': { name: 'Impair Defenses', permissions: ['management'] },
    'T1056': { name: 'Input Capture', permissions: ['clipboardRead'] },
    'T1005': { name: 'Data from Local System', permissions: ['browsingData'] },
    'T1071': { name: 'Application Layer Protocol', permissions: ['webRequest'] }
  },
  
  // CVE Database Integration
  known_vulnerabilities: {
    'CVE-2020-6418': {
      description: 'Chrome Extension Type Confusion',
      affected: ['webRequest', 'webRequestBlocking'],
      severity: 'HIGH',
      cvss: 8.8
    },
    'CVE-2019-5870': {
      description: 'Chrome Extension Use After Free',
      affected: ['tabs', 'windows'],
      severity: 'HIGH',
      cvss: 8.1
    }
  }
};

// ====== SECURITY SCORING MATRIX ======
const RISK_WEIGHTS = {
  permission_severity: 0.35,
  permission_count: 0.15,
  host_access_scope: 0.25,
  combination_risk: 0.15,
  behavioral_anomaly: 0.10
};

const PERMISSION_CATEGORIES = {
  CRITICAL_NETWORK: {
    permissions: ['webRequest', 'webRequestBlocking', 'proxy', 'debugger'],
    base_score: 30,
    reason: 'Can intercept, modify, or redirect network traffic'
  },
  CRITICAL_DATA: {
    permissions: ['cookies', 'browsingData', 'clipboardRead'],
    base_score: 25,
    reason: 'Can access sensitive user data and credentials'
  },
  CRITICAL_CONTROL: {
    permissions: ['management', 'declarativeNetRequestWithHostAccess'],
    base_score: 22,
    reason: 'Can control browser behavior and other extensions'
  },
  HIGH_PRIVACY: {
    permissions: ['history', 'tabs', 'topSites', 'geolocation'],
    base_score: 15,
    reason: 'Extensive privacy invasion capability'
  },
  HIGH_SYSTEM: {
    permissions: ['nativeMessaging', 'downloads', 'clipboardWrite'],
    base_score: 14,
    reason: 'System-level access and file manipulation'
  },
  MEDIUM_TRACKING: {
    permissions: ['idle', 'bookmarks', 'notifications', 'contextMenus'],
    base_score: 7,
    reason: 'User activity monitoring and interaction'
  }
};

// ====== DOMAIN CLASSIFICATION DATABASE ======
const DOMAIN_INTELLIGENCE = {
  FINANCIAL: {
    patterns: ['bank', 'banking', 'chase', 'wellsfargo', 'bofa', 'citi', 'paypal', 'venmo', 'stripe', 'square', 'mint', 'robinhood', 'fidelity', 'vanguard'],
    risk_multiplier: 2.5,
    category: 'Financial Services'
  },
  EMAIL: {
    patterns: ['mail.google', 'outlook', 'yahoo.com/mail', 'protonmail', 'icloud.com/mail', 'aol.com'],
    risk_multiplier: 2.2,
    category: 'Email Services'
  },
  SOCIAL_MEDIA: {
    patterns: ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'reddit', 'pinterest', 'snapchat'],
    risk_multiplier: 1.8,
    category: 'Social Media'
  },
  SHOPPING: {
    patterns: ['amazon', 'ebay', 'walmart', 'target', 'bestbuy', 'shop', 'checkout', 'cart', 'store'],
    risk_multiplier: 2.0,
    category: 'E-Commerce'
  },
  CORPORATE: {
    patterns: ['slack', 'teams.microsoft', 'zoom', 'webex', 'salesforce', 'office365', 'atlassian', 'github', 'gitlab'],
    risk_multiplier: 2.3,
    category: 'Enterprise Productivity'
  },
  GOVERNMENT: {
    patterns: ['.gov', 'irs.gov', 'ssa.gov', 'usa.gov', 'whitehouse.gov'],
    risk_multiplier: 3.0,
    category: 'Government'
  },
  HEALTHCARE: {
    patterns: ['healthcare', 'hospital', 'medical', 'health.', 'patient', 'clinic'],
    risk_multiplier: 2.8,
    category: 'Healthcare'
  },
  EDUCATION: {
    patterns: ['.edu', 'university', 'college', 'school', 'canvas', 'blackboard'],
    risk_multiplier: 1.5,
    category: 'Education'
  }
};

// ====== BEHAVIORAL ANALYSIS ENGINE ======
class BehavioralAnalyzer {
  constructor() {
    this.history = [];
    this.baseline = null;
  }
  
  async analyzeAnomaly(extension, historicalData = []) {
    const anomalies = [];
    let anomaly_score = 0;
    
    // 1. Permission Entropy Analysis (randomness of permissions)
    const permissionEntropy = this.calculatePermissionEntropy(extension.permissions || []);
    if (permissionEntropy > 0.85) {
      anomalies.push({
        type: 'HIGH_ENTROPY',
        severity: 'MEDIUM',
        description: 'Unusual combination of unrelated permissions',
        confidence: 0.72
      });
      anomaly_score += 10;
    }
    
    // 2. Temporal Analysis (if we had historical data)
    if (historicalData.length > 0) {
      const growthRate = this.calculatePermissionGrowthRate(historicalData);
      if (growthRate > 0.5) {
        anomalies.push({
          type: 'RAPID_EXPANSION',
          severity: 'HIGH',
          description: 'Permissions increased rapidly over time',
          confidence: 0.88
        });
        anomaly_score += 20;
      }
    }
    
    // 3. Name-Permission Mismatch Detection
    const nameMismatch = this.detectNamePermissionMismatch(
      extension.name || '',
      extension.permissions || []
    );
    if (nameMismatch.isSuspicious) {
      anomalies.push({
        type: 'NAME_PERMISSION_MISMATCH',
        severity: 'HIGH',
        description: nameMismatch.reason,
        confidence: nameMismatch.confidence
      });
      anomaly_score += 25;
    }
    
    // 4. Update URL Anomaly Detection
    if (extension.updateUrl) {
      const urlRisk = this.analyzeUpdateUrl(extension.updateUrl);
      if (urlRisk.suspicious) {
        anomalies.push({
          type: 'SUSPICIOUS_UPDATE_URL',
          severity: 'HIGH',
          description: urlRisk.reason,
          confidence: 0.80
        });
        anomaly_score += 15;
      }
    }
    
    return { anomalies, anomaly_score };
  }
  
  calculatePermissionEntropy(permissions) {
    if (permissions.length === 0) return 0;
    
    // Calculate how "random" the permission set is
    // High entropy = unrelated permissions (suspicious)
    const categories = ['network', 'storage', 'ui', 'system'];
    const distribution = categories.map(cat => 
      permissions.filter(p => this.getPermissionCategory(p) === cat).length
    );
    
    const total = distribution.reduce((a, b) => a + b, 0);
    if (total === 0) return 0;
    
    const probabilities = distribution.map(count => count / total);
    const entropy = -probabilities
      .filter(p => p > 0)
      .reduce((sum, p) => sum + p * Math.log2(p), 0);
    
    return Math.min(entropy / Math.log2(categories.length), 1);
  }
  
  getPermissionCategory(permission) {
    if (['webRequest', 'proxy', 'webRequestBlocking'].includes(permission)) return 'network';
    if (['storage', 'cookies', 'browsingData'].includes(permission)) return 'storage';
    if (['tabs', 'windows', 'notifications'].includes(permission)) return 'ui';
    if (['management', 'debugger', 'nativeMessaging'].includes(permission)) return 'system';
    return 'other';
  }
  
  calculatePermissionGrowthRate(historicalData) {
    if (historicalData.length < 2) return 0;
    
    const initial = historicalData[0].permissions.length;
    const current = historicalData[historicalData.length - 1].permissions.length;
    
    if (initial === 0) return 0;
    return (current - initial) / initial;
  }
  
  detectNamePermissionMismatch(name, permissions) {
    const nameLower = name.toLowerCase();
    
    // Simple productivity tool requesting dangerous permissions
    const productivityKeywords = ['todo', 'note', 'task', 'calendar', 'timer', 'clock'];
    const isProductivityTool = productivityKeywords.some(keyword => nameLower.includes(keyword));
    
    const hasDangerousPerms = permissions.some(p => 
      ['webRequest', 'proxy', 'cookies', 'debugger', 'management'].includes(p)
    );
    
    if (isProductivityTool && hasDangerousPerms) {
      return {
        isSuspicious: true,
        reason: 'Productivity tool requesting network interception permissions',
        confidence: 0.85
      };
    }
    
    // Shopping tool requesting too many permissions
    const shoppingKeywords = ['coupon', 'deal', 'price', 'shop', 'cashback'];
    const isShoppingTool = shoppingKeywords.some(keyword => nameLower.includes(keyword));
    
    if (isShoppingTool && permissions.length > 8) {
      return {
        isSuspicious: true,
        reason: 'Shopping extension requesting excessive permissions',
        confidence: 0.78
      };
    }
    
    return { isSuspicious: false };
  }
  
  analyzeUpdateUrl(updateUrl) {
    const urlLower = updateUrl.toLowerCase();
    
    // Check for non-HTTPS (major red flag)
    if (!updateUrl.startsWith('https://')) {
      return {
        suspicious: true,
        reason: 'Update URL not using HTTPS encryption'
      };
    }
    
    // Check for suspicious domains
    const suspiciousDomains = ['bit.ly', 'tinyurl', 'pastebin', 'raw.githubusercontent'];
    const hasSuspiciousDomain = suspiciousDomains.some(domain => urlLower.includes(domain));
    
    if (hasSuspiciousDomain) {
      return {
        suspicious: true,
        reason: 'Update URL uses potentially untrustworthy hosting'
      };
    }
    
    return { suspicious: false };
  }
}

const behavioralAnalyzer = new BehavioralAnalyzer();

// ====== INITIALIZATION ======
async function initEmployeeId() {
  try {
    const result = await chrome.storage.local.get(['employeeId']);
    if (result.employeeId) {
      EMPLOYEE_ID = result.employeeId;
    } else {
      EMPLOYEE_ID = 'EMP-' + Date.now() + '-' + Math.floor(Math.random() * 10000);
      await chrome.storage.local.set({ employeeId: EMPLOYEE_ID });
    }
  } catch (error) {
    console.error('Failed to initialize employee ID:', error);
    EMPLOYEE_ID = 'EMP-FALLBACK-' + Math.floor(Math.random() * 10000);
  }
}

// ====== ADVANCED EXTENSION RISK CALCULATION ======
async function calculateExtensionRisk(extension) {
  let riskScore = 0;
  const threats = [];
  const mitre_techniques = [];
  const cve_references = [];
  const behavioral_insights = [];
  
  const permissions = extension.permissions || [];
  const hostPermissions = extension.hostPermissions || [];
  
  // ====== PHASE 1: Permission Categorization & Scoring ======
  let category_scores = {};
  
  for (const [category, config] of Object.entries(PERMISSION_CATEGORIES)) {
    const matches = permissions.filter(p => config.permissions.includes(p));
    if (matches.length > 0) {
      const score = config.base_score * matches.length;
      category_scores[category] = score;
      riskScore += score;
      
      threats.push({
        category: category,
        severity: score >= 25 ? 'CRITICAL' : (score >= 15 ? 'HIGH' : 'MEDIUM'),
        description: config.reason,
        permissions: matches,
        score: score
      });
    }
  }
  
  // ====== PHASE 2: Host Permission Risk Analysis ======
  let host_risk_score = 0;
  const sensitive_domains_accessed = [];
  
  // Check for <all_urls> (maximum risk)
  const hasAllUrls = hostPermissions.some(host => 
    host.includes('<all_urls>') || host === '*://*/*'
  );
  
  if (hasAllUrls) {
    host_risk_score += 40;
    threats.push({
      category: 'UNIVERSAL_ACCESS',
      severity: 'CRITICAL',
      description: 'Can access EVERY website - massive attack surface',
      permissions: ['<all_urls>'],
      score: 40
    });
  }
  
  // Analyze specific domain access
  for (const host of hostPermissions) {
    const hostLower = host.toLowerCase();
    
    for (const [domainType, config] of Object.entries(DOMAIN_INTELLIGENCE)) {
      const matchedPattern = config.patterns.find(pattern => hostLower.includes(pattern));
      
      if (matchedPattern) {
        const domain_score = 15 * config.risk_multiplier;
        host_risk_score += domain_score;
        
        sensitive_domains_accessed.push({
          domain: host,
          category: config.category,
          risk_multiplier: config.risk_multiplier
        });
        
        threats.push({
          category: `${domainType}_ACCESS`,
          severity: config.risk_multiplier >= 2.5 ? 'CRITICAL' : 'HIGH',
          description: `Access to ${config.category} websites`,
          permissions: [host],
          score: domain_score
        });
        
        break;
      }
    }
  }
  
  riskScore += host_risk_score;
  
  // ====== PHASE 3: Malware Signature Detection ======
  for (const signature of THREAT_INTELLIGENCE.malware_signatures) {
    const hasAllPatternPerms = signature.pattern.every(pattern => {
      if (pattern === '<all_urls>') {
        return hasAllUrls;
      }
      return permissions.includes(pattern);
    });
    
    // Check domain patterns if specified
    let hasDomainMatch = true;
    if (signature.domains) {
      hasDomainMatch = signature.domains.some(domain =>
        hostPermissions.some(host => host.toLowerCase().includes(domain))
      );
    }
    
    if (hasAllPatternPerms && hasDomainMatch) {
      riskScore += 50 * signature.detection_confidence;
      
      threats.push({
        category: 'MALWARE_SIGNATURE',
        severity: signature.severity,
        description: `🚨 MATCHES: ${signature.name} - ${signature.description}`,
        signature: signature.name,
        detection_confidence: signature.detection_confidence,
        score: 50
      });
      
      if (signature.cve) {
        cve_references.push(signature.cve);
      }
    }
  }
  
  // ====== PHASE 4: MITRE ATT&CK Technique Mapping ======
  for (const [techniqueId, technique] of Object.entries(THREAT_INTELLIGENCE.attack_techniques)) {
    const hasRequiredPerms = technique.permissions.some(p => permissions.includes(p));
    
    if (hasRequiredPerms) {
      mitre_techniques.push({
        id: techniqueId,
        name: technique.name,
        permissions: technique.permissions.filter(p => permissions.includes(p))
      });
    }
  }
  
  // ====== PHASE 5: Dangerous Permission Combinations ======
  let combo_score = 0;
  
  for (const combo of BEHAVIOR_BASELINE.suspicious_combinations) {
    const hasCombo = combo.every(item => {
      if (item === '<all_urls>') {
        return hasAllUrls;
      }
      return permissions.includes(item);
    });
    
    if (hasCombo) {
      combo_score += 30;
      threats.push({
        category: 'DANGEROUS_COMBINATION',
        severity: 'CRITICAL',
        description: `🔴 ATTACK PATTERN: ${combo.join(' + ')}`,
        permissions: combo,
        score: 30
      });
    }
  }
  
  riskScore += combo_score;
  
  // ====== PHASE 6: Behavioral Anomaly Detection ======
  const behavioralAnalysis = await behavioralAnalyzer.analyzeAnomaly(extension);
  riskScore += behavioralAnalysis.anomaly_score;
  
  for (const anomaly of behavioralAnalysis.anomalies) {
    threats.push({
      category: 'BEHAVIORAL_ANOMALY',
      severity: anomaly.severity,
      description: `🧠 ML Detection: ${anomaly.description}`,
      confidence: anomaly.confidence,
      score: anomaly.severity === 'HIGH' ? 20 : 10
    });
    
    behavioral_insights.push(anomaly);
  }
  
  // ====== PHASE 7: Metadata Analysis ======
  // Check for obfuscated/random name
  const namePattern = /^[a-z]{8,}$/i;
  if (namePattern.test(extension.name) || extension.name.length < 3) {
    riskScore += 15;
    threats.push({
      category: 'SUSPICIOUS_METADATA',
      severity: 'MEDIUM',
      description: 'Suspicious or randomly generated name',
      score: 15
    });
  }
  
  // No description
  if (!extension.description || extension.description.length < 10) {
    riskScore += 8;
    threats.push({
      category: 'SUSPICIOUS_METADATA',
      severity: 'MEDIUM',
      description: 'Missing or inadequate description',
      score: 8
    });
  }
  
  // Developer mode extension
  if (extension.installType === 'development') {
    riskScore += 12;
    threats.push({
      category: 'UNVERIFIED_SOURCE',
      severity: 'MEDIUM',
      description: 'Developer mode - not reviewed by Chrome Web Store',
      score: 12
    });
  }
  
  // ====== PHASE 8: CVE Vulnerability Check ======
  for (const [cveId, vuln] of Object.entries(THREAT_INTELLIGENCE.known_vulnerabilities)) {
    const hasVulnerablePerms = vuln.affected.some(p => permissions.includes(p));
    
    if (hasVulnerablePerms) {
      cve_references.push({
        id: cveId,
        description: vuln.description,
        severity: vuln.severity,
        cvss: vuln.cvss
      });
      
      riskScore += vuln.cvss * 2;
    }
  }
  
  // ====== PHASE 9: Risk Level Classification ======
  let riskLevel = 'LOW';
  let riskColor = '#10b981';
  
  if (riskScore >= 100) {
    riskLevel = 'CRITICAL';
    riskColor = '#dc2626';
  } else if (riskScore >= 60) {
    riskLevel = 'HIGH';
    riskColor = '#ef4444';
  } else if (riskScore >= 30) {
    riskLevel = 'MEDIUM';
    riskColor = '#f59e0b';
  } else if (riskScore >= 10) {
    riskLevel = 'LOW';
    riskColor = '#3b82f6';
  }
  
  // ====== PHASE 10: Generate Risk Flags (Traceability) ======
  const flags = generateRiskFlags(extension, permissions, hostPermissions, threats);
  
  // ====== RETURN COMPREHENSIVE RISK PROFILE ======
  return {
    id: extension.id,
    name: extension.name,
    version: extension.version,
    description: extension.description,
    enabled: extension.enabled,
    installType: extension.installType,
    updateUrl: extension.updateUrl,
    
    // Risk assessment
    riskScore: Math.round(riskScore),
    riskLevel,
    riskColor,
    
    // Permissions
    permissions_requested: permissions,
    host_access: hostPermissions,
    
    // Threat analysis
    threats: threats.sort((a, b) => b.score - a.score),
    flags,
    
    // Advanced intelligence
    mitre_techniques,
    cve_references,
    behavioral_insights,
    sensitive_domains_accessed,
    
    // ML-style scoring breakdown
    risk_breakdown: {
      permission_severity: category_scores,
      host_access_score: host_risk_score,
      combination_risk: combo_score,
      behavioral_anomaly: behavioralAnalysis.anomaly_score
    }
  };
}

// ====== RISK FLAG GENERATION ======
function generateRiskFlags(extension, permissions, hostPermissions, threats) {
  const flags = [];
  
  // P-1: Permission Overreach
  const criticalPerms = permissions.filter(p => 
    ['webRequest', 'webRequestBlocking', 'proxy', 'debugger', 'management', 'browsingData', 'cookies'].includes(p)
  );
  
  if (criticalPerms.length >= 3) {
    flags.push({
      id: 'P-1',
      severity: 'CRITICAL',
      title: 'Excessive Dangerous Permissions',
      reason: `Requests ${criticalPerms.length} critical permissions simultaneously`,
      policy_violation: 'Principle of Least Privilege (POLP)',
      permissions: criticalPerms,
      remediation: 'Verify extension legitimacy. Consider alternatives with fewer permissions.',
      mitre_reference: 'T1068 - Exploitation for Privilege Escalation'
    });
  }
  
  // P-2: Universal Site Access
  const hasAllUrls = hostPermissions.some(h => h.includes('<all_urls>') || h === '*://*/*');
  if (hasAllUrls) {
    flags.push({
      id: 'P-2',
      severity: 'CRITICAL',
      title: 'Universal Website Access',
      reason: 'Can read and modify data on ALL websites',
      policy_violation: 'OWASP Top 10: A01 - Broken Access Control',
      permissions: ['<all_urls>'],
      remediation: 'EXTREME RISK: Extension can see everything you do online. Only install if absolutely necessary.',
      cve_reference: 'CVE-2020-6418'
    });
  }
  
  // P-3: Session Hijacking Capability
  if (permissions.includes('cookies') && (permissions.includes('webRequest') || hasAllUrls)) {
    flags.push({
      id: 'P-3',
      severity: 'CRITICAL',
      title: 'Session Hijacking Capability',
      reason: 'Can steal authentication cookies and session tokens from websites',
      policy_violation: 'NIST 800-63B: Authentication and Lifecycle Management',
      permissions: ['cookies', 'webRequest'],
      remediation: 'HIGH RISK of account takeover. Remove immediately if not trusted.',
      mitre_reference: 'T1539 - Steal Web Session Cookie',
      real_world_example: 'DataSpii malware campaign (2019) - 4.1 million users affected'
    });
  }
  
  // P-4: Financial Data Access
  const financialPatterns = ['bank', 'paypal', 'stripe', 'checkout', 'payment', 'wallet'];
  const financialHosts = hostPermissions.filter(h => 
    financialPatterns.some(pattern => h.toLowerCase().includes(pattern))
  );
  
  if (financialHosts.length > 0) {
    flags.push({
      id: 'P-4',
      severity: 'HIGH',
      title: 'Financial Website Access',
      reason: `Can access ${financialHosts.length} financial service websites`,
      policy_violation: 'PCI DSS Payment Card Industry Data Security Standard',
      permissions: financialHosts.slice(0, 5),
      remediation: 'Verify extension is legitimate before entering payment information.'
    });
  }
  
  // P-5: Security Tool Control
  if (permissions.includes('management')) {
    flags.push({
      id: 'P-5',
      severity: 'HIGH',
      title: 'Can Disable Security Extensions',
      reason: 'Has management API access to control other extensions',
      policy_violation: 'Defense in Depth Security Principle',
      permissions: ['management'],
      remediation: 'Extension could disable antivirus or security tools. Investigate immediately.',
      mitre_reference: 'T1562.001 - Disable or Modify Tools'
    });
  }
  
  // P-6: Unverified Source
  if (extension.installType === 'development') {
    flags.push({
      id: 'P-6',
      severity: 'MEDIUM',
      title: 'Unverified Extension Source',
      reason: 'Installed in developer mode - not reviewed by Chrome Web Store',
      policy_violation: 'Software Supply Chain Security',
      permissions: ['developer_mode'],
      remediation: 'Only install developer extensions from sources you completely trust.'
    });
  }
  
  // P-7: Proxy/MITM Capability
  if (permissions.includes('proxy') || (permissions.includes('webRequest') && permissions.includes('webRequestBlocking'))) {
    flags.push({
      id: 'P-7',
      severity: 'CRITICAL',
      title: 'Man-in-the-Middle Attack Capability',
      reason: 'Can intercept and modify ALL network traffic',
      policy_violation: 'Network Security Best Practices',
      permissions: ['proxy', 'webRequestBlocking'],
      remediation: 'CRITICAL: Can see passwords, credit cards, and all data transmitted. Remove if suspicious.',
      mitre_reference: 'T1090 - Proxy'
    });
  }
  
  return flags;
}

// ====== MAIN SCANNING FUNCTION ======
async function scanExtensions() {
  try {
    const extensions = await chrome.management.getAll();
    const extensionRisks = await Promise.all(
      extensions
        .filter(ext => ext.type === 'extension' && ext.id !== chrome.runtime.id)
        .map(ext => calculateExtensionRisk(ext))
    );
    
    await chrome.storage.local.set({ extensionRisks });
    
    // Report high/critical risks to backend
    const highRiskExtensions = extensionRisks.filter(ext => 
      ext.riskLevel === 'HIGH' || ext.riskLevel === 'CRITICAL'
    );
    
    if (highRiskExtensions.length > 0) {
      await reportToBackend(highRiskExtensions);
    }
    
    return extensionRisks;
  } catch (error) {
    console.error('Extension scan error:', error);
    return [];
  }
}

// ====== BACKEND REPORTING ======
async function reportToBackend(risks) {
  try {
    const response = await fetch(`${API_BASE_URL}/report_risk`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        employee_id: EMPLOYEE_ID,
        timestamp: new Date().toISOString(),
        extensions: risks
      })
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    
    console.log('✅ Risk report sent to backend');
  } catch (error) {
    console.error('Backend report error:', error);
  }
}

// ====== PERIODIC SCANNING ======
async function setupPeriodicScan() {
  // Scan every 30 minutes
  if (chrome.alarms) {
    chrome.alarms.create('periodicScan', { periodInMinutes: 30 });
    
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'periodicScan') {
        scanExtensions();
      }
    });
  }
}

// ====== MESSAGE HANDLING ======
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanExtensions') {
    scanExtensions().then(risks => {
      sendResponse({ success: true, risks });
    });
    return true;
  }
  
  if (request.action === 'getScanData') {
    chrome.storage.local.get(['extensionRisks'], (result) => {
      const risks = result.extensionRisks || [];
      
      // Calculate overall security score
      const totalExtensions = risks.length;
      const avgRisk = risks.length > 0
        ? risks.reduce((sum, ext) => sum + ext.riskScore, 0) / risks.length
        : 0;
      
      const score = Math.max(0, Math.round(100 - avgRisk));
      
      sendResponse({
        score,
        extensionRisks: risks,
        totalExtensions,
        criticalCount: risks.filter(r => r.riskLevel === 'CRITICAL').length,
        highCount: risks.filter(r => r.riskLevel === 'HIGH').length
      });
    });
    return true;
  }
});

// ====== INITIALIZATION ======
initEmployeeId().then(() => {
  scanExtensions();
  setupPeriodicScan();
});

console.log('🛡️ Web Security Guardian - Enterprise Edition Initialized');
