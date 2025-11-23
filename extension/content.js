// Web Security Guardian - Content Script with Real-time Website Safety Analysis
(function() {
  'use strict';
  
  // ====== MALICIOUS WEBSITE DATABASE ======
  const MALICIOUS_INDICATORS = {
    // Phishing patterns (inspired by Malwarebytes Browser Guard)
    phishing_patterns: [
      /login.*verify/i,
      /account.*suspended/i,
      /urgent.*action.*required/i,
      /verify.*identity/i,
      /unusual.*activity/i,
      /confirm.*password/i,
      /suspended.*account/i,
      /security.*alert/i
    ],
    
    // Known malicious domains (curated threat intelligence)
    // NOTE: Only include CONFIRMED malicious domains, not legitimate services
    malicious_domains: [
      'iplogger.org',      // IP logging service used for tracking
      'grabify.link',      // IP grabber service
      'blasze.tk',         // Known phishing infrastructure
      'ps3cfw.com'         // Known malware distribution
    ],
    
    // Suspicious services (report but don't block)
    suspicious_services: [
      'pastebin.com/raw',  // Can host malicious code but also legitimate
      'tempmail.com',      // Temporary email (suspicious but not malicious)
      'guerrillamail.com',
      'throwawaymail.com'
    ],
    
    // Credit card skimmer patterns (Magecart detection)
    skimmer_patterns: [
      /payment.*form.*hidden/i,
      /creditcard.*input.*display.*none/i,
      /checkout.*iframe/i,
      /atob.*eval/,
      /unescape.*document\.write/
    ],
    
    // Cryptojacking domains
    cryptojacking_domains: [
      'coinhive.com',
      'crypto-loot.com',
      'cryptoloot.pro',
      'webminepool.com',
      'jsecoin.com',
      'minero.cc',
      'coin-have.com'
    ],
    
    // Suspicious TLDs (WOT-style risk assessment)
    // NOTE: Only include TLDs with HIGH abuse rates
    high_risk_tlds: [
      '.tk', '.ml', '.ga', '.cf', '.gq'  // Free domains with very high abuse rates
    ],
    medium_risk_tlds: [
      '.zip', '.country', '.kim', '.click'  // Commonly abused but some legitimate use
    ],
    // Removed .xyz, .top, .work, .link as many legitimate businesses use these
    
    // SSL/Certificate red flags
    ssl_risks: {
      self_signed: 'Self-signed certificate (HIGH RISK)',
      expired: 'Expired SSL certificate (CRITICAL)',
      mismatch: 'Domain mismatch (CRITICAL)',
      no_https: 'No encryption (MEDIUM RISK)'
    }
  };
  
  // ====== COMPREHENSIVE TRACKER DATABASE (Privacy Protection) ======
  const TRACKER_DATABASE = {
    // Analytics & Tracking
    analytics: {
      'google-analytics.com': { name: 'Google Analytics', category: 'Analytics', risk: 'LOW', purpose: 'Tracks page views, user behavior, conversions' },
      'googletagmanager.com': { name: 'Google Tag Manager', category: 'Analytics', risk: 'LOW', purpose: 'Manages marketing & analytics tags' },
      'mixpanel.com': { name: 'Mixpanel', category: 'Analytics', risk: 'MEDIUM', purpose: 'Advanced user behavior tracking' },
      'segment.com': { name: 'Segment', category: 'Analytics', risk: 'MEDIUM', purpose: 'Collects & routes user data to multiple services' },
      'segment.io': { name: 'Segment', category: 'Analytics', risk: 'MEDIUM', purpose: 'Collects & routes user data to multiple services' },
      'amplitude.com': { name: 'Amplitude', category: 'Analytics', risk: 'MEDIUM', purpose: 'Product analytics & user tracking' },
      'heap.io': { name: 'Heap', category: 'Analytics', risk: 'MEDIUM', purpose: 'Automatic event tracking (captures all interactions)' },
      'fullstory.com': { name: 'FullStory', category: 'Analytics', risk: 'HIGH', purpose: 'Session replay - records everything you do' },
      'hotjar.com': { name: 'Hotjar', category: 'Analytics', risk: 'HIGH', purpose: 'Heatmaps, session recordings, form tracking' },
      'mouseflow.com': { name: 'Mouseflow', category: 'Analytics', risk: 'HIGH', purpose: 'Session replay, heatmaps, form analytics' },
      'crazyegg.com': { name: 'Crazy Egg', category: 'Analytics', risk: 'MEDIUM', purpose: 'Heatmaps & scroll tracking' },
      'statcounter.com': { name: 'StatCounter', category: 'Analytics', risk: 'LOW', purpose: 'Web analytics & visitor tracking' },
      'clicky.com': { name: 'Clicky', category: 'Analytics', risk: 'MEDIUM', purpose: 'Real-time web analytics' },
      'optimizely.com': { name: 'Optimizely', category: 'Analytics', risk: 'MEDIUM', purpose: 'A/B testing & experimentation (collects user interaction data)' }
    },
    
    // Advertising & Retargeting
    advertising: {
      'doubleclick.net': { name: 'DoubleClick (Google)', category: 'Advertising', risk: 'MEDIUM', purpose: 'Ad serving, tracks browsing for targeted ads' },
      'googlesyndication.com': { name: 'Google AdSense', category: 'Advertising', risk: 'MEDIUM', purpose: 'Displays ads, tracks clicks' },
      'adnxs.com': { name: 'AppNexus', category: 'Advertising', risk: 'MEDIUM', purpose: 'Ad exchange, behavioral targeting' },
      'facebook.net': { name: 'Facebook Pixel', category: 'Advertising', risk: 'HIGH', purpose: 'Tracks you across websites for Facebook ads' },
      'connect.facebook.net': { name: 'Facebook SDK', category: 'Advertising', risk: 'HIGH', purpose: 'Social plugins, tracks logged-in users' },
      'ads-twitter.com': { name: 'Twitter Ads', category: 'Advertising', risk: 'MEDIUM', purpose: 'Conversion tracking for Twitter ads' },
      'adsrvr.org': { name: 'The Trade Desk', category: 'Advertising', risk: 'MEDIUM', purpose: 'Programmatic advertising tracker' },
      'criteo.com': { name: 'Criteo', category: 'Advertising', risk: 'MEDIUM', purpose: 'Retargeting ads (follows you across sites)' },
      'taboola.com': { name: 'Taboola', category: 'Advertising', risk: 'LOW', purpose: 'Content recommendation & ads' },
      'outbrain.com': { name: 'Outbrain', category: 'Advertising', risk: 'LOW', purpose: 'Content recommendation & ads' }
    },
    
    // Social Media Tracking
    social: {
      'facebook.com/tr': { name: 'Facebook Pixel', category: 'Social Tracking', risk: 'HIGH', purpose: 'Tracks purchases & events for Facebook' },
      'linkedin.com/px': { name: 'LinkedIn Insight', category: 'Social Tracking', risk: 'MEDIUM', purpose: 'Conversion tracking for LinkedIn' },
      'pinterest.com/ct': { name: 'Pinterest Tag', category: 'Social Tracking', risk: 'MEDIUM', purpose: 'Tracks Pinterest ad conversions' },
      'snapchat.com/sc-sdk': { name: 'Snapchat Pixel', category: 'Social Tracking', risk: 'MEDIUM', purpose: 'Conversion tracking for Snapchat ads' },
      'tiktok.com/i18n/pixel': { name: 'TikTok Pixel', category: 'Social Tracking', risk: 'MEDIUM', purpose: 'Tracks TikTok ad performance' }
    },
    
    // Marketing Automation
    marketing: {
      'hubspot.com': { name: 'HubSpot', category: 'Marketing', risk: 'MEDIUM', purpose: 'CRM tracking, email tracking, form submissions' },
      'marketo.net': { name: 'Marketo', category: 'Marketing', risk: 'MEDIUM', purpose: 'Marketing automation, lead tracking' },
      'pardot.com': { name: 'Salesforce Pardot', category: 'Marketing', risk: 'MEDIUM', purpose: 'B2B marketing automation & tracking' },
      'mailchimp.com': { name: 'Mailchimp', category: 'Marketing', risk: 'LOW', purpose: 'Email marketing tracking' },
      'sendgrid.net': { name: 'SendGrid', category: 'Marketing', risk: 'LOW', purpose: 'Email delivery & tracking' }
    },
    
    // Performance & CDN (Lower Risk)
    performance: {
      'cloudflare.com': { name: 'Cloudflare', category: 'CDN/Security', risk: 'LOW', purpose: 'Content delivery, DDoS protection' },
      'akamai.net': { name: 'Akamai', category: 'CDN', risk: 'LOW', purpose: 'Content delivery network' },
      'fastly.net': { name: 'Fastly', category: 'CDN', risk: 'LOW', purpose: 'Edge cloud platform' },
      'cloudfront.net': { name: 'Amazon CloudFront', category: 'CDN', risk: 'LOW', purpose: 'AWS content delivery' }
    },
    
    // Data Brokers & Cross-Site Tracking (Highest Risk)
    dataBrokers: {
      'scorecardresearch.com': { name: 'Scorecard Research', category: 'Data Broker', risk: 'HIGH', purpose: 'Cross-site tracking, builds profile of your browsing' },
      'quantserve.com': { name: 'Quantcast', category: 'Data Broker', risk: 'HIGH', purpose: 'Audience measurement, profile building' },
      'bluekai.com': { name: 'Oracle BlueKai', category: 'Data Broker', risk: 'HIGH', purpose: 'Data management platform - sells your data' },
      'exelator.com': { name: 'eXelate', category: 'Data Broker', risk: 'HIGH', purpose: 'Collects & sells audience data' },
      'contextweb.com': { name: 'PulsePoint', category: 'Data Broker', risk: 'HIGH', purpose: 'Behavioral targeting across sites' }
    }
  };
  
  // Build fast lookup pattern
  const TRACKER_PATTERNS = [];
  const TRACKER_INFO = {};
  
  Object.values(TRACKER_DATABASE).forEach(category => {
    Object.entries(category).forEach(([domain, info]) => {
      const pattern = new RegExp(domain.replace(/\./g, '\\.'), 'i');
      TRACKER_PATTERNS.push(pattern);
      TRACKER_INFO[domain] = info;
    });
  });
  
  let isScanning = false;
  let lastScanTime = 0;
  const SCAN_THROTTLE = 2000; // Minimum 2 seconds between scans
  let websiteSafetyScore = 100; // Initialize at 100 (safe)
  
  // ====== WEBSITE SAFETY ANALYSIS (Malwarebytes + WOT + McAfee Style) ======
  function analyzeWebsiteSafety() {
    const url = window.location.href;
    const domain = window.location.hostname.toLowerCase();
    const protocol = window.location.protocol;
    
    const threats = [];
    let riskScore = 0;
    let safetyRating = 'SAFE'; // SAFE, SUSPICIOUS, UNSAFE
    
    // 1. SSL/HTTPS Check (McAfee WebAdvisor style)
    if (protocol !== 'https:') {
      riskScore += 30;
      threats.push({
        type: 'NO_HTTPS',
        severity: 'MEDIUM',
        description: 'Website not using secure HTTPS connection',
        recommendation: 'Avoid entering sensitive information'
      });
    }
    
    // 2. Malicious Domain Check (Malwarebytes style)
    for (const malDomain of MALICIOUS_INDICATORS.malicious_domains) {
      if (domain.includes(malDomain)) {
        riskScore += 80;
        safetyRating = 'UNSAFE';
        threats.push({
          type: 'MALICIOUS_DOMAIN',
          severity: 'CRITICAL',
          description: `Known malicious domain: ${malDomain}`,
          recommendation: 'Leave this website immediately'
        });
      }
    }
    
    // 2b. Suspicious Services Check (lower severity than malicious)
    for (const service of MALICIOUS_INDICATORS.suspicious_services) {
      if (url.includes(service)) {
        riskScore += 35;  // Increased to trigger SUSPICIOUS rating
        safetyRating = 'SUSPICIOUS';  // Explicitly set rating
        threats.push({
          type: 'SUSPICIOUS_SERVICE',
          severity: 'MEDIUM',
          description: `Service commonly used by attackers: ${service}`,
          recommendation: 'Verify content before downloading or executing'
        });
      }
    }
    
    // 3. Cryptojacking Detection
    for (const cryptoDomain of MALICIOUS_INDICATORS.cryptojacking_domains) {
      if (domain.includes(cryptoDomain)) {
        riskScore += 70;
        safetyRating = 'UNSAFE';
        threats.push({
          type: 'CRYPTOJACKING',
          severity: 'CRITICAL',
          description: 'Cryptocurrency mining script detected',
          recommendation: 'Close tab immediately - may slow your device'
        });
      }
    }
    
    // 4. Suspicious TLD Check (WOT style) - Tiered risk assessment
    for (const tld of MALICIOUS_INDICATORS.high_risk_tlds) {
      if (domain.endsWith(tld)) {
        riskScore += 35;
        safetyRating = 'SUSPICIOUS';  // Explicitly set rating
        threats.push({
          type: 'HIGH_RISK_TLD',
          severity: 'HIGH',
          description: `High-risk domain extension: ${tld} (free domain with high abuse rate)`,
          recommendation: 'Exercise extreme caution - verify website legitimacy'
        });
      }
    }
    
    for (const tld of MALICIOUS_INDICATORS.medium_risk_tlds) {
      if (domain.endsWith(tld)) {
        riskScore += 15;  // Lower penalty
        threats.push({
          type: 'MEDIUM_RISK_TLD',
          severity: 'LOW',  // Downgraded from MEDIUM
          description: `Uncommon domain extension: ${tld}`,
          recommendation: 'Verify website is legitimate'
        });
      }
    }
    
    // 5. Phishing Pattern Detection (Malwarebytes Browser Guard style)
    // IMPROVED: Context-aware detection to avoid false positives on legitimate sites
    const pageText = document.body ? document.body.innerText.toLowerCase() : '';
    
    // Whitelist known legitimate domains that may have security language
    const legitimateDomains = [
      'google.com', 'youtube.com', 'gmail.com', 'google.co',
      'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'bing.com',
      'apple.com', 'icloud.com',
      'amazon.com', 'amazon.co', 'amazonaws.com',
      'paypal.com',
      'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
      'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
      'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
      'netflix.com', 'spotify.com', 'dropbox.com',
      'salesforce.com', 'oracle.com', 'ibm.com', 'adobe.com',
      'optimizely.com',
      // News & Media sites (legitimate but heavy tracking)
      'cnn.com', 'bbc.com', 'nytimes.com', 'washingtonpost.com',
      'forbes.com', 'reuters.com', 'bloomberg.com', 'theguardian.com',
      'wsj.com', 'usatoday.com', 'nbcnews.com', 'abcnews.go.com'
    ];
    
    const isLegitimateWebsite = legitimateDomains.some(d => domain.includes(d));
    
    // Only check for phishing if NOT a whitelisted domain
    let phishingIndicatorCount = 0;
    if (!isLegitimateWebsite) {
      for (const pattern of MALICIOUS_INDICATORS.phishing_patterns) {
        if (pattern.test(pageText)) {
          phishingIndicatorCount++;
        }
      }
      
      // Only flag if MULTIPLE phishing indicators found (reduces false positives)
      if (phishingIndicatorCount >= 2) {
        riskScore += 40;
        if (safetyRating !== 'UNSAFE') {
          safetyRating = 'SUSPICIOUS';  // Don't downgrade from UNSAFE
        }
        threats.push({
          type: 'PHISHING_INDICATOR',
          severity: 'HIGH',
          description: `Multiple phishing patterns detected (${phishingIndicatorCount} indicators)`,
          recommendation: 'Verify website legitimacy before entering credentials'
        });
      }
    } else if (phishingIndicatorCount >= 1) {
      // Legitimate site with security language - just inform user
      threats.push({
        type: 'SECURITY_NOTICE',
        severity: 'LOW',
        description: 'This appears to be a legitimate website with security alerts',
        recommendation: 'This is likely normal for banking/security sites'
      });
    }
    
    // 6. Credit Card Skimmer Detection (Magecart protection)
    // Only check on pages that appear to be checkout/payment pages AND not whitelisted
    const isCheckoutPage = url.includes('checkout') || url.includes('payment') || 
                          url.includes('cart') || pageText.includes('credit card');
    
    // Skip skimmer detection for legitimate websites entirely
    if (isCheckoutPage && !isLegitimateWebsite) {
      const scripts = document.querySelectorAll('script');
      let skimmerIndicators = 0;
      
      scripts.forEach(script => {
        const scriptContent = script.innerHTML;
        for (const pattern of MALICIOUS_INDICATORS.skimmer_patterns) {
          if (pattern.test(scriptContent)) {
            skimmerIndicators++;
          }
        }
      });
      
      // Only flag if multiple indicators found
      if (skimmerIndicators >= 2) {
        riskScore += 90;
        safetyRating = 'UNSAFE';
        threats.push({
          type: 'CREDIT_CARD_SKIMMER',
          severity: 'CRITICAL',
          description: 'Payment card skimmer detected (Magecart-style attack)',
          recommendation: 'DO NOT enter payment information - report to browser'
        });
      }
    }
    
    // 7. Hidden iframe detection (common in malicious sites)
    // Skip for legitimate websites (they often use iframes for videos, embeds, etc.)
    if (!isLegitimateWebsite) {
      const iframes = document.querySelectorAll('iframe[style*="display: none"], iframe[style*="display:none"]');
      if (iframes.length > 0) {
        riskScore += 20;
        threats.push({
          type: 'HIDDEN_IFRAME',
          severity: 'MEDIUM',
          description: `${iframes.length} hidden iframe(s) detected`,
          recommendation: 'May be used for tracking or malicious content'
        });
      }
    }
    
    // 8. Obfuscated JavaScript (malware indicator)
    // Skip for legitimate websites (they often use minification/bundling)
    if (!isLegitimateWebsite) {
      const scripts = document.querySelectorAll('script');
      scripts.forEach(script => {
        const content = script.innerHTML;
        if (content.includes('eval(') || content.includes('atob(') || content.includes('unescape(')) {
          riskScore += 30;
          threats.push({
            type: 'OBFUSCATED_JS',
            severity: 'HIGH',
            description: 'Obfuscated JavaScript detected',
            recommendation: 'May contain hidden malicious code'
          });
        }
      });
    }
    
    // Determine final safety rating
    // For whitelisted legitimate websites, ALWAYS mark as SAFE
    // (They may have high risk scores due to tracking/iframes, but they're not malicious)
    if (isLegitimateWebsite) {
      safetyRating = 'SAFE';
      // Keep the original riskScore for privacy calculations, but cap website safety at 100
      websiteSafetyScore = 100;
    } else if (riskScore >= 70) {
      safetyRating = 'UNSAFE';
    } else if (riskScore >= 30) {
      safetyRating = 'SUSPICIOUS';
    } else {
      websiteSafetyScore = Math.max(0, 100 - riskScore);
    }
    
    // For non-whitelisted sites, calculate score based on risk
    if (!isLegitimateWebsite) {
      websiteSafetyScore = Math.max(0, 100 - riskScore);
    }
    
    return {
      safetyRating,
      riskScore,
      safetyScore: websiteSafetyScore,
      threats,
      domain,
      protocol,
      timestamp: new Date().toISOString()
    };
  }
  
  function scanCurrentPage() {
    // Prevent concurrent scans and throttle
    const now = Date.now();
    if (isScanning || (now - lastScanTime) < SCAN_THROTTLE) {
      return null;
    }
    
    isScanning = true;
    lastScanTime = now;
    
    try {
      const url = window.location.href;
      const protocol = window.location.protocol.replace(':', '');
      const domain = window.location.hostname;
      
      // Security: Validate domain to prevent XSS
      if (!domain || typeof domain !== 'string') {
        throw new Error('Invalid domain');
      }
      
      // Run website safety analysis
      const safetyAnalysis = analyzeWebsiteSafety();
      
      const scripts = Array.from(document.querySelectorAll('script[src]'));
      const scriptUrls = scripts.map(s => s.src).filter(Boolean);
      
      const thirdPartyDomains = new Set();
      const trackers = [];
      const trackerDetails = []; // Detailed tracker information
      
      scriptUrls.forEach(scriptUrl => {
        try {
          const scriptDomain = new URL(scriptUrl).hostname;
          if (scriptDomain && scriptDomain !== domain) {
            thirdPartyDomains.add(scriptDomain);
            
            // Check if it's a known tracker
            for (const [trackerDomain, info] of Object.entries(TRACKER_INFO)) {
              if (scriptUrl.toLowerCase().includes(trackerDomain.toLowerCase())) {
                if (!trackers.includes(scriptDomain)) {
                  trackers.push(scriptDomain);
                  trackerDetails.push({
                    domain: scriptDomain,
                    name: info.name,
                    category: info.category,
                    risk: info.risk,
                    purpose: info.purpose,
                    url: scriptUrl.substring(0, 100) // Truncate for storage
                  });
                }
                break;
              }
            }
          }
        } catch (e) {
          // Invalid URL, skip silently
          console.debug('Invalid script URL:', scriptUrl);
        }
      });
      
      // Security: Safe cookie parsing
      let cookieCount = 0;
      try {
        const cookies = document.cookie.split(';').filter(c => c.trim());
        cookieCount = cookies.length;
      } catch (e) {
        console.warn('Cookie access error:', e);
      }
      
      // Check for mixed content
      const mixedContent = protocol === 'https' && 
        scriptUrls.some(url => url.startsWith('http:'));
      
      // Analyze tracker privacy impact
      const privacyImpact = analyzePrivacyImpact(trackerDetails);
      
      const scanResult = {
        url: url.substring(0, 500), // Limit URL length to prevent storage issues
        domain: domain,
        protocol: protocol,
        isSecure: protocol === 'https',
        mixedContent: mixedContent,
        scriptCount: scriptUrls.length,
        thirdPartyDomains: Array.from(thirdPartyDomains).slice(0, 50), // Limit array size
        thirdPartyCount: thirdPartyDomains.size,
        trackers: trackers.slice(0, 20), // Limit tracker list
        trackerDetails: trackerDetails, // Detailed tracker info
        trackerCount: trackers.length,
        cookieCount: cookieCount,
        timestamp: new Date().toISOString(),
        // Add website safety analysis (Malwarebytes + WOT + McAfee style)
        websiteSafety: safetyAnalysis,
        // Add privacy impact analysis
        privacyImpact: privacyImpact
      };
      
      // Display safety warning for unsafe or suspicious sites
      if (safetyAnalysis.safetyRating === 'UNSAFE' || safetyAnalysis.safetyRating === 'SUSPICIOUS') {
        displaySafetyWarning(safetyAnalysis);
      }
      
      // Save to storage with error handling
      chrome.storage.local.set({ currentSiteScan: scanResult }).catch(err => {
        console.error('Storage error:', err);
      });
      
      return scanResult;
    } catch (error) {
      console.error('Scan error:', error);
      return null;
    } finally {
      isScanning = false;
    }
  }
  
  // ====== PRIVACY IMPACT ANALYSIS (Ghostery/Privacy Badger Style) ======
  function analyzePrivacyImpact(trackerDetails) {
    const categoryCounts = {
      'Analytics': 0,
      'Advertising': 0,
      'Social Tracking': 0,
      'Marketing': 0,
      'Data Broker': 0,
      'CDN/Security': 0,
      'Other': 0
    };
    
    const riskCounts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    const dataCollected = new Set();
    
    trackerDetails.forEach(tracker => {
      // Count by category
      const category = tracker.category || 'Other';
      if (categoryCounts[category] !== undefined) {
        categoryCounts[category]++;
      } else {
        categoryCounts.Other++;
      }
      
      // Count by risk level
      if (riskCounts[tracker.risk] !== undefined) {
        riskCounts[tracker.risk]++;
      }
      
      // Determine what data is being collected
      if (tracker.category === 'Analytics') {
        dataCollected.add('Browsing behavior');
        dataCollected.add('Page views');
        dataCollected.add('Click patterns');
      }
      if (tracker.category === 'Advertising') {
        dataCollected.add('Browsing history');
        dataCollected.add('Ad interactions');
        dataCollected.add('Demographic data');
      }
      if (tracker.category === 'Social Tracking') {
        dataCollected.add('Social media profiles');
        dataCollected.add('Cross-site activity');
      }
      if (tracker.category === 'Data Broker') {
        dataCollected.add('Complete browsing profile');
        dataCollected.add('Personal identifiers');
        dataCollected.add('Purchase history');
      }
      if (tracker.risk === 'HIGH') {
        dataCollected.add('Session recordings');
        dataCollected.add('Form inputs');
        dataCollected.add('Mouse movements');
      }
    });
    
    // Calculate privacy score (0-100, higher = more private)
    const trackerPenalty = Math.min(trackerDetails.length * 5, 50);
    const highRiskPenalty = riskCounts.HIGH * 15;
    const mediumRiskPenalty = riskCounts.MEDIUM * 5;
    const dataBrokerPenalty = categoryCounts['Data Broker'] * 20;
    
    const privacyScore = Math.max(0, 100 - trackerPenalty - highRiskPenalty - mediumRiskPenalty - dataBrokerPenalty);
    
    // Generate privacy recommendations
    const recommendations = [];
    if (riskCounts.HIGH > 0) {
      recommendations.push('🔴 HIGH RISK: This site uses session recording - everything you do is being recorded');
    }
    if (categoryCounts['Data Broker'] > 0) {
      recommendations.push('⚠️ Data brokers detected - your browsing data may be sold to third parties');
    }
    if (categoryCounts['Social Tracking'] > 0) {
      recommendations.push('👁️ Social media tracking - your activity is shared with social networks');
    }
    if (trackerDetails.length > 10) {
      recommendations.push('📊 Heavy tracking detected - consider using privacy tools');
    }
    
    return {
      privacyScore,
      totalTrackers: trackerDetails.length,
      categoryCounts,
      riskCounts,
      dataCollected: Array.from(dataCollected),
      recommendations,
      trackerBreakdown: trackerDetails.slice(0, 10) // Top 10 trackers
    };
  }
  
  // ====== VISUAL SAFETY WARNING (Malwarebytes/WOT style) ======
  function displaySafetyWarning(safetyData) {
    // Check if warning already exists
    if (document.getElementById('wsg-safety-warning')) {
      return;
    }
    
    // Different colors based on severity
    const isUnsafe = safetyData.safetyRating === 'UNSAFE';
    const backgroundColor = isUnsafe 
      ? 'linear-gradient(135deg, #dc2626, #991b1b)'  // Red for UNSAFE
      : 'linear-gradient(135deg, #f59e0b, #d97706)'; // Orange for SUSPICIOUS
    const borderColor = isUnsafe ? '#7f1d1d' : '#92400e';
    const icon = isUnsafe ? '🚨' : '⚠️';
    const title = isUnsafe 
      ? '🚨 UNSAFE WEBSITE DETECTED - Web Security Guardian'
      : '⚠️ SUSPICIOUS WEBSITE - Web Security Guardian';
    
    const warningBanner = document.createElement('div');
    warningBanner.id = 'wsg-safety-warning';
    warningBanner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: ${backgroundColor};
      color: white;
      padding: 15px 20px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      z-index: 2147483647;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      border-bottom: 3px solid ${borderColor};
      animation: slideDown 0.3s ease-out;
    `;
    
    // Show all threats for UNSAFE, only CRITICAL/HIGH for SUSPICIOUS
    const relevantThreats = isUnsafe 
      ? safetyData.threats
      : safetyData.threats.filter(t => t.severity === 'CRITICAL' || t.severity === 'HIGH');
    
    const threatList = relevantThreats
      .slice(0, 3)  // Limit to 3 threats to avoid clutter
      .map(t => `• ${t.description}`)
      .join('<br>');
    
    const moreThreats = safetyData.threats.length > 3 
      ? `<div style="font-size: 11px; margin-top: 5px; opacity: 0.9;">+ ${safetyData.threats.length - 3} more security issues detected</div>`
      : '';
    
    warningBanner.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; max-width: 1200px; margin: 0 auto;">
        <div style="flex: 1;">
          <div style="display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 24px;">${icon}</span>
            <div>
              <strong style="font-size: 16px; display: block; margin-bottom: 5px;">
                ${title}
              </strong>
              <div style="font-size: 13px; opacity: 0.95;">
                ${threatList || 'This website may pose security risks'}
                ${moreThreats}
              </div>
            </div>
          </div>
        </div>
        <button id="wsg-close-warning" style="
          background: rgba(255,255,255,0.2);
          border: 1px solid rgba(255,255,255,0.4);
          color: white;
          padding: 8px 16px;
          border-radius: 4px;
          cursor: pointer;
          font-weight: bold;
          margin-left: 20px;
          transition: background 0.2s;
        " onmouseover="this.style.background='rgba(255,255,255,0.3)'" 
           onmouseout="this.style.background='rgba(255,255,255,0.2)'">
          Dismiss
        </button>
      </div>
    `;
    
    // Add animation
    const style = document.createElement('style');
    style.textContent = `
      @keyframes slideDown {
        from { transform: translateY(-100%); }
        to { transform: translateY(0); }
      }
    `;
    document.head.appendChild(style);
    
    document.body.insertBefore(warningBanner, document.body.firstChild);
    
    // Close button
    document.getElementById('wsg-close-warning')?.addEventListener('click', () => {
      warningBanner.remove();
    });
  }
  
  // Initial scan
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanCurrentPage, { once: true });
  } else {
    scanCurrentPage();
  }
  
  // Observe DOM changes with debouncing
  let scanTimeout;
  let observerActive = true;
  
  const observer = new MutationObserver((mutations) => {
    if (!observerActive) return;
    
    const hasNewScripts = mutations.some(m => 
      Array.from(m.addedNodes).some(node => 
        node.tagName === 'SCRIPT' && node.hasAttribute('src')
      )
    );
    
    if (hasNewScripts) {
      clearTimeout(scanTimeout);
      scanTimeout = setTimeout(() => {
        if (observerActive) {
          scanCurrentPage();
        }
      }, 1000);
    }
  });
  
  try {
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  } catch (error) {
    console.error('Observer error:', error);
  }
  
  // Cleanup on unload
  window.addEventListener('beforeunload', () => {
    observerActive = false;
    clearTimeout(scanTimeout);
    observer.disconnect();
  }, { once: true });
  
  // Listen for rescan requests from popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'rescanPage') {
      console.log('Rescan requested by popup');
      isScanning = false;  // Reset scanning flag
      lastScanTime = 0;    // Reset throttle
      scanCurrentPage();
      sendResponse({ success: true });
    }
    return true;
  });
  
})();
