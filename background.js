// SafeGuard Browser Extension - Background Service Worker
// Google Safe Browsing API Integration

// API Configuration with your provided key
const SAFE_BROWSING_API_KEY = 'AIzaSyDZExlGotyTFv3KTsFWvWojzSHfmfoweOg';
const SAFE_BROWSING_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

// Risk assessment factors and weights
const RISK_FACTORS = {
  MALWARE: { weight: 10, description: 'Malware detected' },
  SOCIAL_ENGINEERING: { weight: 8, description: 'Phishing attempt detected' },
  UNWANTED_SOFTWARE: { weight: 6, description: 'Unwanted software' },
  POTENTIALLY_HARMFUL_APPLICATION: { weight: 7, description: 'Potentially harmful application' },
  SUSPICIOUS_DOMAIN: { weight: 5, description: 'Suspicious domain characteristics' },
  NO_HTTPS: { weight: 3, description: 'Unencrypted connection' },
  NEW_DOMAIN: { weight: 4, description: 'Recently registered domain' },
  SUSPICIOUS_TLD: { weight: 2, description: 'Suspicious top-level domain' }
};

// Cache for API responses to reduce calls and improve performance
const apiCache = new Map();
const CACHE_DURATION = 300000; // 5 minutes in milliseconds

// Initialize extension on install
chrome.runtime.onInstalled.addListener(() => {
  console.log('SafeGuard Browser Extension installed successfully');
  
  // Set default settings
  chrome.storage.sync.set({
    extensionEnabled: true,
    blockMalicious: true,
    showWarnings: true,
    logActivity: true
  });
});

// Listen for tab navigation events
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only process main frame (not iframes)
  if (details.frameId !== 0) return;
  
  try {
    // Check if extension is enabled
    const settings = await chrome.storage.sync.get(['extensionEnabled']);
    if (!settings.extensionEnabled) return;
    
    const url = details.url;
    console.log('Analyzing URL:', url);
    
    // Calculate comprehensive risk score
    const riskAssessment = await calculateRiskScore(url);
    
    // Store assessment data for popup display
    await chrome.storage.local.set({
      [`risk_${details.tabId}`]: {
        url: url,
        score: riskAssessment.score,
        factors: riskAssessment.factors,
        level: riskAssessment.level,
        timestamp: Date.now(),
        apiResponse: riskAssessment.apiResponse
      }
    });
    
    // Update extension badge with risk level
    updateBadge(details.tabId, riskAssessment.score, riskAssessment.level);
    
    // Handle high-risk sites (score >= 8)
    if (riskAssessment.score >= 8) {
      await handleHighRiskSite(details.tabId, url, riskAssessment);
    } 
    // Show warnings for medium-risk sites (score >= 5)
    else if (riskAssessment.score >= 5) {
      await showWarning(details.tabId, riskAssessment);
    }
    
    // Log activity if enabled
    const logSettings = await chrome.storage.sync.get(['logActivity']);
    if (logSettings.logActivity) {
      await logSecurityActivity(url, riskAssessment);
    }
    
  } catch (error) {
    console.error('Error in navigation handler:', error);
  }
});

// Main risk calculation function
async function calculateRiskScore(url) {
  let totalScore = 0;
  const factors = [];
  let apiResponse = null;
  
  try {
    const urlObj = new URL(url);
    
    // 1. Check Google Safe Browsing API for known threats
    const threats = await checkSafeBrowsingAPI(url);
    apiResponse = threats;
    
    if (threats && threats.length > 0) {
      console.log('Threats detected:', threats);
      for (const threat of threats) {
        const threatType = threat.threatType || 'MALWARE';
        if (RISK_FACTORS[threatType]) {
          factors.push(RISK_FACTORS[threatType]);
          totalScore += RISK_FACTORS[threatType].weight;
        }
      }
    }
    
    // 2. Check for HTTPS encryption
    if (urlObj.protocol !== 'https:') {
      factors.push(RISK_FACTORS.NO_HTTPS);
      totalScore += RISK_FACTORS.NO_HTTPS.weight;
    }
    
    // 3. Analyze domain for suspicious patterns
    if (await isSuspiciousDomain(urlObj.hostname)) {
      factors.push(RISK_FACTORS.SUSPICIOUS_DOMAIN);
      totalScore += RISK_FACTORS.SUSPICIOUS_DOMAIN.weight;
    }
    
    // 4. Check for suspicious top-level domains
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.bid', '.win'];
    if (suspiciousTlds.some(tld => urlObj.hostname.toLowerCase().endsWith(tld))) {
      factors.push(RISK_FACTORS.SUSPICIOUS_TLD);
      totalScore += RISK_FACTORS.SUSPICIOUS_TLD.weight;
    }
    
  } catch (error) {
    console.error('Risk calculation error:', error);
    totalScore = 0;
  }
  
  // Normalize score to 0-10 scale
  const normalizedScore = Math.min(totalScore, 10);
  
  return {
    score: normalizedScore,
    factors: factors,
    level: getRiskLevel(normalizedScore),
    apiResponse: apiResponse
  };
}

// Google Safe Browsing API integration
async function checkSafeBrowsingAPI(url) {
  const cacheKey = `sb_${url}`;
  
  // Check cache first to avoid unnecessary API calls
  if (apiCache.has(cacheKey)) {
    const cached = apiCache.get(cacheKey);
    if (Date.now() - cached.timestamp < CACHE_DURATION) {
      console.log('Using cached result for:', url);
      return cached.threats;
    }
  }
  
  try {
    const requestBody = {
      client: {
        clientId: "safeguard-extension",
        clientVersion: "1.0.0"
      },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING", 
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: url }]
      }
    };
    
    console.log('Making Safe Browsing API request for:', url);
    
    const response = await fetch(`${SAFE_BROWSING_API_URL}?key=${SAFE_BROWSING_API_KEY}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });
    
    if (!response.ok) {
      console.error(`API request failed: ${response.status} ${response.statusText}`);
      return [];
    }
    
    const data = await response.json();
    const threats = data.matches || [];
    
    // Cache the result
    apiCache.set(cacheKey, {
      threats: threats,
      timestamp: Date.now()
    });
    
    console.log(`API response for ${url}:`, threats.length > 0 ? 'THREATS FOUND' : 'CLEAN');
    return threats;
    
  } catch (error) {
    console.error('Safe Browsing API error:', error);
    return [];
  }
}

// Advanced domain analysis
async function isSuspiciousDomain(hostname) {
  const suspiciousPatterns = [
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP addresses instead of domains
    /-{3,}/, // Multiple consecutive hyphens
    /[0-9]{8,}/, // Long sequences of numbers
    /(secure|login|update|verify|confirm).*(bank|paypal|amazon|google|microsoft|apple)/i, // Phishing keywords
    /[a-z]{25,}/, // Unusually long domain names
    /[0-9]+[a-z]+[0-9]+[a-z]+/, // Mixed numbers and letters pattern
    /(bit\.ly|tinyurl|short|redirect)/i // URL shorteners (can be suspicious)
  ];
  
  return suspiciousPatterns.some(pattern => pattern.test(hostname));
}

// Get risk level classification
function getRiskLevel(score) {
  if (score >= 8) return 'HIGH';
  if (score >= 5) return 'MEDIUM';
  if (score >= 2) return 'LOW';
  return 'SAFE';
}

// Update extension badge with risk indicator
function updateBadge(tabId, score, level) {
  const colors = {
    'HIGH': '#FF4444',
    'MEDIUM': '#FF8800',
    'LOW': '#FFAA00',
    'SAFE': '#44AA44'
  };
  
  const badges = {
    'HIGH': '⚠',
    'MEDIUM': '!',
    'LOW': '?',
    'SAFE': '✓'
  };
  
  chrome.action.setBadgeBackgroundColor({ 
    color: colors[level] || '#44AA44',
    tabId: tabId 
  });
  
  chrome.action.setBadgeText({ 
    text: badges[level] || '✓',
    tabId: tabId 
  });
}

// Handle high-risk sites
async function handleHighRiskSite(tabId, url, riskAssessment) {
  const settings = await chrome.storage.sync.get(['blockMalicious']);
  
  if (settings.blockMalicious) {
    console.log('Blocking high-risk site:', url);
    
    // Create warning page URL with parameters
    const warningUrl = chrome.runtime.getURL('warning.html') + 
                      `?blocked_url=${encodeURIComponent(url)}&score=${riskAssessment.score}`;
    
    // Redirect to warning page
    chrome.tabs.update(tabId, { url: warningUrl });
  }
}

// Show warning overlay for medium-risk sites
async function showWarning(tabId, riskAssessment) {
  const settings = await chrome.storage.sync.get(['showWarnings']);
  
  if (settings.showWarnings) {
    try {
      console.log('Showing warning for medium-risk site');
      
      await chrome.tabs.sendMessage(tabId, {
        action: 'showWarning',
        data: riskAssessment
      });
    } catch (error) {
      console.log('Could not send warning to content script:', error);
    }
  }
}

// Log security activity
async function logSecurityActivity(url, assessment) {
  try {
    const logs = await chrome.storage.local.get(['activityLogs']) || { activityLogs: [] };
    const activityLogs = logs.activityLogs || [];
    
    activityLogs.push({
      timestamp: Date.now(),
      url: url,
      score: assessment.score,
      level: assessment.level,
      factors: assessment.factors.length,
      blocked: assessment.score >= 8
    });
    
    // Keep only last 100 entries
    if (activityLogs.length > 100) {
      activityLogs.splice(0, activityLogs.length - 100);
    }
    
    await chrome.storage.local.set({ activityLogs: activityLogs });
  } catch (error) {
    console.error('Error logging activity:', error);
  }
}

// Handle messages from popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getRiskData') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs && tabs[0]) {
        const tabId = tabs[0].id;
        const data = await chrome.storage.local.get(`risk_${tabId}`);
        sendResponse(data[`risk_${tabId}`] || null);
      } else {
        sendResponse(null);
      }
    });
    return true; // Keep message channel open for async response
  }
  
  if (request.action === 'updateSettings') {
    chrome.storage.sync.set(request.settings);
    console.log('Settings updated:', request.settings);
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'getActivityLogs') {
    chrome.storage.local.get(['activityLogs'], (data) => {
      sendResponse(data.activityLogs || []);
    });
    return true;
  }
  
  if (request.action === 'clearActivityLogs') {
    chrome.storage.local.set({ activityLogs: [] });
    sendResponse({ success: true });
    return true;
  }
});

// Clean up old cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of apiCache.entries()) {
    if (now - value.timestamp > CACHE_DURATION) {
      apiCache.delete(key);
    }
  }
  console.log(`Cache cleanup completed. Current cache size: ${apiCache.size}`);
}, 60000); // Run every minute

// Handle extension startup
chrome.runtime.onStartup.addListener(() => {
  console.log('SafeGuard Browser Extension started');
});