# 🔧 Troubleshooting Guide
## Web Security Guardian - Common Issues & Solutions

**Version:** 2.0.0  
**Last Updated:** November 23, 2025  
**Project:** Web Security Guardian - Enterprise Edition

---

## 📋 Table of Contents

1. [Installation Issues](#installation-issues)
2. [Extension Problems](#extension-problems)
3. [Backend Server Issues](#backend-server-issues)
4. [Network & Connectivity](#network--connectivity)
5. [Performance Issues](#performance-issues)
6. [Data & Storage Problems](#data--storage-problems)
7. [Platform-Specific Issues](#platform-specific-issues)
8. [Advanced Debugging](#advanced-debugging)

---

## Installation Issues

### ❌ Problem: Python Not Found

**Symptoms:**
```powershell
python : The term 'python' is not recognized as the name of a cmdlet...
```

**Solutions:**

**Option 1: Install Python**
1. Download Python 3.8+ from [python.org](https://www.python.org/downloads/)
2. ✅ **Check "Add Python to PATH"** during installation
3. Restart PowerShell
4. Verify: `python --version`

**Option 2: Use Full Path**
```powershell
# Find Python installation
Get-Command python -ErrorAction SilentlyContinue

# If found at C:\Python39\python.exe, use:
C:\Python39\python.exe -m pip install -r requirements.txt
```

**Option 3: Use `py` Launcher (Windows)**
```powershell
py --version
py -m pip install -r requirements.txt
```

---

### ❌ Problem: pip Install Fails

**Symptoms:**
```
ERROR: Could not find a version that satisfies the requirement Flask==2.3.0
```

**Solutions:**

**Solution 1: Upgrade pip**
```powershell
python -m pip install --upgrade pip
```

**Solution 2: Install Without Version Pinning**
```powershell
# Install latest compatible versions
pip install Flask flask-cors flask-limiter
```

**Solution 3: Use Virtual Environment**
```powershell
# Create isolated environment
python -m venv venv

# Activate (PowerShell)
.\venv\Scripts\Activate.ps1

# If execution policy error:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Install dependencies
pip install -r requirements.txt
```

---

### ❌ Problem: Port 5000 Already in Use

**Symptoms:**
```
OSError: [Errno 48] Address already in use
```

**Solutions:**

**Solution 1: Kill Process on Port 5000**
```powershell
# Find process using port 5000
netstat -ano | findstr :5000

# Kill process (replace PID with actual number)
taskkill /PID <PID> /F

# Example:
taskkill /PID 12345 /F
```

**Solution 2: Use Different Port**
```python
# Edit backend/app.py, change last line:
if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Changed to 5001
```

Then update extension:
```javascript
// Edit extension/background.js
const API_URL = 'http://localhost:5001';
```

**Solution 3: Stop Conflicting Service**
```powershell
# Check if AirPlay or other service is using port 5000
Get-Process | Where-Object {$_.ProcessName -like "*air*"}

# Stop if found
Stop-Process -Name "AirPlayUIAgent" -Force
```

---

## Extension Problems

### ❌ Problem: Extension Doesn't Show in Chrome

**Symptoms:**
- Extension loaded but icon not visible
- No errors in `chrome://extensions/`

**Solutions:**

**Solution 1: Pin Extension**
1. Click puzzle piece icon (🧩) in Chrome toolbar
2. Find "Web Security Guardian"
3. Click pin icon 📌

**Solution 2: Check Manifest**
```json
// Verify extension/manifest.json has:
{
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  }
}
```

**Solution 3: Reload Extension**
1. Go to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click 🔄 **Reload** under Web Security Guardian

---

### ❌ Problem: "Errors" Badge on Extension

**Symptoms:**
- Red "Errors" badge on extension card
- Console shows errors

**Common Errors & Fixes:**

**Error: "Uncaught ReferenceError: chrome is not defined"**
```javascript
// FIX: Ensure code is in appropriate context
// popup.js / background.js can use chrome API
// content.js can only use limited chrome APIs

// Add error handling:
if (typeof chrome !== 'undefined' && chrome.runtime) {
  chrome.runtime.sendMessage({...});
} else {
  console.error('Chrome API not available');
}
```

**Error: "Cannot read property 'sendMessage' of undefined"**
```javascript
// FIX: Check message passing syntax
chrome.runtime.sendMessage(
  { action: 'getScanData' },
  (response) => {
    if (chrome.runtime.lastError) {
      console.error(chrome.runtime.lastError);
      return;
    }
    // Process response...
  }
);
```

**Error: "Extension context invalidated"**
- **Cause:** Extension was reloaded while page was open
- **Fix:** Refresh the webpage after reloading extension

---

### ❌ Problem: Popup Shows Blank/White Screen

**Symptoms:**
- Extension icon clickable but popup empty
- No content visible

**Solutions:**

**Solution 1: Check Console Errors**
1. Right-click extension icon
2. Select **Inspect popup**
3. Look for JavaScript errors in Console tab
4. Fix any reported errors

**Solution 2: Verify File Paths**
```javascript
// Check popup.html references correct files:
<script src="popup.js"></script>  // ✅ Correct
<script src="./popup.js"></script> // ❌ May fail in extensions
```

**Solution 3: Clear Extension Storage**
```javascript
// Open extension popup console and run:
chrome.storage.local.clear(() => {
  console.log('Storage cleared');
  location.reload();
});
```

---

### ❌ Problem: Risk Score Always Shows 0

**Symptoms:**
- Dashboard always displays "0 / High Risk"
- No extension risks detected

**Diagnosis:**

**Check 1: Are Extensions Installed?**
```javascript
// Open popup console and run:
chrome.management.getAll((extensions) => {
  console.log('Installed extensions:', extensions.length);
  console.log(extensions);
});
```

**Check 2: Is Calculation Running?**
```javascript
// Look for this in background.js console:
chrome.management.getAll((extensions) => {
  let totalRisk = 0;
  extensions.forEach(ext => {
    console.log(`${ext.name}: risk = ${ext.riskScore || 0}`);
    totalRisk += ext.riskScore || 0;
  });
  console.log('Average risk:', totalRisk / extensions.length);
});
```

**Fix:** If extensions exist but score is 0:
- Most extensions may be low-risk (Google Docs, Gmail, etc.)
- This is **correct behavior** if you only have trusted extensions
- Install a test extension with dangerous permissions to see score change

---

### ❌ Problem: Website Scan Shows "0 Trackers" Everywhere

**Symptoms:**
- All websites show 0 trackers
- Privacy score always 100

**Solutions:**

**Solution 1: Check Content Script Injection**
1. Open website (e.g., cnn.com)
2. Open DevTools (F12)
3. Go to Console tab
4. Type: `document.querySelector('body').dataset`
5. Should see `securityGuardianScanned: "true"`

**Solution 2: Verify Permissions**
```json
// Check manifest.json has:
{
  "host_permissions": ["<all_urls>"],
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"],
    "run_at": "document_idle"
  }]
}
```

**Solution 3: Test on Tracker-Heavy Site**
- Visit: `https://www.cnn.com` (100+ trackers)
- Visit: `https://www.forbes.com` (80+ trackers)
- If still 0, check content.js for errors

---

## Backend Server Issues

### ❌ Problem: Backend Won't Start

**Symptoms:**
```
python: can't open file 'app.py': [Errno 2] No such file or directory
```

**Solutions:**

**Solution 1: Navigate to Correct Directory**
```powershell
# Check current directory
$PWD

# Should be: C:\Users\...\web-security-guardian\backend
# If not, navigate:
cd backend
python app.py
```

**Solution 2: Use Absolute Path**
```powershell
cd C:\Users\prate\Desktop\web-security-guardian\backend
python app.py
```

---

### ❌ Problem: Import Errors in Backend

**Symptoms:**
```
ModuleNotFoundError: No module named 'flask'
```

**Solutions:**

**Solution 1: Install Dependencies**
```powershell
cd backend
pip install -r requirements.txt
```

**Solution 2: Check Virtual Environment**
```powershell
# If using venv, ensure it's activated
# Look for (venv) prefix in terminal:
# (venv) PS C:\...\backend>

# If not activated:
.\venv\Scripts\Activate.ps1
```

**Solution 3: Reinstall Specific Package**
```powershell
pip install Flask==2.3.0 --force-reinstall
```

---

### ❌ Problem: Database Errors

**Symptoms:**
```
sqlite3.OperationalError: table incidents already exists
```

**Solutions:**

**Solution 1: Delete Existing Database**
```powershell
cd backend
Remove-Item security_guardian.db
python app.py  # Will recreate database
```

**Solution 2: Use Different Database Name**
```python
# Edit app.py:
DATABASE = 'security_guardian_v2.db'
```

---

### ❌ Problem: CORS Errors

**Symptoms:**
```
Access to XMLHttpRequest at 'http://localhost:5000' blocked by CORS policy
```

**Solutions:**

**Solution 1: Verify flask-cors Installed**
```powershell
pip install flask-cors
```

**Solution 2: Check CORS Configuration**
```python
# In app.py, ensure this exists:
from flask_cors import CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})
```

**Solution 3: Extension Permissions**
```json
// In manifest.json, ensure:
{
  "host_permissions": [
    "http://localhost:5000/*",
    "https://localhost:5000/*"
  ]
}
```

---

## Network & Connectivity

### ❌ Problem: Extension Can't Connect to Backend

**Symptoms:**
- Extension works but data doesn't save
- Console error: `Failed to fetch`

**Solutions:**

**Solution 1: Verify Backend Running**
```powershell
# Should see:
# * Running on http://127.0.0.1:5000
# * Running on http://localhost:5000

# Test with curl:
curl http://localhost:5000/api/health
# Should return: {"status": "healthy"}
```

**Solution 2: Check Firewall**
```powershell
# Windows Firewall may block Python
# Allow Python through firewall:
# 1. Windows Security → Firewall & network protection
# 2. Allow an app through firewall
# 3. Find Python → Check both Private and Public
```

**Solution 3: Use 127.0.0.1 Instead of localhost**
```javascript
// Edit extension/background.js:
const API_URL = 'http://127.0.0.1:5000';
```

---

### ❌ Problem: Slow Website Scans

**Symptoms:**
- Extension takes 5-10 seconds to analyze page
- Browser feels sluggish

**Solutions:**

**Solution 1: Reduce Tracker Database Size**
```javascript
// content.js - Use curated subset for performance
const PRIORITY_TRACKERS = {
  'google-analytics.com': {...},
  'facebook.net': {...},
  'doubleclick.net': {...}
  // Keep only top 20 most common trackers
};
```

**Solution 2: Debounce Scanning**
```javascript
// content.js - Add delay to avoid multiple scans
let scanTimeout;
function triggerScan() {
  clearTimeout(scanTimeout);
  scanTimeout = setTimeout(() => {
    performActualScan();
  }, 500); // Wait 500ms after page settles
}
```

**Solution 3: Disable Heavy Checks**
```javascript
// Temporarily disable entropy analysis for testing:
function detectObfuscation() {
  return []; // Skip for now
}
```

---

## Performance Issues

### ❌ Problem: High CPU Usage

**Symptoms:**
- Chrome using 80%+ CPU
- Fan spinning loudly

**Solutions:**

**Solution 1: Limit Scan Frequency**
```javascript
// background.js - Reduce periodic scans
// Change from every 10 seconds to every 60 seconds:
setInterval(scanAllExtensions, 60000); // Was 10000
```

**Solution 2: Pause Background Scanning**
```javascript
// Comment out automatic scanning during development:
// setInterval(scanAllExtensions, 30000);
```

**Solution 3: Profile Performance**
```javascript
// Add timing logs:
console.time('websiteScan');
performWebsiteScan();
console.timeEnd('websiteScan');
```

---

### ❌ Problem: High Memory Usage

**Symptoms:**
- Chrome using 2GB+ RAM
- Browser crashes

**Solutions:**

**Solution 1: Clear Storage Periodically**
```javascript
// background.js - Clear old data
function cleanOldData() {
  chrome.storage.local.get(null, (data) => {
    const keys = Object.keys(data);
    if (keys.length > 100) {
      // Keep only recent 50 items
      const toDelete = keys.slice(0, -50);
      chrome.storage.local.remove(toDelete);
    }
  });
}

// Run daily
setInterval(cleanOldData, 24 * 60 * 60 * 1000);
```

**Solution 2: Reduce Data Stored**
```javascript
// Don't store full page content, only indicators:
chrome.storage.local.set({
  websiteScan: {
    url: url,
    rating: 'SAFE',
    riskScore: 85,
    // DON'T store: pageHTML, fullDOMSnapshot
  }
});
```

---

## Data & Storage Problems

### ❌ Problem: Data Not Persisting

**Symptoms:**
- Refresh extension and all data is gone
- Scans not saving

**Solutions:**

**Solution 1: Check Storage Permissions**
```json
// manifest.json must include:
{
  "permissions": ["storage"]
}
```

**Solution 2: Verify Storage Writes**
```javascript
// Add error handling:
chrome.storage.local.set({ key: value }, () => {
  if (chrome.runtime.lastError) {
    console.error('Storage error:', chrome.runtime.lastError);
  } else {
    console.log('Data saved successfully');
  }
});
```

**Solution 3: Check Storage Quota**
```javascript
// Check if storage is full:
chrome.storage.local.getBytesInUse(null, (bytes) => {
  console.log('Storage used:', bytes, 'bytes');
  // chrome.storage.local has 5MB limit
  if (bytes > 4.5 * 1024 * 1024) {
    console.warn('Storage nearly full!');
  }
});
```

---

### ❌ Problem: Incorrect Risk Classifications

**Symptoms:**
- YouTube marked as UNSAFE
- Pastebin showing as SAFE

**Solutions:**

**Solution 1: Update Whitelist**
```javascript
// content.js - Add missing legitimate domains:
const TRUSTED_DOMAINS = [
  'youtube.com',
  'youtu.be',
  'github.com',
  // Add more as needed
];
```

**Solution 2: Adjust Scoring Thresholds**
```javascript
// content.js - Tune classification cutoffs:
function classifyRisk(score) {
  if (score >= 70) return 'SAFE';
  if (score >= 40) return 'SUSPICIOUS';  // Was 30
  return 'UNSAFE';
}
```

**Solution 3: Report False Positives**
- Document URL and expected vs actual rating
- Check console for which indicators triggered
- Adjust specific heuristic thresholds

---

## Platform-Specific Issues

### 🪟 Windows Issues

#### Problem: Execution Policy Error
```
File cannot be loaded because running scripts is disabled
```

**Fix:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Problem: Path Too Long
```
The specified path, file name, or both are too long
```

**Fix:**
- Move project closer to C:\ drive root
- Example: `C:\projects\web-security-guardian`

---

### 🍎 macOS Issues

#### Problem: Python Not Found Despite Installation
**Fix:**
```bash
# Use python3 explicitly:
python3 --version
python3 -m pip install -r requirements.txt
python3 app.py
```

#### Problem: Permission Denied on Port
**Fix:**
```bash
# Don't use port 80 or 443 (requires sudo)
# Use port 5000 or higher
```

---

### 🐧 Linux Issues

#### Problem: Chrome Extension Not Loading
**Fix:**
```bash
# Chrome may be sandboxed, use:
google-chrome --disable-features=RendererCodeIntegrity

# Or install Chromium:
sudo apt install chromium-browser
```

#### Problem: Module Not Found Despite pip install
**Fix:**
```bash
# Ensure pip installs to correct Python version:
python3 -m pip install --user -r requirements.txt
```

---

## Advanced Debugging

### 🔍 Debugging Extension Logic

**Enable Verbose Logging:**
```javascript
// Add to background.js:
const DEBUG = true;

function log(...args) {
  if (DEBUG) {
    console.log('[WEB-SECURITY-GUARDIAN]', ...args);
  }
}

// Use throughout code:
log('Scanning extension:', extension.name);
log('Risk score calculated:', riskScore);
```

**Inspect Service Worker:**
1. Go to `chrome://extensions/`
2. Under Web Security Guardian, click **"service worker"** link
3. Opens DevTools for background.js context

**Inspect Content Script:**
1. Open target webpage
2. F12 → Console tab
3. Content script logs appear here

**Inspect Popup:**
1. Right-click extension icon
2. Select **"Inspect popup"**
3. Popup DevTools opens

---

### 🔍 Debugging Backend

**Enable Flask Debug Mode:**
```python
# app.py:
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
```

**Add Request Logging:**
```python
@app.before_request
def log_request():
    print(f'Request: {request.method} {request.path}')
    print(f'Data: {request.get_json()}')
```

**Test API Endpoints Manually:**
```powershell
# Test health check:
curl http://localhost:5000/api/health

# Test scan endpoint:
curl -X POST http://localhost:5000/api/scan `
  -H "Content-Type: application/json" `
  -d '{"extensionName":"Test","riskScore":50}'
```

---

### 🔍 Network Debugging

**Check Request Details:**
1. Open DevTools (F12)
2. Network tab
3. Filter: "Fetch/XHR"
4. Click request → Preview tab to see response

**Common Network Errors:**

| Error | Meaning | Fix |
|-------|---------|-----|
| `ERR_CONNECTION_REFUSED` | Backend not running | Start backend server |
| `ERR_NAME_NOT_RESOLVED` | Wrong URL | Check API_URL in background.js |
| `403 Forbidden` | CORS issue | Check flask-cors configuration |
| `500 Internal Server Error` | Backend crash | Check backend console for Python errors |

---

## 🆘 Still Having Issues?

### Diagnostic Checklist

Run through this checklist and note which steps fail:

```powershell
# 1. Python installed?
python --version
# Expected: Python 3.8.0 or higher

# 2. Dependencies installed?
pip list | Select-String "Flask"
# Expected: Flask, flask-cors, flask-limiter

# 3. Backend starts?
cd backend; python app.py
# Expected: "Running on http://localhost:5000"

# 4. API responds?
curl http://localhost:5000/api/health
# Expected: {"status":"healthy"}

# 5. Extension loads?
# Go to chrome://extensions/
# Expected: Web Security Guardian with no errors

# 6. Extension has permissions?
# Check manifest.json has: storage, tabs, webRequest, etc.

# 7. Content script runs?
# Open any website, F12 console, type: document.querySelector('body').dataset
# Expected: securityGuardianScanned: "true"
```

### Get Help

**Collect This Info When Reporting Issues:**

1. **Environment:**
   - OS: Windows/macOS/Linux (version?)
   - Chrome version: `chrome://version/`
   - Python version: `python --version`

2. **Error Messages:**
   - Extension errors: `chrome://extensions/` → "Errors"
   - Backend errors: Copy from terminal
   - Browser console: F12 → Console tab

3. **Steps to Reproduce:**
   - What you did
   - What you expected
   - What actually happened

4. **Screenshots:**
   - Extension popup state
   - Error messages
   - Console logs

**Where to Get Help:**
- GitHub Issues: https://github.com/pyush-nandan/HackHatch/issues
- Project README: `README.md`
- Documentation: All `*.md` files in project root

---

## 📚 Related Documentation

- **Setup Guide:** `SETUP_GUIDE.md` - Initial installation
- **Testing Guide:** `TESTING_GUIDE.md` - Feature validation
- **Security Fixes:** `SECURITY_FIXES.md` - Known vulnerabilities
- **Workflow Docs:** `WORKFLOW_DOCUMENTATION.md` - Architecture details

---

**Document Version:** 2.0.0  
**Maintainer:** Web Security Guardian Team  
**Last Review:** November 23, 2025

If this guide doesn't solve your issue, please file a detailed bug report with diagnostic output!
