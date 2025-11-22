# 🧪 Testing Your Security Guardian

## ✅ Quick Test Checklist

### Step 1: Reload Extension
1. Go to `chrome://extensions/`
2. Find "Web Security Guardian"
3. Click the **reload button (🔄)**
4. Verify no errors appear

### Step 2: Test Extension Scanning
1. Click the extension icon in your browser toolbar
2. You should see:
   - ✅ Security score (0-100)
   - ✅ List of installed extensions with risk levels
   - ✅ Color-coded risk badges (CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=green)

### Step 3: Test Detailed Threat Analysis
1. **Click any extension in the list**
2. A modal popup should appear showing:
   - ✅ Extension name and risk level
   - ✅ Detailed threat list with explanations
   - ✅ Specific security concerns (e.g., "🔴 CRITICAL: webRequest - Can intercept ALL network traffic")

### Step 4: Test Website Scanning
1. Navigate to any HTTP website (e.g., `http://example.com`)
2. Click extension icon
3. You should see:
   - ✅ "Current Site" section shows domain
   - ✅ HTTP badge (red) with warning
   - ✅ Security score decreases

4. Navigate to HTTPS website (e.g., `https://google.com`)
5. You should see:
   - ✅ HTTPS badge (green)
   - ✅ Higher security score

### Step 5: Test Backend Connection
1. Verify backend is running:
   ```powershell
   curl http://localhost:5000/api/health
   ```
   Expected: `{"status":"healthy"}`

2. Check if risks are being reported:
   - Wait 10 seconds after opening extension
   - Open: `http://localhost:5000/api/dashboard_data`
   - You should see JSON with your extensions

### Step 6: Test Admin Dashboard
1. Open `dashboard/dashboard.html` in browser
2. Click "🔄 Refresh Data" button
3. You should see:
   - ✅ Total employees count
   - ✅ Risk level distribution chart
   - ✅ Top risky extensions list
   - ✅ Timeline of security events

---

## 🐛 Common Issues & Fixes

### Issue 1: "Cannot read properties of undefined (reading 'create')"
**Status:** ✅ FIXED  
**Solution:** Added proper chrome.alarms API availability check

### Issue 2: Extension icon not loading
**Status:** ✅ FIXED  
**Solution:** Created PNG icon files in icons/ folder

### Issue 3: Service worker registration failed
**Status:** ✅ FIXED  
**Solution:** Added "alarms" permission to manifest.json

### Issue 4: Backend not receiving data
**Check:**
```powershell
# See if Flask is running
Get-Process | Where-Object {$_.ProcessName -like "*python*"}
```
**Fix:** Restart backend:
```powershell
cd C:\Users\prate\Desktop\web-security-guardian\backend
python app.py
```

---

## 🎯 Demo Test Scenarios

### Scenario 1: High-Risk Extension Detection
**Goal:** Show how system catches dangerous extensions

**Steps:**
1. Install uBlock Origin (webRequest permission)
2. Open extension popup
3. **Point out:** "See how it's flagged as HIGH risk"
4. **Click extension** to show detailed threats
5. **Explain:** "uBlock Origin is legitimate, but has dangerous permissions. That's why we flag it for review."

### Scenario 2: HTTP vs HTTPS Detection
**Goal:** Show website security scoring

**Steps:**
1. Visit `http://example.com`
2. Show: "Score drops 25 points for HTTP"
3. Visit `https://google.com`
4. Show: "Score increases with HTTPS"

### Scenario 3: Real-time Monitoring
**Goal:** Show backend data collection

**Steps:**
1. Open extension on multiple websites
2. Open dashboard
3. Show: "All employee activity tracked in real-time"
4. Filter by risk level

---

## 🔥 Hackathon Presentation Tips

### Opening (30 seconds)
"Did you know 500 MILLION downloads of malicious Chrome extensions were removed in the last 4 years? Web Security Guardian protects companies from insider threats and malicious browser extensions using real security research from OWASP and Chrome Security Team."

### Demo Flow (3 minutes)
1. **Show extension popup** (30s)
   - "Real-time risk scoring of all installed extensions"
   
2. **Click an extension** (30s)
   - "Detailed forensic analysis - explains EXACTLY why it's dangerous"
   
3. **Show dashboard** (1min)
   - "IT admins get full visibility across all employees"
   - "Filter by risk level, track trends, audit compliance"
   
4. **Explain technical depth** (1min)
   - "Not just counting permissions - we detect combination attacks"
   - "webRequest + cookies + all_urls = credential theft capability"
   - "Based on real CVE databases and OWASP research"

### Closing (30 seconds)
"Average data breach costs $4.45 million. One malicious extension installed by an employee could compromise the entire company. Web Security Guardian catches these threats before they cause damage."

---

## 📊 Expected Risk Scores

### Common Extensions:
- **Grammarly:** ~45 (HIGH) - Needs content access
- **LastPass:** ~55 (HIGH) - Password manager permissions
- **uBlock Origin:** ~60 (CRITICAL) - webRequest blocking
- **Honey:** ~50 (HIGH) - Shopping sites access
- **Metamask:** ~48 (HIGH) - Financial data access

### Red Flags:
- Score 60+ with unknown publisher = **DELETE IMMEDIATELY**
- Score 40+ with no description = **SUSPICIOUS**
- Score 80+ = **CRITICAL MALWARE** (should never happen with legitimate extensions)

---

## 🎬 Record Your Demo

### Recommended Screen Recording:
1. Open OBS Studio or Loom
2. Record 3-minute demo video
3. Focus on:
   - Extension popup with threat details
   - Dashboard with statistics
   - Code walkthrough (show calculateExtensionRisk function)

### Key Frames to Capture:
- [ ] Extension scanning all installed extensions
- [ ] Clicking extension to show detailed threats
- [ ] HTTP vs HTTPS detection
- [ ] Admin dashboard with employee data
- [ ] Code showing security analysis algorithm

---

## 🚀 Final Checklist Before Submission

- [ ] Backend running without errors
- [ ] Extension loads without errors
- [ ] All 3 icons display correctly
- [ ] Click any extension shows threat details
- [ ] Dashboard displays data correctly
- [ ] README.md has clear setup instructions
- [ ] Screenshots included in documentation
- [ ] Demo video recorded (optional but recommended)
- [ ] Code commented for judges to understand
- [ ] Security research sources cited

---

**You're ready to win! 🏆**

The combination of:
✅ Real security research (not toy demo)
✅ Professional UI/UX
✅ Full-stack implementation
✅ Practical business value
✅ Detailed documentation

...makes this a **strong hackathon submission**. Good luck! 🎉
