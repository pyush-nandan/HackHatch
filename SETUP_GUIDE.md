# 🛡️ STEP-BY-STEP SETUP GUIDE
# Web Security Guardian - Complete Installation Walkthrough

## 📋 TABLE OF CONTENTS
1. [Install Prerequisites](#step-1-install-prerequisites)
2. [Get the Project Files](#step-2-get-the-project-files)
3. [Setup Backend Server](#step-3-setup-backend-server)
4. [Install Browser Extension](#step-4-install-browser-extension)
5. [Open Admin Dashboard](#step-5-open-admin-dashboard)
6. [Test Everything](#step-6-test-everything)
7. [Troubleshooting](#troubleshooting)

---

## STEP 1: Install Prerequisites

### A) Install Python

**Windows:**
1. Go to https://www.python.org/downloads/
2. Click the big yellow "Download Python 3.x" button
3. Run the downloaded installer (e.g., `python-3.11.0-amd64.exe`)
4. ⚠️ **CRITICAL**: Check the box that says "Add Python to PATH"
5. Click "Install Now"
6. Wait for installation to complete (2-3 minutes)
7. Click "Close"

**Verify Python Installation:**
1. Press `Windows Key + R`
2. Type: `powershell`
3. Press Enter
4. Type: `python --version`
5. You should see: `Python 3.11.x` (or similar)
6. If you see an error, restart your computer and try again

---

### B) Install Google Chrome

1. Go to https://www.google.com/chrome/
2. Click "Download Chrome"
3. Run the installer
4. Follow the prompts
5. Chrome will open automatically when done

---

## STEP 2: Get the Project Files

### Option A: If you already have the folder

✅ Your project is already at: `c:\Users\prate\Desktop\web-security-guardian`

**Verify it has these folders:**
1. Open File Explorer
2. Navigate to `c:\Users\prate\Desktop\web-security-guardian`
3. You should see:
   - `backend` folder
   - `dashboard` folder
   - `extension` folder
   - `README.md` file

✅ If you see these, skip to **Step 3**

---

### Option B: If you need to create it from scratch

All files have already been created in your workspace! Just proceed to the next step.

---

## STEP 3: Setup Backend Server

### A) Open PowerShell in Backend Folder

**Method 1 (Easy):**
1. Open File Explorer
2. Navigate to `c:\Users\prate\Desktop\web-security-guardian\backend`
3. Click in the address bar (where it shows the path)
4. Type: `powershell`
5. Press Enter
6. A blue PowerShell window opens

**Method 2 (Alternative):**
1. Press `Windows Key + R`
2. Type: `powershell`
3. Press Enter
4. Type: `cd c:\Users\prate\Desktop\web-security-guardian\backend`
5. Press Enter

---

### B) Install Python Dependencies

In PowerShell, type these commands one by one:

```powershell
# Install Flask and dependencies
pip install flask flask-cors
```

**What you should see:**
```
Collecting flask
  Downloading flask-3.0.0-py3-none-any.whl
...
Successfully installed flask-3.0.0 flask-cors-4.0.0 ...
```

⏱️ **Time**: 30-60 seconds

❌ **If you see an error:**
- Try: `python -m pip install flask flask-cors`
- Or: `py -m pip install flask flask-cors`

---

### C) Start the Backend Server

Still in PowerShell (in the `backend` folder), type:

```powershell
python app.py
```

**What you should see:**
```
==================================================
🛡️  Web Security Guardian API Server
==================================================
Server running on: http://localhost:5000

Endpoints:
  POST   /api/report_risk      - Receive risk reports
  GET    /api/dashboard_data   - Get all incidents
  GET    /api/stats            - Get statistics
  POST   /api/clear_data       - Clear all data

Press Ctrl+C to stop
==================================================
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.x.x:5000
```

✅ **SUCCESS!** Your backend is running!

⚠️ **IMPORTANT**: 
- **DO NOT CLOSE THIS WINDOW!** Keep it open while testing
- The server must be running for the extension and dashboard to work
- You should see this window in the background while using the app

---

### D) Test the Backend

**Keep the PowerShell window open**, and open a new browser window:

1. Open Chrome
2. Type in address bar: `http://localhost:5000`
3. Press Enter

**You should see:**
```json
{
  "status": "running",
  "service": "Web Security Guardian API",
  "version": "1.0.0",
  ...
}
```

✅ **Backend is working!**

---

## STEP 4: Install Browser Extension

### A) Open Chrome Extensions Page

**Method 1:**
1. Open Chrome
2. Type in address bar: `chrome://extensions/`
3. Press Enter

**Method 2:**
1. Open Chrome
2. Click the three dots (⋮) in top-right corner
3. Click "Extensions"
4. Click "Manage Extensions"

---

### B) Enable Developer Mode

1. Look at the **top-right corner** of the Extensions page
2. Find the toggle switch labeled "Developer mode"
3. Click it to turn it **ON** (it should turn blue)

✅ You should now see three new buttons: "Load unpacked", "Pack extension", "Update"

---

### C) Load the Extension

1. Click the **"Load unpacked"** button (top-left)
2. A file browser window opens
3. Navigate to: `c:\Users\prate\Desktop\web-security-guardian\extension`
4. Select the **`extension`** folder (don't go inside it)
5. Click **"Select Folder"** button

---

### D) Verify Extension Loaded

You should see a new card appear on the page:

```
🛡️ Web Security Guardian
Your Browser's Security Antivirus - Real-time extension...
Version 1.0.0
ID: abcdefgh...
```

✅ **Extension installed successfully!**

---

### E) Pin the Extension (Optional but Recommended)

1. Look at the top-right of Chrome (next to the address bar)
2. Click the puzzle piece icon (Extensions)
3. Find "Web Security Guardian" in the list
4. Click the **pin icon** next to it
5. The 🛡️ icon now appears in your toolbar

---

### F) Test the Extension

1. Click the **🛡️ icon** in your Chrome toolbar
2. A popup should appear with:
   - A loading spinner (brief)
   - Then a security score (0-100)
   - Current site information
   - List of installed extensions

✅ **Extension is working!**

❌ **If you see "Failed to connect" or errors:**
- Make sure the backend server is still running (check the PowerShell window from Step 3)
- Restart Chrome
- Try clicking the extension icon again

---

## STEP 5: Open Admin Dashboard

### A) Open the Dashboard File

**Method 1 (Easy):**
1. Open File Explorer
2. Navigate to: `c:\Users\prate\Desktop\web-security-guardian\dashboard`
3. Find `dashboard.html`
4. **Double-click** it

Chrome should open automatically with the dashboard.

**Method 2 (Alternative):**
1. Open Chrome
2. Press `Ctrl + O` (that's the letter O)
3. Navigate to: `c:\Users\prate\Desktop\web-security-guardian\dashboard`
4. Select `dashboard.html`
5. Click "Open"

---

### B) Verify Dashboard Loads

You should see:

```
🛡️ Web Security Guardian
Admin Dashboard - Real-time Security Monitoring

[Statistics Cards]
Total Employees Monitored: 0
High Risk Incidents: 0
...

[Top Risky Extensions]
[Top Risky Employees]
[All Incidents Table]
```

✅ **Dashboard loaded successfully!**

❌ **If you see "Failed to Connect":**
- The backend server might not be running
- Go back to Step 3 and start the server
- Click "Try Again" on the dashboard

---

## STEP 6: Test Everything

Now let's make sure everything works together!

### A) Generate Test Data

1. **Click the extension icon** (🛡️) in Chrome toolbar
2. The extension scans your installed extensions
3. Wait 2-3 seconds

---

### B) Check the Dashboard

1. Go to your dashboard tab
2. Click **🔄 Refresh Data** button (top-right)
3. You should see:
   - Statistics updated (Total Employees: 1, Incidents: X)
   - Your extensions listed in "Top Risky Extensions"
   - Your employee ID in "Top Risky Employees"
   - Incidents in the table at the bottom

✅ **Full system working!**

---

### C) Test Website Scanning

1. Open a new Chrome tab
2. Visit: `http://example.com` (HTTP, not HTTPS)
3. Click the extension icon (🛡️)
4. You should see:
   - Security score decreased
   - Warning: "⚠️ Unencrypted connection (HTTP)"
   - Current Site shows "HTTP" in red badge

---

### D) Test Risk Filtering

1. Go back to dashboard tab
2. Look at the "All Incidents" section
3. Click filter buttons:
   - **All** - Shows all incidents
   - **High Risk** - Shows only high-risk extensions
   - **Medium Risk** - Shows medium-risk
   - **Low Risk** - Shows low-risk

✅ **Filtering works!**

---

## 🎉 SUCCESS!

You now have a **fully functional** Web Security Guardian system!

### What You Built:
- ✅ Backend API server (Python/Flask)
- ✅ Chrome extension (real-time scanning)
- ✅ Admin dashboard (web interface)
- ✅ Risk scoring algorithm
- ✅ Live data flow between all components

---

## 🚀 How to Use for Your Hackathon Demo

### Before the Demo:

1. **Start the backend:**
   ```powershell
   cd c:\Users\prate\Desktop\web-security-guardian\backend
   python app.py
   ```
   (Keep this window open)

2. **Open Chrome** with the extension installed

3. **Open the dashboard** in a Chrome tab

4. **Visit a few websites** to generate data

5. **Click the extension icon** to trigger scans

6. **Refresh the dashboard** to show live data

---

### During the Demo:

**Recommended flow:**

1. **Show the extension** (1 minute)
   - Click icon
   - Explain security score
   - Show extension list
   - Visit HTTP site to show score drop

2. **Show the dashboard** (2 minutes)
   - Statistics overview
   - Top risky extensions
   - Filter incidents
   - Click refresh to show real-time updates

3. **Explain business value** (1 minute)
   - Problem: 67% of extensions are risky
   - Solution: Real-time monitoring
   - Pricing: $5-10/employee/month

4. **Q&A** (1 minute)

---

## 🛠️ TROUBLESHOOTING

### Problem: "python is not recognized"

**Solution:**
1. Restart your computer
2. Open PowerShell again
3. Try: `py --version` instead of `python --version`
4. If still not working, reinstall Python and **check "Add to PATH"**

---

### Problem: "pip is not recognized"

**Solution:**
```powershell
python -m pip install flask flask-cors
```

---

### Problem: Backend shows "Address already in use"

**Solution:**
1. Another program is using port 5000
2. Press `Ctrl + C` in the PowerShell window
3. Wait 5 seconds
4. Run `python app.py` again

**OR change the port:**
1. Open `backend/app.py` in Notepad
2. Find the last line: `app.run(debug=True, port=5000, host='0.0.0.0')`
3. Change `5000` to `5001`
4. Save file
5. Also update extension and dashboard to use `http://localhost:5001`

---

### Problem: Extension shows "Failed to load"

**Solution:**
1. Go to `chrome://extensions/`
2. Find Web Security Guardian
3. Click "Remove"
4. Click "Load unpacked" again
5. Select the `extension` folder
6. Make sure backend is running

---

### Problem: Dashboard shows "No incidents found"

**Solution:**
1. Make sure backend is running (check PowerShell window)
2. Click the extension icon in Chrome to trigger a scan
3. Wait 5 seconds
4. Click 🔄 Refresh Data on dashboard

---

### Problem: Extension icons not showing

**Solution:**
This is **not critical** for the hackathon. Chrome will use a default icon. 

**If you want custom icons:**
1. Download a shield emoji PNG from https://emojipedia.org/shield/
2. Resize to 16x16, 48x48, and 128x128 pixels (use Paint or online tool)
3. Save as `icon16.png`, `icon48.png`, `icon128.png`
4. Place in `extension/icons/` folder
5. Go to `chrome://extensions/` and click ↻ reload

---

### Problem: Dashboard loads but shows 0 for everything

**Solution:**
This means no data has been sent yet. 

1. Click the extension icon to trigger a scan
2. Wait 3-5 seconds
3. Go to dashboard
4. Click 🔄 Refresh Data

---

## 📝 Quick Reference Commands

### Start Backend
```powershell
cd c:\Users\prate\Desktop\web-security-guardian\backend
python app.py
```

### Stop Backend
Press `Ctrl + C` in the PowerShell window

### Test Backend
Open browser: `http://localhost:5000`

### Clear Demo Data
Open browser: `http://localhost:5000/api/clear_data` (POST request)

Or use PowerShell:
```powershell
Invoke-WebRequest -Uri http://localhost:5000/api/clear_data -Method POST
```

---

## 🎯 Next Steps

Now that everything works:

1. **Practice your demo** (use `DEMO_SCRIPT.md`)
2. **Prepare answers** to common questions
3. **Test on different websites** to generate varied data
4. **Take screenshots** for your presentation
5. **Rehearse timing** (aim for 4-5 minutes)

---

## 💡 Pro Tips for the Hackathon

1. **Keep backend running** throughout the event
2. **Install 5-10 Chrome extensions** before demo to show variety
3. **Have HTTP and HTTPS sites bookmarked** for quick comparison
4. **Clear data between practice runs** to start fresh
5. **Zoom in** when showing the UI (Ctrl + Plus)
6. **Speak confidently** - you built something impressive!

---

## 🏆 You're Ready to Win!

You have a **complete, working product**. Most hackathon projects are just mockups or ideas. You built something **real**.

**Confidence is key:**
- You understand the problem
- You built the solution
- You can demo it live
- You know the business model

Go win that hackathon! 🚀🛡️

---

**Need help during the event?**
- Re-read this guide
- Check README.md for technical details
- Review DEMO_SCRIPT.md for presentation tips
- Test each component individually

**Good luck! 🎉**
