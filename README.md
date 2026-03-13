# XSS Shield Pro — Modular Setup Guide

## Quick Start (3 commands)
```
cd xss-shield-pro
pip install -r backend/requirements.txt
python backend/app.py
```
Then open: http://localhost:5000

---

## Full Step-by-Step Instructions

### Step 1 — Prerequisites

Install Python 3.8+ (check: `python --version`)
Install pip (comes with Python)

### Step 2 — Get the project

If you have the folder already, skip to Step 3.

```bash
# If cloning from git:
git clone https://github.com/yourname/xss-shield-pro.git
cd xss-shield-pro
```

### Step 3 — Create a virtual environment (recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 4 — Install dependencies

```bash
pip install -r backend/requirements.txt
```

### Step 5 — Run the server

```bash
python backend/app.py
```

You will see:
```
XSS Shield Pro — Backend Server
─────────────────────────────────
API running at http://localhost:5000
Frontend at  http://localhost:5000
```

### Step 6 — Open the app

Open your browser and go to: **http://localhost:5000**

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## API Endpoints (for developers)

| Method | Endpoint      | Body                          | Returns             |
|--------|---------------|-------------------------------|---------------------|
| POST   | /api/scan     | `{"input": "url or payload"}` | Full scan result    |
| POST   | /api/sanitize | `{"input": "raw html"}`       | 3 sanitized forms   |
| POST   | /api/csp      | `{"options": {...}}`          | CSP header + meta   |
| POST   | /api/report   | `{"scan_results": {...}}`     | Plain text report   |
| GET    | /api/health   | —                             | Status + rule count |

