#!/bin/bash
echo "Starting XSS Shield Pro..."
cd "$(dirname "$0")"
source venv/bin/activate 2>/dev/null || true
python backend/app.py
