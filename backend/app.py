"""
XSS Shield Pro - Main Flask Application
Entry point for the backend server
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from full_scanner import FullScanner
import os

from full_scanner import FullScanner
from csp_builder import CSPBuilder
from sanitizer import Sanitizer
from report_generator import ReportGenerator


# ── App Setup ───────────────────────────────────────────────
app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend'),
    static_url_path=''
)
CORS(app)  # Allow frontend to call backend

scanner = FullScanner()
csp_builder   = CSPBuilder()
sanitizer     = Sanitizer()
report_gen    = ReportGenerator()


# ── Routes ──────────────────────────────────────────────────

@app.route("/scan-site", methods=["POST"])
def scan_site():

    data = request.json
    url = data.get("url")

    results = scanner.scan_site(url)

    return jsonify(results)
@app.route('/')
def index():
    """Serve the main frontend page"""
    return send_from_directory(app.static_folder, 'index.html')


@app.route("/api/scan", methods=["POST"])
def scan():

    data = request.json
    raw_input = data.get("input")

    result = scanner.scan(raw_input)

    # generate PDF report
    scanner.report.generate([{
        "url": raw_input,
        "xss": result
    }])

    return jsonify(result)


@app.route('/api/sanitize', methods=['POST'])
def sanitize_input():
    """
    POST /api/sanitize
    Body: { "input": "<raw html>" }
    Returns all 3 sanitization strategies
    """
    data = request.get_json(silent=True) or {}
    raw = data.get('input', '')
    return jsonify(sanitizer.sanitize_all(raw))


@app.route('/api/csp', methods=['POST'])
def build_csp():
    """
    POST /api/csp
    Body: { "options": { "inline": true, "eval": true, ... } }
    Returns generated CSP header string
    """
    data = request.get_json(silent=True) or {}
    options = data.get('options', {})
    return jsonify(csp_builder.build(options))


@app.route('/api/report', methods=['POST'])
def generate_report():
    """
    POST /api/report
    Body: { "scan_results": {...} }
    Returns formatted text report
    """
    data = request.get_json(silent=True) or {}
    scan_results = data.get('scan_results', {})
    return jsonify(report_gen.generate(scan_results))


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'rules': scanner.rule_count()})


# ── Run ─────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n  XSS Shield Pro — Backend Server")
    print("  ─────────────────────────────────")
    print("  API running at http://localhost:5000")
    print("  Frontend at  http://localhost:5000\n")
    app.run(debug=True, port=5000)
