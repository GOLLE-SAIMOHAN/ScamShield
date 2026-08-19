from datetime import datetime, timezone
import json
import os
import sqlite3
from flask import Flask, jsonify, render_template, request, session
from flask_cors import CORS

from detector import analyze_content, analyze_media_file, analyze_url


app = Flask(__name__, static_folder="frontend", template_folder="frontend", static_url_path="")
CORS(app)
app.secret_key = os.environ.get("SCAMSHIELD_SECRET_KEY", "scamshield-demo-secret")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scamshield.db")

SEED_REPORTS = [
    {
        "id": 1,
        "type": "UPI Fraud",
        "title": "Fake payment collect request",
        "location": "Hyderabad",
        "risk": "High",
        "status": "Verified",
        "created_at": "2026-05-25T10:30:00Z",
    }
]


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                location TEXT NOT NULL,
                risk TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                input TEXT NOT NULL,
                risk TEXT NOT NULL,
                score INTEGER NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            )
        """)

        count = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        if count == 0:
            db.executemany(
                """
                INSERT INTO reports (type, title, location, risk, status, created_at)
                VALUES (:type, :title, :location, :risk, :status, :created_at)
                """,
                SEED_REPORTS,
            )


def row_to_dict(row):
    return dict(row)


def add_history(kind, input_value, risk, score, details=None):
    with get_db() as db:
        db.execute(
            """
            INSERT INTO history (kind, input, risk, score, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                kind,
                input_value,
                risk,
                int(score),
                json.dumps(details or {}),
                utc_now(),
            ),
        )


def list_history(limit=8):
    with get_db() as db:
        rows = db.execute(
            "SELECT kind, input, risk, score, created_at FROM history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


def list_reports(limit=8):
    with get_db() as db:
        rows = db.execute(
            "SELECT id, type, title, location, risk, status, created_at FROM reports ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


init_db()


def is_authenticated():
    return bool(session.get("authenticated"))


@app.route("/api/auth-status")
def auth_status():
    return jsonify({"authenticated": is_authenticated(), "user": session.get("user")})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if email == "demo@scamshield.com" and password == "scamshield123":
        session["authenticated"] = True
        session["user"] = {"email": email, "name": "Demo Analyst"}
        return jsonify({"success": True, "message": "Signed in successfully"})

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check-url", methods=["POST"])
@app.route("/api/check-url", methods=["POST"])
def check_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = analyze_url(url)
    add_history("URL", url, result["risk_level"], result["risk_score"], result)
    return jsonify(result)


@app.route("/api/analyze", methods=["POST"])
def analyze_scam():
    data = request.get_json(silent=True) or {}
    content = data.get("content", "").strip()
    content_type = data.get("content_type", "message")

    if not content:
        return jsonify({"error": "Content is required"}), 400

    result = analyze_content(content, content_type)
    add_history(content_type.title(), content[:90], result["risk_level"], result["scam_probability"], result)
    return jsonify(result)


@app.route("/api/analyze-file", methods=["POST"])
def analyze_file():
    uploaded_file = request.files.get("file")
    content_type = request.form.get("content_type", "file")
    transcript = request.form.get("transcript", "").strip()

    if not uploaded_file:
        return jsonify({"error": "File is required"}), 400

    filename = uploaded_file.filename or "uploaded file"
    file_size = len(uploaded_file.read())
    uploaded_file.seek(0)

    analysis_text = transcript or (
        f"Uploaded {content_type} file named {filename}. "
        "No extracted text or transcript was provided for AI risk analysis."
    )
    result = analyze_content(analysis_text, content_type)
    result["file"] = {
        "name": filename,
        "size_bytes": file_size,
        "content_type": uploaded_file.mimetype,
    }
    result["processing_note"] = (
        "File upload is enabled. Add Tesseract OCR for screenshot text extraction "
        "and Whisper/OpenAI speech-to-text for automatic audio transcription."
    )

    add_history(content_type.title(), filename, result["risk_level"], result["scam_probability"], result)
    return jsonify(result)


@app.route("/api/analyze-media", methods=["POST"])
def analyze_media():
    uploaded_file = request.files.get("file")

    if not uploaded_file:
        return jsonify({"error": "Image or video file is required"}), 400

    filename = uploaded_file.filename or "uploaded-media"
    file_bytes = uploaded_file.read()
    file_size = len(file_bytes)
    uploaded_file.seek(0)

    width = request.form.get("width", type=int)
    height = request.form.get("height", type=int)
    duration = request.form.get("duration", type=float)

    result = analyze_media_file(
        filename=filename,
        mimetype=uploaded_file.mimetype,
        size_bytes=file_size,
        width=width,
        height=height,
        duration=duration,
        file_bytes=file_bytes,
    )
    result["file"] = {
        "name": filename,
        "size_bytes": file_size,
        "content_type": uploaded_file.mimetype,
    }

    media_risk = "High" if result["ai_likelihood"] >= 70 else "Medium" if result["ai_likelihood"] >= 45 else "Low"
    add_history("Media Forensics", filename, media_risk, result["ai_likelihood"], result)
    return jsonify(result)


@app.route("/api/report", methods=["POST"])
def report_scam():
    data = request.get_json(silent=True) or {}
    title = data.get("title", "").strip()
    scam_type = data.get("type", "Unknown").strip() or "Unknown"
    location = data.get("location", "Unknown").strip() or "Unknown"
    description = data.get("description", "").strip()

    if not title and not description:
        return jsonify({"error": "Report title or description is required"}), 400

    analysis = analyze_content(f"{title} {description}", scam_type)
    report = {
        "type": scam_type,
        "title": title or description[:60],
        "location": location,
        "risk": analysis["risk_level"],
        "status": "New",
        "created_at": utc_now(),
    }
    with get_db() as db:
        cursor = db.execute(
            """
            INSERT INTO reports (type, title, location, risk, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                report["type"],
                report["title"],
                report["location"],
                report["risk"],
                report["status"],
                report["created_at"],
            ),
        )
        report["id"] = cursor.lastrowid
    return jsonify({"report": report, "analysis": analysis}), 201


@app.route("/api/dashboard")
def dashboard():
    reports = list_reports()
    history = list_history()

    with get_db() as db:
        report_count = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        scan_count = db.execute("SELECT COUNT(*) FROM history").fetchone()[0]
        critical_reports = db.execute("SELECT COUNT(*) FROM reports WHERE risk = 'Critical'").fetchone()[0]
        verified_reports = db.execute("SELECT COUNT(*) FROM reports WHERE status = 'Verified'").fetchone()[0]

    return jsonify({
        "metrics": {
            "scans_today": max(128, scan_count + 128),
            "critical_threats": critical_reports,
            "community_reports": report_count,
            "verified_scams": verified_reports,
            "average_risk": 64 if report_count else 0,
            "protected_users": 18420,
        },
        "trend_series": [22, 28, 35, 31, 44, 52, 49, 63, 71, 68, 79, 86],
        "category_series": {
            "Phishing": 38,
            "UPI Fraud": 24,
            "Job Scam": 15,
            "OTP Fraud": 13,
            "Voice Scam": 10,
        },
        "heatmap": [
            {"city": "Hyderabad", "x": 58, "y": 61, "reports": 42, "risk": "High"},
            {"city": "Mumbai", "x": 35, "y": 69, "reports": 61, "risk": "Critical"},
            {"city": "Bengaluru", "x": 43, "y": 78, "reports": 36, "risk": "High"},
            {"city": "Delhi", "x": 48, "y": 38, "reports": 53, "risk": "Critical"},
            {"city": "Kolkata", "x": 72, "y": 55, "reports": 28, "risk": "Medium"},
        ],
        "threat_feed": [
            "Fake bank KYC links using shortened URLs",
            "WhatsApp job offers asking registration fees",
            "UPI collect requests pretending to be refunds",
            "AI voice calls claiming courier police cases",
        ],
        "reports": reports,
        "history": history,
    })


if __name__ == "__main__":
    app.run(debug=True)
