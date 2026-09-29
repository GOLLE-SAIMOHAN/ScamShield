"""HTTP controllers for scanning workflows."""

from flask import g, jsonify, request

from scamshield.repositories.history_repository import HistoryRepository
from scamshield.services.scan_service import ScanService
from scamshield.validators.scan_validator import (
    validate_content_payload,
    validate_file_upload,
    validate_media_upload,
    validate_url_payload,
)


def check_url():
    """Analyze a submitted URL."""
    payload = validate_url_payload(request.get_json(silent=True) or {})
    return jsonify(ScanService.check_url(payload["url"]))


def scan_url():
    """Analyze a URL using the modular scan engine."""
    payload = validate_url_payload(request.get_json(silent=True) or {})
    user = getattr(g, "current_user", {}) or {}
    return jsonify(ScanService.scan_url(payload["url"], user.get("user_id")))


def scan_history():
    """Return paginated scan history."""
    result = ScanService.get_scan_history(
        page=request.args.get("page", 1, type=int),
        per_page=request.args.get("per_page", 10, type=int),
        search=request.args.get("search", ""),
        classification=request.args.get("classification", ""),
    )
    return jsonify({"success": True, "data": result})


def delete_scan(scan_id: str):
    """Delete a scan history entry with authorization check."""
    user = getattr(g, "current_user", {}) or {}
    user_id = user.get("user_id")
    role = user.get("role", "user")

    scan = HistoryRepository.find_by_scan_id(scan_id)
    if not scan:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Not Found",
                    "message": "Scan history entry was not found",
                }
            ),
            404,
        )

    scan_owner = scan.get("user_id")
    if role != "admin" and scan_owner and scan_owner != user_id:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Forbidden",
                    "message": "Permission denied: Cannot delete another user's scan",
                }
            ),
            403,
        )

    if not ScanService.delete_scan(scan_id):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Not Found",
                    "message": "Scan history entry was not found",
                }
            ),
            404,
        )
    return jsonify({"success": True, "message": "Scan history entry deleted"})


def analyze_scam():
    """Analyze submitted text content."""
    payload = validate_content_payload(request.get_json(silent=True) or {})
    return jsonify(ScanService.analyze_content(payload["content"], payload["content_type"]))


def analyze_file():
    """Analyze an uploaded file with optional transcript text."""
    uploaded_file = validate_file_upload(request.files.get("file"))
    result = ScanService.analyze_file(
        uploaded_file=uploaded_file,
        content_type=request.form.get("content_type", "file"),
        transcript=request.form.get("transcript", ""),
    )
    return jsonify(result)


def analyze_media():
    """Analyze an uploaded image or video."""
    uploaded_file = validate_media_upload(request.files.get("file"))
    result = ScanService.analyze_media(
        uploaded_file=uploaded_file,
        width=request.form.get("width", type=int),
        height=request.form.get("height", type=int),
        duration=request.form.get("duration", type=float),
    )
    return jsonify(result)
