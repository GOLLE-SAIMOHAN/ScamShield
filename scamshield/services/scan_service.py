"""Scan orchestration service."""

from time import perf_counter
from uuid import uuid4

from flask import current_app
from werkzeug.datastructures import FileStorage

from scamshield.ai.detector import analyze_content, analyze_media_file, analyze_url
from scamshield.analysis.explanation_service import ExplanationService
from scamshield.detection.engine import ScanEngine
from scamshield.repositories.history_repository import HistoryRepository
from scamshield.services.threat_intelligence_service import ThreatIntelligenceService


class ScanService:
    """Coordinate URL, content, file, and media analysis workflows."""

    @staticmethod
    def get_scan_history(
        page: int = 1,
        per_page: int = 10,
        search: str = "",
        classification: str = "",
    ) -> dict:
        """Return paginated scan history."""
        return HistoryRepository.list_history_page(
            page=page,
            per_page=per_page,
            search=search,
            classification=classification,
        )

    @staticmethod
    def delete_scan(scan_id: str) -> bool:
        """Delete a scan history entry."""
        return HistoryRepository.delete_scan(scan_id)

    @staticmethod
    def check_url(url: str) -> dict:
        """Analyze a URL and persist scan history."""
        result = analyze_url(url)
        HistoryRepository.add_history(
            "URL",
            url,
            result["risk_level"],
            result["risk_score"],
            result,
        )
        return result

    @staticmethod
    def scan_url(url: str, user_id: str | None = None) -> dict:
        """Analyze a URL with the modular scan engine and persist the result."""
        started_at = perf_counter()
        domain = ThreatIntelligenceService.extract_domain(url)
        existing_threat = ThreatIntelligenceService.get_domain(domain)
        result = ScanEngine().analyze_url(url)
        threat_summary = ThreatIntelligenceService.record_url_scan(
            domain,
            result,
            existing_threat,
        )
        explanation = ExplanationService().explain(result, threat_summary)
        scan_id = f"scan-{uuid4()}"
        HistoryRepository.create_url_scan(
            {
                "scan_id": scan_id,
                "user_id": user_id,
                "url": result["url"],
                "risk_score": result["risk_score"],
                "classification": result["classification"],
                "reasons": result["reasons"],
                "confidence": result["confidence"],
                "threat_intelligence": threat_summary,
                "threat_summary": explanation,
            }
        )
        duration_ms = (perf_counter() - started_at) * 1000
        current_app.logger.info(
            "url_scan_completed scan_id=%s user_id=%s risk_score=%s duration_ms=%.2f",
            scan_id,
            user_id,
            result["risk_score"],
            duration_ms,
        )
        return {
            "scan_id": scan_id,
            **result,
            "threat_intelligence": threat_summary,
            "threat_summary": explanation,
        }

    @staticmethod
    def analyze_content(content: str, content_type: str) -> dict:
        """Analyze text content and persist scan history."""
        result = analyze_content(content, content_type)
        result["threat_summary"] = ExplanationService().explain(result, {})
        HistoryRepository.add_history(
            content_type.title(),
            content[:90],
            result["risk_level"],
            result["scam_probability"],
            result,
        )
        return result

    @staticmethod
    def analyze_file(uploaded_file: FileStorage, content_type: str, transcript: str) -> dict:
        """Analyze an uploaded file using supplied or fallback text."""
        filename = uploaded_file.filename or "uploaded file"
        file_size = len(uploaded_file.read())
        uploaded_file.seek(0)

        normalized_type = (content_type or "file").strip() or "file"
        analysis_text = transcript.strip() or (
            f"Uploaded {normalized_type} file named {filename}. "
            "No extracted text or transcript was provided for AI risk analysis."
        )
        result = analyze_content(analysis_text, normalized_type)
        result["file"] = {
            "name": filename,
            "size_bytes": file_size,
            "content_type": uploaded_file.mimetype,
        }
        result["processing_note"] = (
            "File upload is enabled. Add Tesseract OCR for screenshot text extraction "
            "and Whisper/OpenAI speech-to-text for automatic audio transcription."
        )
        result["threat_summary"] = ExplanationService().explain(result, {})

        HistoryRepository.add_history(
            normalized_type.title(),
            filename,
            result["risk_level"],
            result["scam_probability"],
            result,
        )
        return result

    @staticmethod
    def analyze_media(
        uploaded_file: FileStorage,
        width: int | None = None,
        height: int | None = None,
        duration: float | None = None,
    ) -> dict:
        """Analyze an uploaded image or video and persist scan history."""
        filename = uploaded_file.filename or "uploaded-media"
        file_bytes = uploaded_file.read()
        file_size = len(file_bytes)
        uploaded_file.seek(0)

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

        media_risk = "High"
        if result["ai_likelihood"] < 45:
            media_risk = "Low"
        elif result["ai_likelihood"] < 70:
            media_risk = "Medium"

        HistoryRepository.add_history(
            "Media Forensics",
            filename,
            media_risk,
            result["ai_likelihood"],
            result,
        )
        return result
