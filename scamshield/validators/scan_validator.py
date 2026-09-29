"""Validators for scanning requests."""

from io import BytesIO
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from scamshield.validators.exceptions import ValidationError

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

MAX_IMAGE_PIXELS = 100_000_000
MAX_IMAGE_DIMENSION = 10000

DISALLOWED_SIGNATURES = [
    b"MZ",
    b"\x7fELF",
    b"#!/",
    b"<?php",
    b"<script",
    b"<!DOCTYPE html",
    b"<html",
]

IMAGE_SIGNATURES = [
    b"\xff\xd8\xff",
    b"\x89PNG\r\n\x1a\n",
    b"GIF87a",
    b"GIF89a",
    b"BM",
]

VIDEO_SIGNATURES = [
    b"ftyp",
    b"\x1a\x45\xdf\xa3",
    b"RIFF",
]


def _is_disallowed_signature(header: bytes) -> bool:
    """Return True if header starts with executable or script signatures."""
    lowered = header.lower()
    for sig in DISALLOWED_SIGNATURES:
        if sig.lower() in lowered[:128]:
            return True
    return False


def _is_valid_media_signature(header: bytes) -> bool:
    """Check if header matches known image or video magic signatures."""
    for sig in IMAGE_SIGNATURES:
        if header.startswith(sig):
            return True
    if len(header) >= 12:
        if b"ftyp" in header[4:12]:
            return True
        if header.startswith(b"\x1a\x45\xdf\xa3"):
            return True
        if header.startswith(b"RIFF") and (b"WEBP" in header[8:16] or b"AVI " in header[8:16]):
            return True
    return False


def validate_url_payload(payload: dict) -> dict:
    """Validate URL analysis input."""
    url = (payload.get("url") or "").strip()
    if not url:
        raise ValidationError("URL is required")
    return {"url": url}


def validate_content_payload(payload: dict) -> dict:
    """Validate text analysis input."""
    content = (payload.get("content") or "").strip()
    content_type = (payload.get("content_type") or "message").strip() or "message"
    if not content:
        raise ValidationError("Content is required")
    return {"content": content, "content_type": content_type}


def validate_file_upload(uploaded_file: FileStorage | None) -> FileStorage:
    """Validate generic file upload input."""
    if not uploaded_file:
        raise ValidationError("File is required")

    raw_filename = uploaded_file.filename or ""
    if not raw_filename.strip():
        raise ValidationError("Filename is required")

    sanitized = secure_filename(raw_filename)
    if not sanitized:
        sanitized = "uploaded_file"
    uploaded_file.filename = sanitized

    header = uploaded_file.read(512)
    uploaded_file.seek(0)

    if not header:
        raise ValidationError("Uploaded file is empty")

    if _is_disallowed_signature(header):
        raise ValidationError("Executable or script files are strictly prohibited")

    return uploaded_file


def validate_media_upload(uploaded_file: FileStorage | None) -> FileStorage:
    """Validate image or video media upload input."""
    if not uploaded_file:
        raise ValidationError("Image or video file is required")

    raw_filename = uploaded_file.filename or ""
    if not raw_filename.strip():
        raise ValidationError("Filename is required")

    sanitized = secure_filename(raw_filename)
    if not sanitized:
        sanitized = "uploaded_media"
    uploaded_file.filename = sanitized

    header = uploaded_file.read(512)
    uploaded_file.seek(0)

    if not header:
        raise ValidationError("Uploaded media file is empty")

    if _is_disallowed_signature(header):
        raise ValidationError("Executable or script content disguised as media is prohibited")

    if not _is_valid_media_signature(header):
        raise ValidationError("Invalid or unsupported media file format")

    if any(header.startswith(sig) for sig in IMAGE_SIGNATURES) or (
        header.startswith(b"RIFF") and b"WEBP" in header[8:16]
    ):
        if Image is not None:
            try:
                content_bytes = uploaded_file.read()
                uploaded_file.seek(0)
                img = Image.open(BytesIO(content_bytes))
                img.verify()
                w, h = img.size
                if w <= 0 or h <= 0 or w > MAX_IMAGE_DIMENSION or h > MAX_IMAGE_DIMENSION or (w * h) > MAX_IMAGE_PIXELS:
                    raise ValidationError("Image dimensions exceed maximum allowed safety limits")
            except ValidationError:
                raise
            except Exception as exc:
                raise ValidationError("Malformed or corrupted image file") from exc

    return uploaded_file
