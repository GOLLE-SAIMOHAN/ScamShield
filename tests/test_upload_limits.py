from io import BytesIO
from PIL import Image


def test_media_upload_over_16mb_returns_json_413(client):
    response = client.post(
        "/api/analyze-media",
        data={"file": (BytesIO(b"x" * (16 * 1024 * 1024 + 1)), "large.bin")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 413
    assert response.is_json
    assert response.get_json() == {
        "success": False,
        "message": "Uploaded file is too large",
        "error": "Request Entity Too Large",
        "details": {"max_size_mb": 16},
    }


def _create_test_image_bytes(width=10, height=10, fmt="PNG"):
    buf = BytesIO()
    img = Image.new("RGB", (width, height), color="red")
    img.save(buf, format=fmt)
    buf.seek(0)
    return buf.read()


def test_valid_image_upload(client):
    img_bytes = _create_test_image_bytes()
    response = client.post(
        "/api/analyze-media",
        data={"file": (BytesIO(img_bytes), "sample.png")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert response.get_json()["file"]["name"] == "sample.png"


def test_spoofed_mime_type_rejected(client):
    response = client.post(
        "/api/analyze-media",
        data={"file": (BytesIO(b"Plain text payload pretending to be image"), "fake.jpg")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "Invalid or unsupported media file format" in response.get_json()["message"]


def test_wrong_file_signature_rejected(client):
    pdf_header = b"%PDF-1.4 fake pdf signature content"
    response = client.post(
        "/api/analyze-media",
        data={"file": (BytesIO(pdf_header), "doc.png")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "Invalid or unsupported media file format" in response.get_json()["message"]


def test_malicious_filename_sanitized(client):
    img_bytes = _create_test_image_bytes()
    response = client.post(
        "/api/analyze-media",
        data={"file": (BytesIO(img_bytes), "../../etc/passwd")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    # werkzeug secure_filename turns '../../etc/passwd' into 'etc_passwd'
    assert response.get_json()["file"]["name"] == "etc_passwd"


def test_script_disguised_as_image_rejected(client):
    php_script = b"<?php echo shell_exec($_GET['cmd']); ?>"
    response = client.post(
        "/api/analyze-media",
        data={"file": (BytesIO(php_script), "shell.jpg")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "prohibited" in response.get_json()["message"].lower()


def test_malformed_image_rejected(client):
    corrupted_jpg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01garbage_corrupted_data_without_end"
    response = client.post(
        "/api/analyze-media",
        data={"file": (BytesIO(corrupted_jpg), "corrupt.jpg")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "Malformed or corrupted image file" in response.get_json()["message"]


def test_excessive_image_dimensions_rejected(client):
    # Construct an image exceeding MAX_IMAGE_DIMENSION (10000)
    from scamshield.validators import scan_validator
    
    img_bytes = _create_test_image_bytes(width=10, height=10)
    
    # Temporarily lower MAX_IMAGE_DIMENSION for testing the validation logic cleanly
    orig_limit = scan_validator.MAX_IMAGE_DIMENSION
    try:
        scan_validator.MAX_IMAGE_DIMENSION = 5
        response = client.post(
            "/api/analyze-media",
            data={"file": (BytesIO(img_bytes), "oversized.png")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        assert "exceed maximum allowed safety limits" in response.get_json()["message"]
    finally:
        scan_validator.MAX_IMAGE_DIMENSION = orig_limit
