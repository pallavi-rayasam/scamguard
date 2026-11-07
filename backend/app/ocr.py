"""Bounded screenshot OCR. This module never opens or navigates extracted links."""
from __future__ import annotations

import cv2
import numpy as np
import pytesseract

from app.core.config import settings

MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_MULTIPART_OVERHEAD = 64 * 1024
OCR_TIMEOUT_SECONDS = 8
MAX_IMAGE_PIXELS = 20_000_000
PNG_SIGNATURE = bytes.fromhex("89504e470d0a1a0a")


class UnsupportedImageError(ValueError):
    pass


class ImageDecodeError(ValueError):
    pass


class OCRUnavailableError(RuntimeError):
    pass


class OCRTimeoutError(RuntimeError):
    pass


def _check_image_signature(contents: bytes) -> None:
    if contents.startswith(PNG_SIGNATURE):
        return
    if contents.startswith(bytes.fromhex("ffd8ff")):
        return
    raise UnsupportedImageError("Only JPEG and PNG image bytes are accepted")


def extract_text_from_image(contents: bytes) -> str:
    """Validate bytes, preprocess with OpenCV and extract text with Tesseract."""
    _check_image_signature(contents)
    image = cv2.imdecode(np.frombuffer(contents, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None or image.size == 0:
        raise ImageDecodeError("Image decoder rejected the supplied bytes")
    height, width = image.shape[:2]
    if height * width > MAX_IMAGE_PIXELS:
        raise ImageDecodeError("Image dimensions exceed the supported pixel limit")

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    if max(height, width) < 1400:
        scale = min(2.0, 1400 / max(height, width))
        gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
    processed = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]

    pytesseract.pytesseract.tesseract_cmd = settings.tesseract_cmd or "tesseract"
    try:
        return pytesseract.image_to_string(processed, config="--psm 6", timeout=OCR_TIMEOUT_SECONDS).strip()
    except pytesseract.TesseractNotFoundError as exc:
        raise OCRUnavailableError("Tesseract is not installed or TESSERACT_CMD is invalid") from exc
    except RuntimeError as exc:
        if "timeout" in str(exc).lower():
            raise OCRTimeoutError("Tesseract exceeded the OCR time limit") from exc
        raise OCRUnavailableError("Tesseract could not run") from exc
    except OSError as exc:
        raise OCRUnavailableError("Tesseract could not run") from exc
