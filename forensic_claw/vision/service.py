"""Lightweight image interpretation scaffolding for local evidence uploads."""

from __future__ import annotations

import mimetypes
import struct
from pathlib import Path
from typing import Any


class VisionInterpretationService:
    """Return deterministic image metadata until a vision SLLM adapter is configured."""

    def interpret_image(self, path: Path) -> dict[str, Any]:
        """Inspect an image and return a stable, LLM-friendly interpretation payload."""
        dimensions = self._read_dimensions(path)
        mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        summary_parts = [
            f"Image evidence file '{path.name}' was uploaded.",
            f"MIME type: {mime_type}.",
        ]
        if dimensions:
            summary_parts.append(f"Dimensions: {dimensions['width']}x{dimensions['height']} pixels.")
        else:
            summary_parts.append("Dimensions could not be determined from the file header.")

        return {
            "status": "metadata_only",
            "provider": "local-header-inspector",
            "mimeType": mime_type,
            "dimensions": dimensions,
            "summary": " ".join(summary_parts),
            "visibleText": [],
            "objects": [],
            "forensicSignals": [],
            "limitations": (
                "No configured vision SLLM is available yet, so this result contains file "
                "metadata only. Route this payload to a small vision model before final "
                "evidence interpretation."
            ),
        }

    def to_rag_text(
        self,
        *,
        file_name: str,
        sha256: str,
        interpretation: dict[str, Any],
    ) -> str:
        """Create a small text artifact that can be indexed by the existing RAG pipeline."""
        dimensions = interpretation.get("dimensions") or {}
        dimension_text = (
            f"{dimensions.get('width')}x{dimensions.get('height')}"
            if dimensions.get("width") and dimensions.get("height")
            else "unknown"
        )
        return "\n".join(
            [
                f"Image Evidence: {file_name}",
                f"SHA256: {sha256}",
                f"MIME Type: {interpretation.get('mimeType') or 'unknown'}",
                f"Dimensions: {dimension_text}",
                f"Vision Status: {interpretation.get('status') or 'unknown'}",
                f"Summary: {interpretation.get('summary') or ''}",
                f"Limitations: {interpretation.get('limitations') or ''}",
            ]
        )

    def _read_dimensions(self, path: Path) -> dict[str, int] | None:
        try:
            with path.open("rb") as handle:
                header = handle.read(32)
                if header.startswith(b"\x89PNG\r\n\x1a\n") and len(header) >= 24:
                    width, height = struct.unpack(">II", header[16:24])
                    return {"width": int(width), "height": int(height)}
                if header[:6] in {b"GIF87a", b"GIF89a"} and len(header) >= 10:
                    width, height = struct.unpack("<HH", header[6:10])
                    return {"width": int(width), "height": int(height)}
                if header.startswith(b"\xff\xd8"):
                    return self._read_jpeg_dimensions(handle, header)
        except OSError:
            return None
        return None

    @staticmethod
    def _read_jpeg_dimensions(handle, header: bytes) -> dict[str, int] | None:
        data = bytearray(header)
        while True:
            marker_index = data.find(b"\xff")
            if marker_index < 0:
                chunk = handle.read(4096)
                if not chunk:
                    return None
                data.extend(chunk)
                continue
            if marker_index + 4 >= len(data):
                chunk = handle.read(4096)
                if not chunk:
                    return None
                data.extend(chunk)
                continue
            marker = data[marker_index + 1]
            if marker == 0xD8:
                del data[: marker_index + 2]
                continue
            if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                if marker_index + 9 >= len(data):
                    chunk = handle.read(4096)
                    if not chunk:
                        return None
                    data.extend(chunk)
                    continue
                height, width = struct.unpack(">HH", data[marker_index + 5 : marker_index + 9])
                return {"width": int(width), "height": int(height)}
            if marker in {0xD9, 0xDA}:
                return None
            segment_length = struct.unpack(">H", data[marker_index + 2 : marker_index + 4])[0]
            if segment_length < 2:
                return None
            del data[: marker_index + 2 + segment_length]
