from __future__ import annotations

import hashlib
import struct

from forensic_claw.config.schema import KnowledgeConfig
from forensic_claw.knowledge.service import KnowledgeService
from forensic_claw.uploads import UploadService, build_attachment_context, classify_upload


def _config() -> KnowledgeConfig:
    return KnowledgeConfig(neo4j={"enabled": False}, chunk_chars=1000, chunk_overlap_chars=0)


def test_save_bytes_indexes_text_upload_when_knowledge_service_is_available(tmp_path):
    knowledge_service = KnowledgeService(tmp_path, _config())
    upload_service = UploadService(tmp_path, knowledge_service=knowledge_service)

    record = upload_service.save_bytes(
        file_name="security.log",
        content=b"2026-05-09 powershell.exe connected to 10.0.0.5",
        session_id="sess_upload",
        case_name="Case Upload",
        investigator_name="Investigator One",
    )

    assert record.kind == "text"
    assert record.status == "ready"
    assert record.hashes == {
        "md5": hashlib.md5(b"2026-05-09 powershell.exe connected to 10.0.0.5").hexdigest(),
        "sha256": hashlib.sha256(b"2026-05-09 powershell.exe connected to 10.0.0.5").hexdigest(),
        "sha512": hashlib.sha512(b"2026-05-09 powershell.exe connected to 10.0.0.5").hexdigest(),
    }
    assert record.sha256 == record.hashes["sha256"]
    assert record.ingest["chunks"] >= 1
    assert knowledge_service.search("powershell 10.0.0.5")["hits"]

    loaded = upload_service.load(record.upload_id)
    assert loaded.file_name == "security.log"
    assert loaded.hashes == record.hashes
    context = build_attachment_context([loaded])
    assert "Attached Evidence Context" in context
    assert "security.log" in context
    assert "Hashes: MD5=" in context
    assert "SHA256=" in context
    assert "SHA512=" in context
    assert "knowledge_search" in context


def test_save_bytes_indexes_image_metadata_when_vision_model_is_not_configured(tmp_path):
    knowledge_service = KnowledgeService(tmp_path, _config())
    upload_service = UploadService(tmp_path, knowledge_service=knowledge_service)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + struct.pack(">II", 2, 3)
        + b"\x08\x02\x00\x00\x00"
        + b"\x00" * 12
    )

    record = upload_service.save_bytes(
        file_name="screen.png",
        content=png,
        session_id="sess_upload",
        case_name="Case Upload",
        investigator_name="Investigator One",
    )

    assert record.kind == "image"
    assert record.status == "vision_metadata_indexed"
    assert record.vision["status"] == "metadata_only"
    assert record.vision["dimensions"] == {"width": 2, "height": 3}
    assert knowledge_service.search("Image Evidence screen.png")["hits"]


def test_classify_upload_routes_known_extensions_to_processors():
    assert classify_upload("events.jsonl") == "text"
    assert classify_upload("History") == "database"
    assert classify_upload("photo.jpg") == "image"
    assert classify_upload("report.pdf") == "document"
    assert classify_upload("memory.raw") == "binary"
