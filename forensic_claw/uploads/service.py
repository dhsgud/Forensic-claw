"""Evidence upload staging, classification, and knowledge routing."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from forensic_claw.utils.hashing import DEFAULT_HASH_ALGORITHMS, calculate_file_hashes
from forensic_claw.vision import VisionInterpretationService

_TEXT_EXTENSIONS = {
    ".csv",
    ".json",
    ".jsonl",
    ".log",
    ".ndjson",
    ".ps1",
    ".reg",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
_DATABASE_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}
_DATABASE_NAMES = {"history", "history.sqlite"}
_IMAGE_EXTENSIONS = {".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"}
_DOCUMENT_EXTENSIONS = {".doc", ".docx", ".hwp", ".hwpx", ".pdf", ".ppt", ".pptx", ".xls", ".xlsx"}
_VALID_UPLOAD_ID = re.compile(r"^upl_[a-f0-9]{12}$")
_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class UploadProcessingError(ValueError):
    """Raised when an uploaded file cannot be accepted."""


class UploadNotFoundError(KeyError):
    """Raised when a referenced upload id does not exist."""


@dataclass
class UploadRecord:
    """Stored metadata for one browser-uploaded evidence file."""

    upload_id: str
    session_id: str
    file_name: str
    stored_path: str
    size_bytes: int
    sha256: str
    kind: str
    status: str
    processor: str
    message: str
    uploaded_at: str
    case_name: str | None = None
    investigator_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    hashes: dict[str, str] = field(default_factory=dict)
    ingest: dict[str, Any] = field(default_factory=dict)
    vision: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        payload = asdict(self)
        payload["uploadId"] = payload.pop("upload_id")
        payload["sessionId"] = payload.pop("session_id")
        payload["fileName"] = payload.pop("file_name")
        payload["storedPath"] = payload.pop("stored_path")
        payload["sizeBytes"] = payload.pop("size_bytes")
        payload["uploadedAt"] = payload.pop("uploaded_at")
        payload["caseName"] = payload.pop("case_name")
        payload["investigatorName"] = payload.pop("investigator_name")
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "UploadRecord":
        """Load a record from its persisted JSON form."""
        data = dict(payload)
        for camel, snake in (
            ("uploadId", "upload_id"),
            ("sessionId", "session_id"),
            ("fileName", "file_name"),
            ("storedPath", "stored_path"),
            ("sizeBytes", "size_bytes"),
            ("uploadedAt", "uploaded_at"),
            ("caseName", "case_name"),
            ("investigatorName", "investigator_name"),
        ):
            if camel in data:
                data[snake] = data.pop(camel)
        return cls(**data)


def sanitize_file_name(file_name: str | None) -> str:
    """Keep an uploaded filename local to its staging directory."""
    raw = Path(str(file_name or "upload.bin")).name.strip()
    clean = "".join(char for char in raw if char >= " " and char not in {'"', "*", ":", "<", ">", "?", "|"})
    clean = clean.replace("\\", "_").replace("/", "_").strip(" .")
    return clean[:180] or "upload.bin"


def classify_upload(file_name: str) -> str:
    """Map a filename to the processing route used by the upload service."""
    name = sanitize_file_name(file_name)
    suffix = Path(name).suffix.lower()
    lower_name = name.lower()
    if suffix in _TEXT_EXTENSIONS:
        return "text"
    if suffix in _DATABASE_EXTENSIONS or lower_name in _DATABASE_NAMES:
        return "database"
    if suffix in _IMAGE_EXTENSIONS:
        return "image"
    if suffix in _DOCUMENT_EXTENSIONS:
        return "document"
    return "binary"


def build_attachment_context(records: list[UploadRecord]) -> str:
    """Render upload records into concise context for the downstream LLM."""
    if not records:
        return ""

    lines = [
        "Attached Evidence Context:",
        "The user attached files through the WebUI. Use this context and call knowledge_search when a file is indexed.",
    ]
    for index, record in enumerate(records, start=1):
        lines.append(
            f"{index}. {record.file_name} | kind={record.kind} | status={record.status} | "
            f"sha256={record.sha256} | sizeBytes={record.size_bytes}"
        )
        if record.hashes:
            lines.append(
                "   Hashes: "
                + " ".join(
                    f"{algorithm.upper()}={digest}"
                    for algorithm, digest in sorted(record.hashes.items())
                )
            )
        lines.append(f"   storedPath={record.stored_path}")
        if record.ingest:
            lines.append(
                "   RAG/Graph ingest: "
                f"ready={record.ingest.get('ready')} "
                f"chunks={record.ingest.get('chunks', 0)} "
                f"entities={record.ingest.get('entities', 0)} "
                f"relationships={record.ingest.get('relationships', 0)} "
                f"neo4j={json.dumps(record.ingest.get('neo4j') or {}, ensure_ascii=False)} "
                f"helix={json.dumps(record.ingest.get('helix') or {}, ensure_ascii=False)}"
            )
        if record.vision:
            lines.append(f"   Vision summary: {record.vision.get('summary') or ''}")
            if record.vision.get("limitations"):
                lines.append(f"   Vision limitations: {record.vision['limitations']}")
        if record.message:
            lines.append(f"   Processing note: {record.message}")
    return "\n".join(lines)


class UploadService:
    """Stage uploads and route them into RAG, Neo4j, or image interpretation."""

    def __init__(
        self,
        workspace: Path,
        *,
        knowledge_service: Any | None = None,
        vision_service: VisionInterpretationService | None = None,
    ) -> None:
        self.workspace = workspace
        self.root = workspace / "uploads"
        self.index_root = self.root / "_index"
        self.knowledge_service = knowledge_service
        self.vision_service = vision_service or VisionInterpretationService()

    def save_bytes(
        self,
        *,
        file_name: str | None,
        content: bytes,
        session_id: str,
        case_name: str | None = None,
        investigator_name: str | None = None,
    ) -> UploadRecord:
        """Persist an upload and immediately perform the best available processing route."""
        if not session_id:
            raise UploadProcessingError("missing session id")
        safe_name = sanitize_file_name(file_name)
        upload_id = f"upl_{uuid.uuid4().hex[:12]}"
        upload_dir = self.root / "sessions" / _safe_segment(session_id) / upload_id
        upload_dir.mkdir(parents=True, exist_ok=True)
        target = upload_dir / safe_name
        target.write_bytes(content)
        hashes = calculate_file_hashes(target, DEFAULT_HASH_ALGORITHMS)
        logger.info(
            "WebUI upload stored: uploadId={} sessionId={} fileName={} sizeBytes={}",
            upload_id,
            session_id,
            safe_name,
            len(content),
        )

        record = UploadRecord(
            upload_id=upload_id,
            session_id=session_id,
            file_name=safe_name,
            stored_path=str(target),
            size_bytes=target.stat().st_size,
            sha256=hashes["sha256"],
            kind=classify_upload(safe_name),
            status="stored",
            processor="none",
            message="File stored. No processor ran yet.",
            uploaded_at=datetime.now(UTC).isoformat(),
            case_name=case_name or None,
            investigator_name=investigator_name or None,
            metadata={"extension": target.suffix.lower()},
            hashes=hashes,
        )
        logger.debug(
            "WebUI upload classified: uploadId={} kind={} extension={} hashes={}",
            record.upload_id,
            record.kind,
            record.metadata.get("extension"),
            record.hashes,
        )
        processed = self._process(record, upload_dir)
        self._save_record(processed, upload_dir)
        logger.info(
            "WebUI upload processed: uploadId={} kind={} status={} processor={} ready={} errors={}",
            processed.upload_id,
            processed.kind,
            processed.status,
            processed.processor,
            (processed.ingest or {}).get("ready"),
            len((processed.ingest or {}).get("errors") or []),
        )
        return processed

    def load(self, upload_id: str) -> UploadRecord:
        """Load a persisted upload record by id."""
        if not _VALID_UPLOAD_ID.match(upload_id or ""):
            raise UploadNotFoundError(upload_id)
        path = self.index_root / f"{upload_id}.json"
        if not path.is_file():
            raise UploadNotFoundError(upload_id)
        return UploadRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def load_many(self, upload_ids: list[str]) -> list[UploadRecord]:
        """Load multiple upload records in caller-supplied order."""
        return [self.load(upload_id) for upload_id in upload_ids]

    def _process(self, record: UploadRecord, upload_dir: Path) -> UploadRecord:
        logger.debug("Routing upload for processing: uploadId={} kind={}", record.upload_id, record.kind)
        if record.kind in {"text", "database"}:
            return self._ingest_record(record, Path(record.stored_path), processor="rag")
        if record.kind == "image":
            return self._process_image(record, upload_dir)
        if record.kind == "document":
            record.status = "stored_pending_parser"
            record.message = "Document parsing is not configured yet. The original file was stored for later OCR/parser ingestion."
            logger.info(
                "Upload stored pending document parser: uploadId={} fileName={} sizeBytes={}",
                record.upload_id,
                record.file_name,
                record.size_bytes,
            )
            return record

        record.status = "stored_unsupported"
        record.message = "Unsupported binary file type. The original file was stored but not indexed."
        logger.info(
            "Upload stored as unsupported binary: uploadId={} fileName={} sizeBytes={}",
            record.upload_id,
            record.file_name,
            record.size_bytes,
        )
        return record

    def _process_image(self, record: UploadRecord, upload_dir: Path) -> UploadRecord:
        image_path = Path(record.stored_path)
        logger.info("Upload image interpretation started: uploadId={} path={}", record.upload_id, image_path)
        interpretation = self.vision_service.interpret_image(image_path)
        record.vision = interpretation
        record.processor = "vision"
        record.status = "vision_metadata_ready"
        record.message = (
            "Image metadata was extracted. Configure a small vision SLLM adapter for full visual interpretation."
        )

        derived_text = self.vision_service.to_rag_text(
            file_name=record.file_name,
            sha256=record.sha256,
            interpretation=interpretation,
        )
        derived_path = upload_dir / "_vision_analysis.txt"
        derived_path.write_text(derived_text, encoding="utf-8")
        if self.knowledge_service:
            ingested = self._ingest_record(record, derived_path, processor="vision+rag")
            ingested.status = "vision_metadata_indexed" if ingested.ingest.get("ready") else record.status
            ingested.vision = interpretation
            logger.info(
                "Upload image metadata indexed: uploadId={} ready={}",
                record.upload_id,
                ingested.ingest.get("ready"),
            )
            return ingested
        logger.warning("Upload image could not be indexed because knowledge service is unavailable: uploadId={}", record.upload_id)
        return record

    def _ingest_record(self, record: UploadRecord, path: Path, *, processor: str) -> UploadRecord:
        if not self.knowledge_service:
            record.status = "stored"
            record.processor = processor
            record.message = "Knowledge service is unavailable, so the file was stored but not indexed."
            logger.warning(
                "Upload ingest skipped because knowledge service is unavailable: uploadId={} processor={}",
                record.upload_id,
                processor,
            )
            return record

        logger.info(
            "Upload ingest started: uploadId={} processor={} path={}",
            record.upload_id,
            processor,
            path,
        )
        result = self.knowledge_service.ingest_path(
            path,
            recursive=False,
            case_name=record.case_name,
            investigator_name=record.investigator_name,
        )
        record.processor = processor
        record.ingest = {
            "ok": result.ok,
            "ready": result.ready,
            "scannedFiles": result.scanned_files,
            "ingestedFiles": result.ingested_files,
            "skippedFiles": result.skipped_files,
            "chunks": result.chunks,
            "entities": result.entities,
            "relationships": result.relationships,
            "errors": list(result.errors),
            "neo4j": dict(result.neo4j or {}),
            "helix": dict(result.helix or {}),
        }
        record.status = "ready" if result.ready else "stored"
        record.message = (
            "File indexed into local RAG and graph storage."
            if result.ready
            else "File was stored, but no ingestible content was indexed."
        )
        if result.errors:
            logger.warning(
                "Upload ingest finished with errors: uploadId={} processor={} ready={} errors={}",
                record.upload_id,
                processor,
                result.ready,
                result.errors[:5],
            )
        else:
            logger.info(
                "Upload ingest finished: uploadId={} processor={} ready={} chunks={} entities={} relationships={}",
                record.upload_id,
                processor,
                result.ready,
                result.chunks,
                result.entities,
                result.relationships,
            )
        return record

    def _save_record(self, record: UploadRecord, upload_dir: Path) -> None:
        payload = json.dumps(record.to_dict(), ensure_ascii=False, indent=2)
        upload_dir.mkdir(parents=True, exist_ok=True)
        self.index_root.mkdir(parents=True, exist_ok=True)
        (upload_dir / "metadata.json").write_text(payload, encoding="utf-8")
        (self.index_root / f"{record.upload_id}.json").write_text(payload, encoding="utf-8")
        logger.debug(
            "Upload metadata saved: uploadId={} metadataPath={} indexPath={}",
            record.upload_id,
            upload_dir / "metadata.json",
            self.index_root / f"{record.upload_id}.json",
        )


def _safe_segment(value: str) -> str:
    clean = _SAFE_SEGMENT_RE.sub("_", str(value or "session")).strip("._-")
    return clean[:80] or "session"
