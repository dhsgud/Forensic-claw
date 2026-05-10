"""HelixDB graph-vector backend adapter."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin
from urllib.request import Request, urlopen

from loguru import logger

from forensic_claw.knowledge.store import ChunkRecord, DocumentRecord


class HelixBackendError(RuntimeError):
    """Raised when HelixDB cannot execute the configured query contract."""


class HelixHttpClient:
    """Small HelixDB HTTP client that avoids requiring helix-py in packaged builds."""

    def __init__(self, base_url: str, *, timeout: float = 10.0, verbose: bool = False) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.verbose = verbose

    def query(self, name: str, payload: dict[str, Any]) -> Any:
        """Call one compiled HelixQL query endpoint."""
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        query_name = name.strip()
        url = urljoin(self.base_url, quote(query_name, safe=""))
        logger.debug(
            "HelixDB query request: name={} url={} payloadBytes={} payloadKeys={}",
            query_name,
            url,
            len(encoded),
            sorted(payload.keys()),
        )
        request = Request(
            url,
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        return self._send(request)

    def introspect(self) -> Any:
        """Read the Helix introspection endpoint for connection tests."""
        url = urljoin(self.base_url, "introspect")
        logger.debug("HelixDB introspection request: url={}", url)
        request = Request(
            url,
            headers={"Accept": "application/json"},
            method="GET",
        )
        return self._send(request)

    def _send(self, request: Request) -> Any:
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = response.read()
                logger.debug(
                    "HelixDB HTTP response: method={} url={} status={} bytes={}",
                    request.get_method(),
                    request.full_url,
                    getattr(response, "status", None),
                    len(body),
                )
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            logger.warning(
                "HelixDB HTTP error: method={} url={} status={} detail={}",
                request.get_method(),
                request.full_url,
                exc.code,
                detail[:500],
            )
            raise HelixBackendError(f"Helix HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            logger.warning(
                "HelixDB connection error: method={} url={} reason={}",
                request.get_method(),
                request.full_url,
                exc.reason,
            )
            raise HelixBackendError(f"Helix connection failed: {exc.reason}") from exc
        except TimeoutError as exc:
            logger.warning(
                "HelixDB request timed out: method={} url={} timeout={}",
                request.get_method(),
                request.full_url,
                self.timeout,
            )
            raise HelixBackendError("Helix request timed out.") from exc

        if not body:
            return None
        text = body.decode("utf-8", errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text


class HelixKnowledgeBackend:
    """Synchronize knowledge documents into HelixDB through named HelixQL queries."""

    def __init__(
        self,
        config: Any,
        *,
        client_factory: Callable[[Any], Any] | None = None,
    ) -> None:
        self.config = config
        self.client_factory = client_factory
        self.enabled = bool(getattr(config, "enabled", False))

    def reconfigure(self, config: Any) -> None:
        """Apply updated Helix settings."""
        self.config = config
        self.enabled = bool(getattr(config, "enabled", False))
        logger.info("HelixDB backend reconfigured: enabled={} baseUrl={}", self.enabled, self._safe_base_url())

    def status(self) -> dict[str, Any]:
        """Return Helix HTTP readiness."""
        if not self.enabled:
            return {"enabled": False, "state": "disabled"}
        status_query = str(getattr(self.config, "status_query", "") or "").strip()
        try:
            client = self._client()
            logger.debug(
                "Checking HelixDB status: statusQuery={} baseUrl={}",
                status_query or "introspect",
                self._safe_base_url(),
            )
            response = client.query(status_query, {}) if status_query else client.introspect()
        except Exception as exc:
            logger.warning("HelixDB status unavailable: {}", exc)
            return {
                "enabled": True,
                "state": "unavailable",
                "error": str(exc),
                **self._connection_summary(),
            }
        return {
            "enabled": True,
            "state": "connected",
            "transport": "http",
            "statusQuery": status_query or "introspect",
            "response": self._summarize_status_response(response),
            **self._connection_summary(),
        }

    def sync_document(
        self,
        *,
        document: DocumentRecord,
        chunks: list[ChunkRecord],
        graph: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        """Write one ingested document, its chunks, and graph rows into HelixDB."""
        if not self.enabled:
            return {"enabled": False, "state": "disabled"}

        client = self._client()
        counts = {"sources": 0, "chunks": 0, "entities": 0, "relationships": 0}
        logger.info(
            "Syncing document to HelixDB: documentId={} kind={} chunks={} entities={} relationships={}",
            document.id,
            document.kind,
            len(chunks),
            len(graph.get("entities", [])),
            len(graph.get("relationships", [])),
        )

        try:
            client.query(self._query_name("upsert_source_query"), self._source_payload(document))
            counts["sources"] = 1

            for chunk in chunks:
                client.query(
                    self._query_name("upsert_chunk_query"),
                    self._chunk_payload(document, chunk),
                )
                counts["chunks"] += 1

            for entity in graph.get("entities", []):
                client.query(
                    self._query_name("upsert_entity_query"),
                    self._entity_payload(entity),
                )
                counts["entities"] += 1

            for relationship in graph.get("relationships", []):
                client.query(
                    self._query_name("upsert_relationship_query"),
                    self._relationship_payload(relationship),
                )
                counts["relationships"] += 1
        except Exception as exc:
            logger.warning(
                "HelixDB sync failed: documentId={} counts={} error={}",
                document.id,
                counts,
                exc,
            )
            return {
                "enabled": True,
                "state": "error",
                "error": str(exc),
                **counts,
                **self._connection_summary(),
            }

        logger.info("HelixDB sync complete: documentId={} counts={}", document.id, counts)
        return {
            "enabled": True,
            "state": "synced",
            **counts,
            **self._connection_summary(),
        }

    def search(self, query: str, *, limit: int = 8, include_graph: bool = True) -> dict[str, Any]:
        """Run the configured Helix hybrid search query and normalize its result."""
        if not self.enabled:
            return {"query": query, "hits": [], "graph": [], "helix": {"enabled": False, "state": "disabled"}}

        payload = {
            "query": query,
            "keywords": query,
            "limit": int(limit),
            "include_graph": bool(include_graph),
        }
        client = self._client()
        try:
            logger.debug(
                "Running HelixDB search: queryLength={} limit={} includeGraph={}",
                len(query),
                limit,
                include_graph,
            )
            raw = client.query(self._query_name("search_hybrid_query"), payload)
        except Exception as exc:
            logger.warning("HelixDB search failed: queryLength={} error={}", len(query), exc)
            return {
                "query": query,
                "hits": [],
                "graph": [],
                "helix": {
                    "enabled": True,
                    "state": "error",
                    "error": str(exc),
                    **self._connection_summary(),
                },
            }
        normalized = self._normalize_search_response(raw, query=query)
        if include_graph:
            graph_view = self.graph(query=query, limit=limit)
            if graph_view.get("state") != "error":
                normalized["graphView"] = {
                    "nodes": graph_view.get("nodes", []),
                    "edges": graph_view.get("edges", []),
                }
            else:
                normalized["graphView"] = {"nodes": [], "edges": [], "error": graph_view.get("error")}
        normalized["helix"] = {
            "enabled": True,
            "state": "queried",
            "queryName": self._query_name("search_hybrid_query"),
            **self._connection_summary(),
        }
        logger.debug(
            "HelixDB search complete: hits={} graphNodes={} graphEdges={}",
            len(normalized.get("hits", [])),
            len((normalized.get("graphView") or {}).get("nodes", [])),
            len((normalized.get("graphView") or {}).get("edges", [])),
        )
        return normalized

    def graph(self, *, query: str = "", limit: int = 100) -> dict[str, Any]:
        """Return a visualization-friendly graph payload from HelixDB."""
        if not self.enabled:
            return {"state": "disabled", "nodes": [], "edges": []}

        payload = {"query": query, "limit": int(limit)}
        try:
            logger.debug("Running HelixDB graph query: queryLength={} limit={}", len(query), limit)
            raw = self._client().query(self._query_name("graph_query"), payload)
        except Exception as exc:
            logger.warning("HelixDB graph query failed: queryLength={} error={}", len(query), exc)
            return {
                "state": "error",
                "error": str(exc),
                "nodes": [],
                "edges": [],
                **self._connection_summary(),
            }
        graph = self._normalize_graph_view(raw)
        graph["state"] = "queried"
        graph["queryName"] = self._query_name("graph_query")
        logger.debug(
            "HelixDB graph query complete: nodes={} edges={}",
            len(graph.get("nodes", [])),
            len(graph.get("edges", [])),
        )
        return graph

    def _client(self) -> Any:
        if self.client_factory:
            return self.client_factory(self.config)
        return HelixHttpClient(
            self._base_url(),
            timeout=float(getattr(self.config, "request_timeout_seconds", 10.0)),
            verbose=bool(getattr(self.config, "verbose", False)),
        )

    def _base_url(self) -> str:
        api_endpoint = str(getattr(self.config, "api_endpoint", "") or "").strip()
        if api_endpoint:
            return api_endpoint
        if not bool(getattr(self.config, "local", True)):
            raise HelixBackendError("Helix apiEndpoint is required when local is false.")
        return f"http://127.0.0.1:{int(getattr(self.config, 'port', 6969))}"

    def _connection_summary(self) -> dict[str, Any]:
        api_endpoint = str(getattr(self.config, "api_endpoint", "") or "").strip()
        return {
            "local": bool(getattr(self.config, "local", True)),
            "port": int(getattr(self.config, "port", 6969)),
            "apiEndpoint": api_endpoint,
            "baseUrl": api_endpoint or f"http://127.0.0.1:{int(getattr(self.config, 'port', 6969))}",
            "transport": "http",
        }

    def _safe_base_url(self) -> str:
        try:
            return self._base_url()
        except Exception as exc:
            return f"unavailable:{exc}"

    def _query_name(self, field: str) -> str:
        value = str(getattr(self.config, field, "") or "").strip()
        if not value:
            raise HelixBackendError(f"Helix query name is empty: {field}")
        return value

    @staticmethod
    def _source_payload(document: DocumentRecord) -> dict[str, Any]:
        return {
            "document_id": document.id,
            "source_path": document.source_path,
            "kind": document.kind,
            "sha256": document.sha256,
            "size_bytes": document.size_bytes,
            "metadata": document.metadata,
            "metadata_json": json.dumps(document.metadata, ensure_ascii=False, sort_keys=True),
        }

    @staticmethod
    def _chunk_payload(document: DocumentRecord, chunk: ChunkRecord) -> dict[str, Any]:
        return {
            "chunk_id": chunk.id,
            "document_id": document.id,
            "source_path": document.source_path,
            "chunk_index": chunk.chunk_index,
            "content": chunk.text,
            "metadata": chunk.metadata,
            "metadata_json": json.dumps(chunk.metadata, ensure_ascii=False, sort_keys=True),
        }

    @staticmethod
    def _entity_payload(entity: dict[str, Any]) -> dict[str, Any]:
        metadata = entity.get("metadata") or {}
        return {
            "entity_id": entity.get("id") or "",
            "kind": entity.get("kind") or "",
            "value": entity.get("value") or "",
            "metadata": metadata,
            "metadata_json": json.dumps(metadata, ensure_ascii=False, sort_keys=True),
        }

    @staticmethod
    def _relationship_payload(relationship: dict[str, Any]) -> dict[str, Any]:
        metadata = relationship.get("metadata") or {}
        return {
            "relationship_id": relationship.get("id") or "",
            "source_id": relationship.get("source_id") or "",
            "target_id": relationship.get("target_id") or "",
            "rel_type": relationship.get("type") or "",
            "document_id": relationship.get("document_id") or "",
            "metadata": metadata,
            "metadata_json": json.dumps(metadata, ensure_ascii=False, sort_keys=True),
        }

    @classmethod
    def _normalize_search_response(cls, raw: Any, *, query: str) -> dict[str, Any]:
        if isinstance(raw, dict):
            hit_source: Any = raw.get("hits") or raw.get("documents") or raw.get("chunks")
            if hit_source is None and ("vector" in raw or "keyword" in raw):
                hit_source = [*(raw.get("vector") or []), *(raw.get("keyword") or [])]
            if hit_source is None:
                hit_source = raw
            hits = cls._coerce_hits(hit_source)
            graph = cls._coerce_graph(raw.get("graph") or raw.get("entities") or [])
            return {"query": query, "hits": hits, "graph": graph, "raw": raw}
        if isinstance(raw, list):
            return {"query": query, "hits": cls._coerce_hits(raw), "graph": [], "raw": raw}
            return {"query": query, "hits": [], "graph": [], "raw": raw}

    @classmethod
    def _coerce_hits(cls, value: Any) -> list[dict[str, Any]]:
        if isinstance(value, dict):
            value = [value]
        if not isinstance(value, list):
            return []
        hits = []
        for item in value:
            if not isinstance(item, dict):
                continue
            node = item.get("chunk") or item.get("document") or item.get("node") or item
            if hasattr(node, "__dict__"):
                node = asdict(node) if hasattr(node, "__dataclass_fields__") else vars(node)
            if not isinstance(node, dict):
                continue
            text = node.get("content") or node.get("text") or node.get("body") or ""
            hits.append(
                {
                    "sourcePath": node.get("source_path") or node.get("sourcePath") or node.get("path") or "",
                    "kind": node.get("kind") or "helix",
                    "rank": float(node.get("rank") or node.get("score") or item.get("score") or 0.0),
                    "text": str(text),
                    "metadata": node.get("metadata") or node,
                }
            )
        return hits

    @staticmethod
    def _coerce_graph(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, dict):
            value = [value]
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    @classmethod
    def _normalize_graph_view(cls, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            return {"nodes": [], "edges": [], "raw": raw}
        nodes = raw.get("nodes") or raw.get("entities") or []
        edges = raw.get("edges") or raw.get("relationships") or []
        return {
            "nodes": [cls._graph_node(item) for item in cls._as_list(nodes)],
            "edges": [cls._graph_edge(item) for item in cls._as_list(edges)],
            "raw": raw,
        }

    @classmethod
    def _graph_node(cls, item: Any) -> dict[str, Any]:
        data = cls._to_dict(item)
        node_id = str(data.get("entity_id") or data.get("id") or data.get("value") or "")
        kind = str(data.get("kind") or data.get("label") or "Node")
        value = str(data.get("value") or data.get("path") or node_id)
        return {
            "id": node_id,
            "label": value,
            "kind": kind,
            "group": kind,
            "metadata": data,
        }

    @classmethod
    def _graph_edge(cls, item: Any) -> dict[str, Any]:
        data = cls._to_dict(item)
        source = str(data.get("source_id") or data.get("source") or data.get("from") or "")
        target = str(data.get("target_id") or data.get("target") or data.get("to") or "")
        label = str(data.get("rel_type") or data.get("type") or data.get("label") or "RELATED")
        return {
            "id": str(data.get("relationship_id") or data.get("id") or f"{source}:{label}:{target}"),
            "source": source,
            "target": target,
            "label": label,
            "type": label,
            "metadata": data,
        }

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _to_dict(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if is_dataclass(value):
            return asdict(value)
        if hasattr(value, "__dict__"):
            return dict(vars(value))
        return {}

    @staticmethod
    def _summarize_status_response(response: Any) -> Any:
        if not isinstance(response, dict):
            return response
        schema = response.get("schema")
        if isinstance(schema, dict):
            queries = schema.get("queries")
            nodes = ((schema.get("schema") or {}).get("nodes") or [])
            edges = ((schema.get("schema") or {}).get("edges") or [])
            vectors = ((schema.get("schema") or {}).get("vectors") or [])
            return {
                "queries": len(queries) if isinstance(queries, list) else None,
                "nodes": len(nodes) if isinstance(nodes, list) else None,
                "edges": len(edges) if isinstance(edges, list) else None,
                "vectors": len(vectors) if isinstance(vectors, list) else None,
            }
        return response
