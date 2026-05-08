"""Optional Neo4j synchronization for the local knowledge graph."""

from __future__ import annotations

import os
from typing import Any


class Neo4jSink:
    """Synchronize local graph rows into Neo4j when configured."""

    def __init__(self, config: Any):
        self.config = config

    @property
    def enabled(self) -> bool:
        return bool(getattr(self.config, "enabled", False))

    def status(self) -> dict[str, Any]:
        """Return a small connection status payload without raising."""
        if not self.enabled:
            return {"enabled": False, "state": "disabled"}
        driver_cls = self._driver_class()
        if driver_cls is None:
            return {"enabled": True, "state": "driver_missing"}
        try:
            with self._driver(driver_cls) as driver:
                driver.verify_connectivity()
            return {"enabled": True, "state": "connected", "uri": self._uri}
        except Exception as exc:
            return {
                "enabled": True,
                "state": "unavailable",
                "uri": self._uri,
                "error": str(exc),
            }

    def sync(self, graph: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
        """Push graph entities and relationships into Neo4j."""
        if not self.enabled:
            return {"enabled": False, "state": "disabled", "entities": 0, "relationships": 0}
        driver_cls = self._driver_class()
        if driver_cls is None:
            return {"enabled": True, "state": "driver_missing", "entities": 0, "relationships": 0}

        entities = graph.get("entities") or []
        relationships = graph.get("relationships") or []
        try:
            with self._driver(driver_cls) as driver:
                with driver.session(database=self._database) as session:
                    session.execute_write(self._ensure_constraints)
                    for entity in entities:
                        session.execute_write(self._merge_entity, entity)
                    for relationship in relationships:
                        session.execute_write(self._merge_relationship, relationship)
            return {
                "enabled": True,
                "state": "synced",
                "entities": len(entities),
                "relationships": len(relationships),
            }
        except Exception as exc:
            return {
                "enabled": True,
                "state": "unavailable",
                "entities": 0,
                "relationships": 0,
                "error": str(exc),
            }

    @staticmethod
    def _driver_class() -> Any | None:
        try:
            from neo4j import GraphDatabase
        except Exception:
            return None
        return GraphDatabase

    @property
    def _uri(self) -> str:
        return os.environ.get("FORENSIC_CLAW_NEO4J_URI") or getattr(
            self.config, "uri", "bolt://127.0.0.1:7687"
        )

    @property
    def _username(self) -> str:
        return os.environ.get("FORENSIC_CLAW_NEO4J_USERNAME") or getattr(
            self.config, "username", "neo4j"
        )

    @property
    def _password(self) -> str:
        return os.environ.get("FORENSIC_CLAW_NEO4J_PASSWORD") or getattr(
            self.config, "password", ""
        )

    @property
    def _database(self) -> str | None:
        database = os.environ.get("FORENSIC_CLAW_NEO4J_DATABASE") or getattr(
            self.config, "database", "neo4j"
        )
        return database or None

    def _driver(self, driver_cls: Any) -> Any:
        auth = None
        if self._username and self._password:
            auth = (self._username, self._password)
        return driver_cls.driver(self._uri, auth=auth, connection_timeout=3)

    @staticmethod
    def _ensure_constraints(tx: Any) -> None:
        tx.run(
            """
            CREATE CONSTRAINT fc_entity_id IF NOT EXISTS
            FOR (e:FCEntity) REQUIRE e.id IS UNIQUE
            """
        )

    @staticmethod
    def _merge_entity(tx: Any, entity: dict[str, Any]) -> None:
        tx.run(
            """
            MERGE (e:FCEntity {id: $id})
            SET e.kind = $kind,
                e.value = $value,
                e.metadata = $metadata
            """,
            id=entity["id"],
            kind=entity["kind"],
            value=entity["value"],
            metadata=entity.get("metadata") or {},
        )

    @staticmethod
    def _merge_relationship(tx: Any, relationship: dict[str, Any]) -> None:
        tx.run(
            """
            MATCH (s:FCEntity {id: $source_id})
            MATCH (t:FCEntity {id: $target_id})
            MERGE (s)-[r:FC_REL {id: $id}]->(t)
            SET r.type = $type,
                r.document_id = $document_id,
                r.metadata = $metadata
            """,
            id=relationship["id"],
            source_id=relationship["source_id"],
            target_id=relationship["target_id"],
            type=relationship["type"],
            document_id=relationship.get("document_id"),
            metadata=relationship.get("metadata") or {},
        )
