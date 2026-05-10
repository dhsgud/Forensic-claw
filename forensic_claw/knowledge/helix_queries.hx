// Reference HelixQL query contract for Forensic-Claw.
// Copy these schema/query definitions into a Helix project and run `helix check`
// and `helix push dev` before setting knowledge.backend = "helix".

N::EvidenceSource {
  INDEX path: String,
  kind: String,
  sha256: String,
  metadata_json: String
}

N::EvidenceEntity {
  INDEX entity_id: String,
  kind: String,
  value: String,
  metadata_json: String
}

N::EvidenceChunkText {
  INDEX chunk_id: String,
  document_id: String,
  source_path: String,
  chunk_index: I64,
  content: String,
  metadata_json: String
}

V::EvidenceChunk {
  INDEX chunk_id: String,
  document_id: String,
  source_path: String,
  content: String,
  metadata_json: String
}

E::EvidenceHasChunk {
  From: EvidenceSource,
  To: EvidenceChunkText,
  Properties: {
    document_id: String
  }
}

E::EvidenceChunkTextHasVector {
  From: EvidenceChunkText,
  To: EvidenceChunk,
  Properties: {
    document_id: String
  }
}

E::EvidenceRelationship {
  From: EvidenceEntity,
  To: EvidenceEntity,
  Properties: {
    relationship_id: String,
    source_id: String,
    target_id: String,
    document_id: String,
    rel_type: String,
    metadata_json: String
  }
}

QUERY UpsertEvidenceSource(
  document_id: String,
  source_path: String,
  kind: String,
  sha256: String,
  size_bytes: I64,
  metadata_json: String
) =>
  existing <- N<EvidenceSource>::WHERE(_::{path}::EQ(source_path))
  source <- existing::UpsertN({
    path: source_path,
    kind: kind,
    sha256: sha256,
    metadata_json: metadata_json
  })
  RETURN source

QUERY UpsertEvidenceChunk(
  chunk_id: String,
  document_id: String,
  source_path: String,
  chunk_index: I64,
  content: String,
  metadata_json: String
) =>
  existing_text <- N<EvidenceChunkText>::WHERE(_::{chunk_id}::EQ(chunk_id))
  text_node <- existing_text::UpsertN({
    chunk_id: chunk_id,
    document_id: document_id,
    source_path: source_path,
    chunk_index: chunk_index,
    content: content,
    metadata_json: metadata_json
  })
  source <- N<EvidenceSource>({path: source_path})
  existing_edge <- E<EvidenceHasChunk>
  edge <- existing_edge::UpsertE({document_id: document_id})::From(source)::To(text_node)
  RETURN text_node

QUERY UpsertEvidenceEntity(
  entity_id: String,
  kind: String,
  value: String,
  metadata_json: String
) =>
  existing <- N<EvidenceEntity>::WHERE(_::{entity_id}::EQ(entity_id))
  entity <- existing::UpsertN({
    entity_id: entity_id,
    kind: kind,
    value: value,
    metadata_json: metadata_json
  })
  RETURN entity

QUERY UpsertEvidenceRelationship(
  relationship_id: String,
  source_id: String,
  target_id: String,
  rel_type: String,
  document_id: String,
  metadata_json: String
) =>
  source <- N<EvidenceEntity>({entity_id: source_id})
  target <- N<EvidenceEntity>({entity_id: target_id})
  existing <- E<EvidenceRelationship>
  edge <- existing::UpsertE({
    relationship_id: relationship_id,
    source_id: source_id,
    target_id: target_id,
    document_id: document_id,
    rel_type: rel_type,
    metadata_json: metadata_json
  })::From(source)::To(target)
  RETURN edge

QUERY SearchEvidenceKeyword(keywords: String, limit: I64) =>
  chunks <- SearchBM25<EvidenceChunkText>(keywords, limit)
  RETURN chunks

QUERY SearchEvidenceVector(query: String, limit: I64) =>
  chunks <- SearchBM25<EvidenceChunkText>(query, limit)
  RETURN chunks

QUERY SearchEvidenceHybrid(query: String, keywords: String, limit: I64, include_graph: Boolean) =>
  vector_hits <- SearchBM25<EvidenceChunkText>(query, limit)
  keyword_hits <- SearchBM25<EvidenceChunkText>(keywords, limit)
  RETURN { vector: vector_hits, keyword: keyword_hits }

QUERY GetEntityNeighborhood(value: String, limit: I64) =>
  entity <- N<EvidenceEntity>::WHERE(_::{value}::EQ(value))
  RETURN entity

QUERY GetEvidenceGraph(query: String, limit: I64) =>
  nodes <- N<EvidenceEntity>::RANGE(0, limit)
  edges <- nodes::OutE<EvidenceRelationship>
  RETURN { nodes: nodes, edges: edges }
