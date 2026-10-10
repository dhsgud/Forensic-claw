from forensic_claw.knowledge.store import SqliteKnowledgeBackend


def test_vector_search_returns_matching_case_even_when_other_case_is_closer(tmp_path):
    store = SqliteKnowledgeBackend(tmp_path)
    first = store.replace_document(
        source_path="C:/a.log",
        kind="text_log",
        sha256="a" * 64,
        size_bytes=1,
        mtime=0,
        metadata={"caseId": "A"},
    )
    other = store.replace_document(
        source_path="C:/b.log",
        kind="text_log",
        sha256="b" * 64,
        size_bytes=1,
        mtime=0,
        metadata={"caseId": "B"},
    )
    store.add_chunks(first, [("target", {}, [0.0, 1.0])])
    store.add_chunks(other, [("other", {}, [1.0, 0.0])])
    result = store.search("missing-keyword", query_embedding=[1.0, 0.0], limit=1, case_id="A")
    assert [hit["text"] for hit in result["hits"]] == ["target"]
