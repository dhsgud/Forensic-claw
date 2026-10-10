from pathlib import Path
from tempfile import TemporaryDirectory

from hypothesis import given, settings
from hypothesis import strategies as st

from forensic_claw.config.schema import KnowledgeConfig, VectorConfig
from forensic_claw.knowledge.service import KnowledgeService


@settings(max_examples=12, deadline=None)
@given(name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12))
def test_executable_references_remain_executables_without_duplicate_domain_classification(name):
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        filename = f"{name}.exe"
        source = root / "events.log"
        source.write_text(f"{filename} contacted example.com", encoding="utf-8")
        service = KnowledgeService(root, KnowledgeConfig(vector=VectorConfig(enabled=False)))
        service.ingest_path(source, case_name="case")
        graph = service.search(name, case_id="case")["graphView"]["nodes"]
        kinds = {(node["kind"], node["label"]) for node in graph}
        assert ("Executable", filename) in kinds
        assert ("Domain", filename) not in kinds
        assert ("Domain", "example.com") in kinds
