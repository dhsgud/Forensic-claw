"""Windows forensic artifact helpers."""

from forensic_claw.forensics.windows.amcache import analyze_amcache_artifact
from forensic_claw.forensics.windows.eventlog import (
    ingest_eventlog_query_output,
    run_windows_eventlog_query,
)
from forensic_claw.forensics.windows.prefetch import analyze_prefetch_artifact
from forensic_claw.forensics.windows.timeline import build_windows_timeline

__all__ = [
    "analyze_amcache_artifact",
    "analyze_prefetch_artifact",
    "build_windows_timeline",
    "ingest_eventlog_query_output",
    "run_windows_eventlog_query",
]
