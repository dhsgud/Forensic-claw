"""Report template loading.

Templates are JSON assets bundled with the package so they survive PyInstaller
``onedir``/``onefile`` packaging. Loaded via ``importlib.resources``.
"""

from __future__ import annotations

import json
from importlib import resources

from forensic_claw.forensics.report.models import ReportSpec

DEFAULT_TEMPLATE_ID = "knpa_forensic_report"
_TEMPLATES_PACKAGE = "forensic_claw.forensics.report.templates"


def load_template(template_id: str = DEFAULT_TEMPLATE_ID) -> ReportSpec:
    """Load a bundled report template by id."""
    resource = resources.files(_TEMPLATES_PACKAGE).joinpath(f"{template_id}.json")
    if not resource.is_file():
        raise FileNotFoundError(f"Report template not found: {template_id}")
    payload = json.loads(resource.read_text(encoding="utf-8"))
    return ReportSpec.from_dict(payload)


def default_template() -> ReportSpec:
    """Load the standard KNPA digital-forensics report template."""
    return load_template(DEFAULT_TEMPLATE_ID)
