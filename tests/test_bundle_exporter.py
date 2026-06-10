from pathlib import Path

from api.services.bundle_exporter import BundleExporter
from api.services.case_manager import CaseManager


def _seed_case(manager: CaseManager) -> str:
    case = manager.create_case({"title": "Malware Investigation", "description": "Bundle export test"})
    manager.add_ioc(case["id"], {"type": "ip", "value": "203.0.113.34", "source": "alert", "verdict": "malicious"})
    manager.add_finding(case["id"], {"type": "alert", "summary": "Beaconing detected", "data": {"mitre_techniques": ["T1071.001"]}})
    return case["id"]


def test_export_json(tmp_path: Path):
    manager = CaseManager(cases_dir=tmp_path)
    case_id = _seed_case(manager)
    exporter = BundleExporter(manager)

    payload = exporter.export_json(case_id)
    assert payload["id"] == case_id
    assert payload["export_format"] == "json"


def test_export_stix(tmp_path: Path):
    manager = CaseManager(cases_dir=tmp_path)
    case_id = _seed_case(manager)
    exporter = BundleExporter(manager)

    stix = exporter.export_stix(case_id)
    assert stix["type"] == "bundle"
    assert any(obj["type"] == "report" for obj in stix["objects"])
    assert any(obj["type"] == "indicator" for obj in stix["objects"])


def test_export_html(tmp_path: Path):
    manager = CaseManager(cases_dir=tmp_path)
    case_id = _seed_case(manager)
    exporter = BundleExporter(manager)

    html = exporter.export_html(case_id)
    assert "<!doctype html>" in html.lower()
    assert "Malware Investigation" in html
