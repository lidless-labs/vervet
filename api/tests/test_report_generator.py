"""Tests for report generator."""
import pytest
from unittest.mock import MagicMock, patch

from api.services.report_generator import ReportGenerator


class TestReportGenerator:
    def _mock_store(self):
        store = MagicMock()
        store.connections = []
        store.dns_queries = []
        store.alerts = []
        return store

    @patch('api.services.report_generator.UnifiedThreatEngine')
    @patch('api.services.report_generator.SessionReconstructor')
    def test_json_report_structure(self, MockReconstructor, MockEngine):
        MockEngine.return_value.analyze_all.return_value = {}
        MockReconstructor.return_value.reconstruct_all.return_value = []

        store = self._mock_store()
        generator = ReportGenerator(store)
        report = generator.generate_json()

        assert "report_metadata" in report
        assert "executive_summary" in report
        assert "top_threats" in report
        assert "mitre_coverage" in report
        assert "ioc_summary" in report

    @patch('api.services.report_generator.UnifiedThreatEngine')
    @patch('api.services.report_generator.SessionReconstructor')
    def test_json_metadata(self, MockReconstructor, MockEngine):
        MockEngine.return_value.analyze_all.return_value = {}
        MockReconstructor.return_value.reconstruct_all.return_value = []

        store = self._mock_store()
        generator = ReportGenerator(store)
        report = generator.generate_json()

        meta = report["report_metadata"]
        assert "generated_at" in meta
        assert meta["generator"] == "Vervet v0.2.0"
        assert meta["total_hosts_analyzed"] == 0

    @patch('api.services.report_generator.UnifiedThreatEngine')
    @patch('api.services.report_generator.SessionReconstructor')
    def test_html_report_is_valid(self, MockReconstructor, MockEngine):
        MockEngine.return_value.analyze_all.return_value = {}
        MockReconstructor.return_value.reconstruct_all.return_value = []

        store = self._mock_store()
        generator = ReportGenerator(store)
        html = generator.generate_html()

        assert "<!DOCTYPE html>" in html
        assert "Threat Assessment Report" in html
        assert "Vervet" in html
        assert "</html>" in html

    @patch('api.services.report_generator.UnifiedThreatEngine')
    @patch('api.services.report_generator.SessionReconstructor')
    def test_empty_data_no_crash(self, MockReconstructor, MockEngine):
        MockEngine.return_value.analyze_all.return_value = {}
        MockReconstructor.return_value.reconstruct_all.return_value = []

        store = self._mock_store()
        generator = ReportGenerator(store)
        # Should not raise
        report = generator.generate_json()
        _html = generator.generate_html()
        assert report["executive_summary"]["total_threats"] == 0
