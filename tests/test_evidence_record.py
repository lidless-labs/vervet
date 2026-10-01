"""Regressions for Vervet's file-backed evidence export slice. All providers are mocked."""
import json
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.dependencies.auth import api_key_auth
from api.routers import bundles, cases, integrations
from api.services.case_manager import CaseManager


@pytest.fixture
def manager(tmp_path):
    return CaseManager(tmp_path / 'cases')


@pytest.fixture
def client(manager, monkeypatch):
    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: 'test'
    monkeypatch.setattr(cases, 'case_manager', manager)
    monkeypatch.setattr(integrations, 'case_manager', manager)
    app.include_router(cases.router, prefix='/api/v1/cases')
    app.include_router(bundles.router, prefix='/api/v1/cases')
    app.include_router(integrations.router)
    return TestClient(app)


def test_close_reopen_and_absent_facts(manager):
    case = manager.create_case({'title': 'Lifecycle'})
    assert {key: case[key] for key in ('closed_at', 'resolution', 'impact', 'summary')} == dict.fromkeys(('closed_at', 'resolution', 'impact', 'summary'))
    case = manager.update_case(case['id'], {'status': 'resolved', 'resolution': 'TruePositive', 'impact': 'WithImpact', 'summary': 'Confirmed beacon'})
    closed = case['closed_at']
    assert datetime.fromisoformat(closed).tzinfo is not None
    assert manager.update_case(case['id'], {'title': 'Edited'})['closed_at'] == closed
    assert manager.update_case(case['id'], {'status': 'closed'})['closed_at'] == closed
    assert manager.update_case(case['id'], {'status': 'investigating'})['closed_at'] is None
    assert manager.update_case(case['id'], {'status': 'closed'})['closed_at'] is not None


@pytest.mark.parametrize('field,value', [('resolution', 'bogus'), ('impact', 'bogus'), ('summary', {})])
def test_closeout_invalid_4xx(client, manager, field, value):
    case = manager.create_case({'title': 'Validation'})
    assert client.put(f"/api/v1/cases/{case['id']}", json={field: value}).status_code == 400
    assert client.post('/api/v1/cases', json={'title': 'Validation', field: value}).status_code == 400


@pytest.mark.parametrize('verdict', ['good', None, [], {}])
def test_invalid_ioc_verdict_is_4xx(client, manager, verdict):
    case = manager.create_case({'title': 'Validation'})
    before = manager.get_case(case['id'])
    response = client.post(f"/api/v1/cases/{case['id']}/iocs", json={'value': '203.0.113.4', 'verdict': verdict})
    assert response.status_code == 400
    assert manager.get_case(case['id']) == before


@pytest.mark.parametrize('status', ['resolved', 'closed'])
def test_created_closed_case_has_timestamp(manager, status):
    case = manager.create_case({'title': 'Already closed', 'status': status})
    assert case['closed_at'] == case['created_at']


def test_finding_retains_own_provenance(manager):
    case = manager.create_case({'title': 'Provenance'})
    finding = manager.add_finding(case['id'], {'summary': 'Flow', 'type': 'connection', 'related_connection_uid': 'Copaque', 'related_rule_id': 'rule-1', 'observed_at': '2026-09-29T10:00:00Z'})
    stored = manager.get_case(case['id'])['findings'][0]
    assert stored['related_connection_uid'] == 'Copaque'
    assert stored['related_rule_id'] == 'rule-1'
    assert stored['observed_at'] == '2026-09-29T10:00:00Z'
    assert stored == finding


@pytest.mark.parametrize('provider', ['misp', 'wazuh'])
def test_mock_provider_results_persist_bounded_and_deduplicate(client, manager, monkeypatch, provider):
    case = manager.create_case({'title': 'IOC enrichment'})
    manager.add_ioc(case['id'], {'value': '203.0.113.4', 'source': 'alert'})
    hit = {'id': 'native-1', 'timestamp': '2026-09-29T10:00:00Z', 'api_key': 'SECRET', 'url': 'https://private.invalid', 'payload': 'x' * 100000, 'rule': {'mitre': {'id': ['T1071.001']}}}
    class MockProvider:
        configured = True
        def search_attribute(self, value, limit):
            return {'response': {'Attribute': [hit]}}
        def search_alerts_for_ioc(self, value, limit):
            return {'data': {'affected_items': [hit]}}
    monkeypatch.setattr(integrations, 'MISPClient' if provider == 'misp' else 'WazuhClient', MockProvider)
    operation = 'enrich' if provider == 'misp' else 'correlate'
    path = f"/api/v1/integrations/{provider}/{operation}/case/{case['id']}"
    assert client.post(path).status_code == 200
    assert client.post(path).status_code == 200
    persisted = CaseManager(manager.cases_dir).get_case(case['id'])['iocs'][0]['enrichment']
    assert len(persisted) == 1
    assert persisted[0]['provider'] == provider
    assert persisted[0]['hit_count'] == 1
    assert persisted[0]['refs'] == ['native-1']
    assert persisted[0]['observed_at'] == '2026-09-29T10:00:00Z'
    assert persisted[0]['mitre_techniques'] == ['T1071.001']
    text = json.dumps(persisted)
    assert len(text) < 2000
    assert 'SECRET' not in text and 'private.invalid' not in text and 'payload' not in text

from pathlib import Path
import re
from jsonschema import Draft202012Validator, FormatChecker
from api.services.annotations import AnnotationsService
from api.services.bundle_exporter import BundleExporter

FIXTURES = Path(__file__).parent / 'fixtures' / 'evidence-record'
CHECKER = FormatChecker()

# jsonschema's optional RFC3339 dependency is not installed. Make date-time
# validation explicit using stdlib so this gate cannot silently skip formats.
@CHECKER.checks('date-time', raises=(ValueError, TypeError))
def rfc3339(value):
    if not isinstance(value, str):
        return True
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', value):
        return False
    if value[-1] not in 'Zz' and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        return False
    normalized = value.upper()
    leap = normalized[17:19] == '60'
    if leap:
        normalized = normalized[:17] + '59' + normalized[19:]
    parsed = datetime.fromisoformat(normalized.replace('Z', '+00:00')).astimezone(timezone.utc)
    return not leap or ((parsed.hour, parsed.minute, parsed.second) == (23, 59, 59) and (parsed.month, parsed.day) in {(6, 30), (12, 31)})


def validate(payload):
    schema = json.loads((FIXTURES / 'evidence-record-v1.schema.json').read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=CHECKER).validate(payload)


@pytest.fixture
def exporter(manager, tmp_path, monkeypatch):
    import api.services.bundle_exporter as module
    annotations = AnnotationsService(tmp_path / 'annotations.json')
    monkeypatch.setattr(module, 'annotations_service', annotations, raising=False)
    exporter = BundleExporter(manager)
    monkeypatch.setattr(bundles, 'bundle_exporter', exporter)
    return exporter, annotations


def test_export_provenance_annotation_and_legacy(client, manager, exporter):
    service, annotations = exporter
    case = manager.create_case({'title': 'Sanitized case', 'assignee': 'case-owner'})
    one = manager.add_finding(case['id'], {'type': 'connection', 'summary': 'Beacon', 'related_connection_uid': 'C-one', 'observed_at': '2026-09-29T10:00:00Z', 'data': {'mitre_techniques': ['T1071.001', 'invalid']}})
    two = manager.add_finding(case['id'], {'type': 'rule_match', 'summary': 'Rule', 'related_rule_id': 'rule-two'})
    ioc = manager.add_ioc(case['id'], {'value': '203.0.113.4', 'source': 'alert', 'verdict': 'suspicious'})
    annotation = annotations.create({'target_type': 'connection', 'target_id': 'C-one', 'content': 'Analyst confirmed', 'author': 'reviewer', 'verdict': 'malicious'})
    legacy = manager.get_case(case['id'])
    legacy['findings'].append({'id': 'legacy-finding', 'type': 'connection', 'summary': 'No link', 'data': {}})
    legacy['iocs'].append({'id': 'legacy-ioc', 'type': 'domain', 'value': 'example.invalid'})
    for field in ('closed_at', 'resolution', 'impact', 'summary'):
        legacy.pop(field, None)
    manager._case_path(case['id']).write_text(json.dumps(legacy))
    response = client.post(f"/api/v1/cases/{case['id']}/export?format=evidence-record")
    assert response.status_code == 200
    payload = response.json()
    validate(payload)
    assert payload['subject'] == {'kind': 'case', 'id': case['id'], 'title': case['title']}
    assert len(payload['records']) == 5
    records = {r['id']: r for r in payload['records']}
    assert records[one['id']]['source']['ref'] == 'C-one'
    assert records[two['id']]['source']['ref'] == 'rule-two'
    assert records['legacy-finding']['source']['ref'] is None
    assert records['legacy-finding']['source']['observed_at'] is None
    assert records['legacy-finding']['decision'] is None
    assert records['legacy-ioc']['decision'] is None
    assert records['legacy-ioc']['source']['tool'] == 'vervet'
    assert records[one['id']]['decision'] == {'verdict': 'malicious', 'rationale': 'Analyst confirmed', 'by': 'reviewer', 'at': annotation['updated_at']}
    attack = records[one['id']]['enrichment'][0]
    assert attack['kind'] == 'attack'
    assert attack['value']['technique_ids'] == ['T1071.001']
    assert attack['at'] is None
    assert records[ioc['id']]['decision'] == {'verdict': 'suspicious', 'rationale': None, 'by': None, 'at': None}
    assert payload['closeout'] == {'status': 'open', 'resolution': None, 'impact': None, 'summary': None, 'closed_at': None, 'closed_by': 'case-owner'}
    assert manager.get_case(case['id']) == legacy  # export is read-only
    for fmt in ('json', 'stix', 'html'):
        assert client.post(f"/api/v1/cases/{case['id']}/export?format={fmt}").status_code == 200
    assert client.post('/api/v1/cases/missing/export?format=evidence-record').status_code == 404


@pytest.mark.parametrize('provider', ['misp', 'wazuh'])
def test_provider_summary_export(client, manager, exporter, monkeypatch, provider):
    case = manager.create_case({'title': 'Summary export'})
    ioc = manager.add_ioc(case['id'], {'value': '203.0.113.4'})
    hit = {'id': 'alert-1', 'timestamp': '2026-09-29T10:00:00Z', 'rule': {'mitre': {'id': ['T1059.001']}}}
    class MockProvider:
        configured = True
        def search_attribute(self, value, limit): return {'Attribute': [hit]}
        def search_alerts_for_ioc(self, value, limit): return {'alerts': [hit]}
    monkeypatch.setattr(integrations, 'MISPClient' if provider == 'misp' else 'WazuhClient', MockProvider)
    operation = 'enrich' if provider == 'misp' else 'correlate'
    assert client.post(f"/api/v1/integrations/{provider}/{operation}/case/{case['id']}").status_code == 200
    payload = exporter[0].export_evidence_record(case['id'])
    validate(payload)
    enrichments = payload['records'][0]['enrichment']
    ti = next(e for e in enrichments if e['kind'] == 'ti')
    attack = next(e for e in enrichments if e['kind'] == 'attack')
    assert ti['provider'] == provider and ti['value']['hit_count'] == 1
    assert ti['value']['refs'] == ['alert-1']
    assert ti['value']['observed_at'] == hit['timestamp']
    assert attack['value']['technique_ids'] == ['T1059.001']
    assert ti['at'] == manager.get_case(case['id'])['iocs'][0]['enrichment'][0]['at']


def test_malformed_oversized_stored_enrichment_export(manager, exporter):
    case = manager.create_case({'title': 'Bounded export'})
    manager.add_ioc(case['id'], {'value': '203.0.113.4'})
    raw = manager.get_case(case['id'])
    raw['iocs'][0]['enrichment'] = [None, 'bad', {'provider': 'misp', 'hit_count': 9, 'at': 'bad', 'observed_at': 'bad', 'refs': ['ref'] * 1000, 'mitre_techniques': ['T1071', 'invalid'] * 1000, 'api_key': 'SECRET', 'payload': 'x' * 100000}]
    manager._case_path(case['id']).write_text(json.dumps(raw))
    payload = exporter[0].export_evidence_record(case['id'])
    validate(payload)
    text = json.dumps(payload)
    assert len(text) < 6000 and 'SECRET' not in text and 'payload' not in text
    assert payload['records'][0]['enrichment'][0]['at'] is None
    assert payload['records'][0]['enrichment'][0]['value']['observed_at'] is None


def test_datetime_validation_is_active():
    from jsonschema import ValidationError
    schema = {'type': 'string', 'format': 'date-time'}
    validator = Draft202012Validator(schema, format_checker=CHECKER)
    for value in ('nonsense', '2026-09-29T10:00:00', '2026-99-29T10:00:00Z'):
        with pytest.raises(ValidationError):
            validator.validate(value)
    validator.validate('2026-09-29T10:00:00Z')

@pytest.mark.parametrize('time', ['2026-09-29T10:00:00+00:99', '2026-09-29T10:00:00-00:99', '2026-09-29T10:00:00+24:00', '2026-09-29T24:00:00Z', '2026-09-29T10:00:60Z'])
def test_invalid_source_offsets_stay_null(time):
    from api.services.evidence_summary import timestamp
    assert timestamp(time) is None
    assert not CHECKER.conforms(time, 'date-time')


def test_annotation_latest_aware_instant_wins(manager, exporter):
    service, annotations = exporter
    case = manager.create_case({'title': 'Annotation chronology'})
    finding = manager.add_finding(case['id'], {'type': 'connection', 'summary': 'Flow', 'related_connection_uid': 'C-offset'})
    old = annotations.create({'target_type': 'connection', 'target_id': 'C-offset', 'content': 'Older', 'author': 'old-reviewer', 'verdict': 'benign'})
    latest = annotations.create({'target_type': 'connection', 'target_id': 'C-offset', 'content': 'Latest', 'author': 'latest-reviewer', 'verdict': 'malicious'})
    items = annotations._read_all()
    items[0]['updated_at'] = '2026-09-29T12:00:00+02:00'
    items[1]['updated_at'] = '2026-09-29T11:00:00Z'
    annotations._write_all(items)
    payload = service.export_evidence_record(case['id'])
    decision = payload['records'][0]['decision']
    assert decision == {'verdict': 'malicious', 'rationale': 'Latest', 'by': 'latest-reviewer', 'at': '2026-09-29T11:00:00Z'}
    validate(payload)

@pytest.fixture(autouse=True)
def forbid_live_integrations(monkeypatch):
    from urllib import request
    def forbidden(*args, **kwargs):
        raise AssertionError('Live integration or reference fetching is forbidden in this suite')
    monkeypatch.setattr(request, 'urlopen', forbidden)


@pytest.mark.parametrize('verdict', ['benign', 'suspicious', 'malicious', 'false-positive', 'unknown'])
def test_valid_verdicts_preserve_null_attribution(client, manager, exporter, verdict):
    case = manager.create_case({'title': 'Recorded verdict', 'assignee': 'owner'})
    response = client.post(f"/api/v1/cases/{case['id']}/iocs", json={'value': '203.0.113.4', 'verdict': verdict, 'ref': 'https://opaque.invalid/ref'})
    assert response.status_code == 201
    payload = exporter[0].export_evidence_record(case['id'])
    validate(payload)
    assert payload['records'][0]['source']['ref'] == 'https://opaque.invalid/ref'
    assert payload['records'][0]['source']['observed_at'] is None
    assert payload['records'][0]['decision'] == {'verdict': verdict, 'rationale': None, 'by': None, 'at': None}


def test_ioc_annotation_only_attributes_matching_verdict(manager, exporter):
    service, annotations = exporter
    case = manager.create_case({'title': 'IOC attribution', 'assignee': 'owner'})
    manager.add_ioc(case['id'], {'value': '203.0.113.4', 'verdict': 'malicious'})
    annotation = annotations.create({'target_type': 'host', 'target_id': '203.0.113.4', 'content': 'Confirmed', 'author': 'ioc-reviewer', 'verdict': 'malicious'})
    payload = service.export_evidence_record(case['id'])
    assert payload['records'][0]['decision'] == {'verdict': 'malicious', 'rationale': 'Confirmed', 'by': 'ioc-reviewer', 'at': annotation['updated_at']}
    annotations.update(annotation['id'], {'verdict': 'benign'})
    assert service.export_evidence_record(case['id'])['records'][0]['decision'] == {'verdict': 'malicious', 'rationale': None, 'by': None, 'at': None}
    items = annotations._read_all()
    items[0]['verdict'] = 'malicious'
    for key in ('author', 'created_at', 'updated_at'):
        items[0].pop(key)
    annotations._write_all(items)
    payload = service.export_evidence_record(case['id'])
    assert payload['records'][0]['decision']['by'] is None
    assert payload['records'][0]['decision']['at'] is None
    validate(payload)


def test_multi_record_export_reads_annotations_once_and_preserves_decisions(manager, exporter, monkeypatch):
    service, annotations = exporter
    case = manager.create_case({'title': 'Annotation snapshot'})
    flow = manager.add_finding(case['id'], {'type': 'connection', 'summary': 'Flow', 'related_connection_uid': 'C-shared'})
    entity = manager.add_finding(case['id'], {'type': 'connection', 'summary': 'Entity', 'related_connection_uid': 'C-shared'})
    unlinked = manager.add_finding(case['id'], {'type': 'rule_match', 'summary': 'Unlinked'})
    ioc = manager.add_ioc(case['id'], {'value': '203.0.113.4', 'verdict': 'malicious', 'related_connection_uid': 'C-shared'})
    unattributed = manager.add_ioc(case['id'], {'value': '203.0.113.5', 'verdict': 'suspicious'})
    legacy = manager.get_case(case['id'])
    legacy['iocs'].append({'id': 'legacy-no-verdict', 'type': 'ip', 'value': '203.0.113.4'})
    manager._case_path(case['id']).write_text(json.dumps(legacy))
    items = [
        {'target_type': 'connection', 'target_id': 'C-shared', 'verdict': 'malicious',
         'content': 'Connection confirmed', 'author': 'connection-reviewer', 'updated_at': '2026-09-29T11:00:00Z'},
        {'target_type': 'connection', 'target_id': 'C-shared', 'verdict': 'benign',
         'content': 'Earlier offset', 'author': 'earlier-reviewer', 'updated_at': '2026-09-29T12:00:00+02:00'},
        {'target_type': 'connection', 'target_id': 'C-shared', 'verdict': 'invalid',
         'content': 'Invalid verdict', 'updated_at': '2026-09-29T14:00:00Z'},
        {'target_type': 'connection', 'target_id': entity['id'], 'verdict': 'suspicious',
         'content': 'Exact entity target', 'author': 'entity-reviewer', 'updated_at': 'invalid', 'created_at': '2026-09-29T11:00:00Z'},
        {'target_type': 'dns', 'target_id': entity['id'], 'verdict': 'benign',
         'content': 'Different target type', 'updated_at': '2026-09-29T14:00:00Z'},
        {'target_type': 'host', 'target_id': '203.0.113.4', 'verdict': 'benign',
         'content': 'Later conflicting verdict', 'updated_at': '2026-09-29T14:00:00Z'},
        {'target_type': 'host', 'target_id': '203.0.113.4', 'verdict': 'malicious',
         'content': 'IOC confirmed', 'author': 'ioc-reviewer', 'updated_at': '2026-09-29T12:30:00+01:00'},
        {'target_type': 'host', 'target_id': '203.0.113.5', 'verdict': 'benign',
         'content': 'Unmatched verdict', 'updated_at': '2026-09-29T14:00:00Z'},
    ]
    annotations._write_all(items)
    annotation_bytes = annotations.annotations_path.read_bytes()
    read_count = 0
    read_all = annotations._read_all

    def counted_read():
        nonlocal read_count
        read_count += 1
        return read_all()

    monkeypatch.setattr(annotations, '_read_all', counted_read)
    payload = service.export_evidence_record(case['id'])
    decisions = {record['id']: record['decision'] for record in payload['records']}
    assert decisions == {
        flow['id']: {'verdict': 'malicious', 'rationale': 'Connection confirmed', 'by': 'connection-reviewer', 'at': '2026-09-29T11:00:00Z'},
        entity['id']: {'verdict': 'suspicious', 'rationale': 'Exact entity target', 'by': 'entity-reviewer', 'at': '2026-09-29T11:00:00Z'},
        unlinked['id']: None,
        ioc['id']: {'verdict': 'malicious', 'rationale': 'IOC confirmed', 'by': 'ioc-reviewer', 'at': '2026-09-29T12:30:00+01:00'},
        unattributed['id']: {'verdict': 'suspicious', 'rationale': None, 'by': None, 'at': None},
        'legacy-no-verdict': None,
    }
    validate(payload)
    assert read_count == 1
    assert annotations.annotations_path.read_bytes() == annotation_bytes
    assert manager.get_case(case['id']) == legacy
    service.export_json(case['id'])
    service.export_html(case['id'])
    service.export_stix(case['id'])
    assert read_count == 1  # Legacy exporters do not consult annotations.

    # A subsequent export must take a fresh snapshot, not reuse an instance cache.
    items[6]['content'] = 'Updated IOC rationale'
    annotations._write_all(items)
    refreshed = service.export_evidence_record(case['id'])
    assert read_count == 2
    updated = {record['id']: record['decision'] for record in refreshed['records']}
    decisions[ioc['id']]['rationale'] = 'Updated IOC rationale'
    assert updated == decisions
    validate(refreshed)


@pytest.mark.parametrize('provider', ['misp', 'wazuh'])
def test_no_hits_and_malformed_hits_still_bounded(client, manager, exporter, monkeypatch, provider):
    case = manager.create_case({'title': 'No hits'})
    ioc = manager.add_ioc(case['id'], {'value': '203.0.113.4'})
    results = []
    class MockProvider:
        configured = True
        def search_attribute(self, value, limit): return {'Attribute': results}
        def search_alerts_for_ioc(self, value, limit): return {'alerts': results}
    monkeypatch.setattr(integrations, 'MISPClient' if provider == 'misp' else 'WazuhClient', MockProvider)
    operation = 'enrich' if provider == 'misp' else 'correlate'
    path = f"/api/v1/integrations/{provider}/{operation}/case/{case['id']}"
    assert client.post(path).status_code == 200
    summary = manager.get_case(case['id'])['iocs'][0]['enrichment'][0]
    assert summary['hit_count'] == 0 and summary['observed_at'] is None
    validate(exporter[0].export_evidence_record(case['id']))
    results.extend([None, 'bad', {'id': 'x' * 100000, 'timestamp': '2026-09-29T10:00:00+00:99', 'rule': {'mitre': {'id': ['T1059.001'] * 10000}}, 'api_key': 'SECRET'}] * 1000)
    assert client.post(path).status_code == 200
    summary = manager.get_case(case['id'])['iocs'][0]['enrichment'][0]
    assert summary['hit_count'] == 3000 and summary['observed_at'] is None
    assert summary['refs'] == [] and summary['mitre_techniques'] == ['T1059.001']
    assert len(json.dumps(summary)) < 1000
    validate(exporter[0].export_evidence_record(case['id']))


def test_misp_tags_and_epoch_wazuh_native_refs(manager, exporter):
    case = manager.create_case({'title': 'Native projections'})
    ioc = manager.add_ioc(case['id'], {'value': '203.0.113.4'})
    manager.persist_ioc_enrichment(case['id'], ioc['id'], 'misp', [{'id': 42, 'timestamp': '1790676000', 'Tag': [{'name': 'mitre-attack-pattern="T1071.001"'}, {'name': 'private.invalid'}]}], 1)
    manager.persist_ioc_enrichment(case['id'], ioc['id'], 'wazuh', [{'_id': 'wazuh-native', '_source': {'@timestamp': '2026-09-29T10:00:00Z', 'rule': {'mitre': {'id': ['T1059.001']}}}}], 1)
    summaries = manager.get_case(case['id'])['iocs'][0]['enrichment']
    assert summaries[0]['refs'] == ['42']
    assert summaries[0]['observed_at'] == '2026-09-29T10:00:00+00:00'
    assert summaries[0]['mitre_techniques'] == ['T1071.001']
    assert summaries[1]['refs'] == ['wazuh-native']
    payload = exporter[0].export_evidence_record(case['id'])
    assert 'private.invalid' not in json.dumps(payload)
    validate(payload)


def test_closed_export_and_legacy_unknown_time(manager, exporter):
    case = manager.create_case({'title': 'Closeout', 'assignee': 'owner'})
    case = manager.update_case(case['id'], {'status': 'resolved', 'resolution': 'TruePositive', 'impact': 'NoImpact', 'summary': 'Contained'})
    payload = exporter[0].export_evidence_record(case['id'])
    assert payload['closeout'] == {'status': 'closed', 'resolution': 'TruePositive', 'impact': 'NoImpact', 'summary': 'Contained', 'closed_at': case['closed_at'], 'closed_by': 'owner'}
    validate(payload)
    case.pop('closed_at')
    manager._case_path(case['id']).write_text(json.dumps(case))
    manager.update_case(case['id'], {'title': 'Legacy closed case'})
    assert exporter[0].export_evidence_record(case['id'])['closeout']['closed_at'] is None


def test_export_rejects_oversized_case_without_dropping_records(client, manager, exporter):
    case = manager.create_case({'title': 'Oversized'})
    raw = manager.get_case(case['id'])
    raw['findings'] = [{'id': str(i), 'type': 'manual', 'summary': 'x' * 8000} for i in range(600)]
    manager._case_path(case['id']).write_text(json.dumps(raw))
    assert client.post(f"/api/v1/cases/{case['id']}/export?format=evidence-record").status_code == 422
    raw['findings'] = [{'id': str(i), 'type': 'manual'} for i in range(10001)]
    manager._case_path(case['id']).write_text(json.dumps(raw))
    assert client.post(f"/api/v1/cases/{case['id']}/export?format=evidence-record").status_code == 422


def test_record_count_boundary_preserves_all_records(manager, exporter):
    case = manager.create_case({'title': 'Count boundary'})
    raw = manager.get_case(case['id'])
    raw['findings'] = [{'id': str(i), 'type': 'manual'} for i in range(10000)]
    manager._case_path(case['id']).write_text(json.dumps(raw))
    payload = exporter[0].export_evidence_record(case['id'])
    assert len(payload['records']) == 10000
    assert payload['records'][-1]['id'] == '9999'
    raw['findings'].append({'id': '10000', 'type': 'manual'})
    manager._case_path(case['id']).write_text(json.dumps(raw))
    with pytest.raises(ValueError, match='at most 10000'):
        exporter[0].export_evidence_record(case['id'])


def test_utf8_output_byte_boundary_is_inclusive(manager, exporter, monkeypatch):
    import api.services.bundle_exporter as module
    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 1, 12, 0, 0, tzinfo=tz)
    monkeypatch.setattr(module, 'datetime', FixedClock)
    case = manager.create_case({'title': 'Byte boundary'})
    raw = manager.get_case(case['id'])
    # Source files are not evidence-record input envelopes. The bound applies
    # to the exporter output's UTF-8 JSON, independently of file size.
    raw['findings'] = [{'id': str(i), 'type': 'manual', 'summary': '\u00e9' * 3990} for i in range(512)]
    path = manager._case_path(case['id'])
    path.write_text(json.dumps(raw))
    service = exporter[0]
    payload = service.export_evidence_record(case['id'])
    size = len(json.dumps(payload, ensure_ascii=False).encode('utf-8'))
    remaining = 4 * 1024 * 1024 - size
    assert remaining > 0
    # Spread byte padding across the 8192-character per-string bound.
    for item in raw['findings']:
        padding = min(remaining, 8192 - len(item['summary']))
        item['summary'] += 'x' * padding
        remaining -= padding
        if not remaining:
            break
    assert remaining == 0
    path.write_text(json.dumps(raw))
    payload = service.export_evidence_record(case['id'])
    assert len(json.dumps(payload, ensure_ascii=False).encode('utf-8')) == 4 * 1024 * 1024
    assert len(payload['records']) == 512
    raw['findings'][-1]['summary'] += 'x'
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match='exceeds 4 MiB'):
        service.export_evidence_record(case['id'])

@pytest.mark.parametrize('time', ['2016-12-31T23:59:60Z', '2017-01-01T00:59:60+01:00', '2015-06-30T23:59:60Z', '2015-07-01T01:59:60+02:00'])
def test_valid_leap_second_provenance_preserves_text(manager, exporter, time):
    from api.services.evidence_summary import timestamp
    assert timestamp(time) == time
    case = manager.create_case({'title': 'Leap second provenance'})
    finding = manager.add_finding(case['id'], {'type': 'connection', 'summary': 'Flow', 'related_connection_uid': 'C-leap', 'observed_at': time})
    payload = exporter[0].export_evidence_record(case['id'])
    assert payload['records'][0]['source']['observed_at'] == time
    validate(payload)


@pytest.mark.parametrize('time', ['2016-12-30T23:59:60Z', '2016-12-31T12:59:60Z', '2016-11-30T23:59:60Z', '2017-01-01T00:59:60+00:00'])
def test_invalid_leap_second_locations_stay_null(time):
    from api.services.evidence_summary import timestamp
    assert timestamp(time) is None
    assert not CHECKER.conforms(time, 'date-time')


def test_leap_second_annotation_and_enrichment_ordering(manager, exporter):
    service, annotations = exporter
    case = manager.create_case({'title': 'Leap second chronology'})
    manager.add_finding(case['id'], {'type': 'connection', 'summary': 'Flow', 'related_connection_uid': 'C-leap'})
    ioc = manager.add_ioc(case['id'], {'value': '203.0.113.4'})
    manager.persist_ioc_enrichment(case['id'], ioc['id'], 'wazuh', [
        {'id': 'leap', 'timestamp': '2017-01-01T00:59:60+01:00'},
        {'id': 'previous', 'timestamp': '2016-12-31T23:59:59Z'},
    ], 2)
    annotations.create({'target_type': 'connection', 'target_id': 'C-leap', 'content': 'Leap decision', 'author': 'leap-reviewer', 'verdict': 'malicious'})
    annotations.create({'target_type': 'connection', 'target_id': 'C-leap', 'content': 'Older', 'author': 'old-reviewer', 'verdict': 'benign'})
    items = annotations._read_all()
    items[0]['updated_at'] = '2017-01-01T00:59:60+01:00'
    items[1]['updated_at'] = '2016-12-31T23:59:59Z'
    annotations._write_all(items)
    payload = service.export_evidence_record(case['id'])
    assert payload['records'][0]['decision']['by'] == 'leap-reviewer'
    assert payload['records'][0]['decision']['at'] == '2017-01-01T00:59:60+01:00'
    ti = next(e for e in payload['records'][1]['enrichment'] if e['kind'] == 'ti')
    assert ti['value']['observed_at'] == '2017-01-01T00:59:60+01:00'
    validate(payload)


def test_sanitized_real_exporter_fixture_validates():
    payload = json.loads((FIXTURES / 'vervet-export.json').read_text())
    validate(payload)
    assert payload['generator']['name'] == 'vervet'
    assert payload['subject']['kind'] == 'case'
    assert len(payload['records']) == 3
    assert {r['source']['ref'] for r in payload['records']} == {'C-example-flow', 'rule-example-1', 'alert-example-native'}
    providers = {e['provider'] for r in payload['records'] for e in r['enrichment']}
    assert providers == {'vervet', 'misp', 'wazuh'}
    assert payload['records'][0]['decision']['by'] == 'reviewer'
    assert payload['records'][2]['decision']['by'] is None
    assert payload['closeout']['resolution'] == 'TruePositive'
    text = json.dumps(payload)
    assert 'DO-NOT-EXPORT' not in text and 'private.invalid' not in text
